using System.Text;
using Darkspyre.Encryption;
using Microsoft.Data.Sqlite;

namespace Encryption.Tests;

/// <summary>
/// Loads the prebuilt SQLCipher library named by <c>DARKSPYRE_SQLCIPHER_LIBRARY</c>, or found under
/// <c>DARKSPYRE_NATIVE_DRIVERS</c> at <c>sqlcipher/4.19.0-osx-arm64/libsqlcipher.dylib</c>. Without either, every
/// database test fails with a message naming the variables; it never passes without SQLCipher.
/// </summary>
public sealed class SqlCipherFixture
{
    public SqlCipherFixture()
    {
        string? library = Environment.GetEnvironmentVariable("DARKSPYRE_SQLCIPHER_LIBRARY");
        string? drivers = Environment.GetEnvironmentVariable("DARKSPYRE_NATIVE_DRIVERS");
        if (string.IsNullOrEmpty(library) && !string.IsNullOrEmpty(drivers))
            library = Path.Combine(drivers, "sqlcipher", "4.19.0-osx-arm64", "libsqlcipher.dylib");
        if (string.IsNullOrEmpty(library))
            throw new InvalidOperationException("Set DARKSPYRE_SQLCIPHER_LIBRARY or DARKSPYRE_NATIVE_DRIVERS to run the SQLCipher tests.");
        SqlCipher.Initialize(library);
    }
}

[CollectionDefinition("SqlCipher")]
public sealed class SqlCipherGroup : ICollectionFixture<SqlCipherFixture>;

[Collection("SqlCipher")]
public sealed class SqlCipherTests : IDisposable
{
    private const string Secret = "the quick transcript about the harbor lighthouse";
    private readonly string folder = Path.Combine(AppContext.BaseDirectory, "sqlcipher-tests", Guid.NewGuid().ToString("N"));
    private readonly VaultKey root = VaultKey.Generate();

    public SqlCipherTests(SqlCipherFixture fixture)
    {
        _ = fixture;
        Directory.CreateDirectory(folder);
    }

    [Fact]
    public void LoadedLibraryIsSqlCipher() => Assert.StartsWith("4.19.0", SqlCipher.Version, StringComparison.Ordinal);

    [Fact]
    public void KeyedDatabaseKeepsPlaintextOutOfTheFileAndWal()
    {
        string path = File("sessions.db");
        using StoreKey key = Key("sessions");
        using (SqlCipherDatabase database = new(path, key))
        using (SqliteConnection connection = database.Open())
        {
            Execute(connection, "PRAGMA journal_mode = WAL; CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT);");
            Insert(connection, Secret);
            Assert.Equal(Secret, Scalar(connection, "SELECT body FROM messages;"));
            AssertAbsent(path);
            AssertAbsent(path + "-wal");
        }
        Assert.True(SqlCipherDatabase.IsEncrypted(path));
    }

    [Fact]
    public void EncryptedDatabaseWithoutAKeyReportsKeyRequired()
    {
        string path = CreateEncrypted("sessions");
        Assert.Equal(EncryptionFailure.KeyRequired, Assert.Throws<EncryptionException>(() => SqlCipherDatabase.OpenPlain(path)).Failure);
    }

    [Fact]
    public void WrongKeyReportsKeyRejected()
    {
        string path = CreateEncrypted("sessions");
        using StoreKey wrong = Key("other");
        using SqlCipherDatabase database = new(path, StoreKey.FromBytes("sessions", 1, Bytes(wrong)));
        Assert.Equal(EncryptionFailure.KeyRejected, Assert.Throws<EncryptionException>(() => database.Open()).Failure);
    }

    [Fact]
    public void KeyIsNotInTheConnectionString()
    {
        string path = CreateEncrypted("sessions");
        using StoreKey key = Key("sessions");
        string hex = Convert.ToHexString(Bytes(key));
        using SqlCipherDatabase database = new(path, key);
        using SqliteConnection connection = database.Open();
        Assert.DoesNotContain(hex, connection.ConnectionString, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password", connection.ConnectionString, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void KeylessOpenOfTheSamePathGetsNoKeyedConnection()
    {
        string path = CreateEncrypted("sessions");
        using StoreKey key = Key("sessions");
        using SqlCipherDatabase database = new(path, key);
        using (SqliteConnection connection = database.Open()) Assert.Equal(Secret, Scalar(connection, "SELECT body FROM messages;"));
        using SqliteConnection keyless = new(new SqliteConnectionStringBuilder { DataSource = path }.ToString());
        keyless.Open();
        Assert.Throws<SqliteException>(() => Scalar(keyless, "SELECT body FROM messages;"));
    }

    [Fact]
    public void LockClosesOpenConnectionsAndDisposeRefusesNewOnes()
    {
        string path = CreateEncrypted("sessions");
        using StoreKey key = Key("sessions");
        SqlCipherDatabase database = new(path, key);
        using SqliteConnection held = database.Open();
        database.Lock();
        Assert.Equal(System.Data.ConnectionState.Closed, held.State);
        using (SqliteConnection reopened = database.Open()) Assert.Equal(Secret, Scalar(reopened, "SELECT body FROM messages;"));
        database.Dispose();
        Assert.Throws<ObjectDisposedException>(() => database.Open());
    }

    [Fact]
    public void LockedDatabaseReopensWithItsKey()
    {
        string path = CreateEncrypted("sessions");
        using StoreKey key = Key("sessions");
        using SqlCipherDatabase database = new(path, key);
        using (SqliteConnection connection = database.Open()) Assert.Equal(Secret, Scalar(connection, "SELECT body FROM messages;"));
        database.Lock();
        using (SqliteConnection connection = database.Open()) Assert.Equal(Secret, Scalar(connection, "SELECT body FROM messages;"));
    }

    [Fact]
    public void Fts5SearchWorksOnAnEncryptedDatabaseAfterReopen()
    {
        string path = File("index.db");
        using StoreKey key = Key("memory.index");
        using (SqlCipherDatabase database = new(path, key))
        using (SqliteConnection connection = database.Open())
        {
            Execute(connection, "CREATE VIRTUAL TABLE docs USING fts5(body);");
            Execute(connection, $"INSERT INTO docs (body) VALUES ('{Secret}'), ('nothing relevant here');");
        }
        using (SqlCipherDatabase database = new(path, key))
        using (SqliteConnection connection = database.Open())
            Assert.Equal(Secret, Scalar(connection, "SELECT body FROM docs WHERE docs MATCH 'lighthouse';"));
        AssertAbsent(path);
    }

    [Fact]
    public void ConversionRoundTripKeepsContent()
    {
        string plain = File("plain.db");
        using (SqliteConnection connection = SqlCipherDatabase.OpenPlain(plain, pooling: false))
        {
            Execute(connection, "PRAGMA journal_mode = WAL; PRAGMA user_version = 7; CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT, data BLOB);" +
                "CREATE TABLE settings (name TEXT PRIMARY KEY, value REAL) WITHOUT ROWID; CREATE VIRTUAL TABLE docs USING fts5(body);");
            Insert(connection, Secret);
            Execute(connection, "INSERT INTO messages (body, data) VALUES (NULL, x'00ff10'); INSERT INTO settings VALUES ('ratio', 0.5);" +
                $"INSERT INTO docs (body) VALUES ('{Secret}');");
        }

        string encrypted = File("encrypted.db");
        using StoreKey key = Key("sessions");
        ConversionResult toEncrypted = SqlCipherConversion.Encrypt(plain, encrypted, key);
        Assert.True(SqlCipherDatabase.IsEncrypted(encrypted));
        AssertAbsent(encrypted);
        Assert.True(toEncrypted.Rows >= 4);

        string decrypted = File("decrypted.db");
        ConversionResult toPlain = SqlCipherConversion.Decrypt(encrypted, key, decrypted);
        Assert.Equal(toEncrypted, toPlain);
        Assert.False(SqlCipherDatabase.IsEncrypted(decrypted));
        using SqliteConnection check = SqlCipherDatabase.OpenPlain(decrypted, pooling: false);
        Assert.Equal(7L, Scalar(check, "PRAGMA user_version;"));
        Assert.Equal("wal", Scalar(check, "PRAGMA journal_mode;"));
        Assert.Equal(Secret, Scalar(check, "SELECT body FROM docs WHERE docs MATCH 'harbor';"));
    }

    [Fact]
    public void ConversionRefusesAnExistingTarget()
    {
        string plain = File("plain.db");
        using (SqliteConnection connection = SqlCipherDatabase.OpenPlain(plain, pooling: false))
            Execute(connection, "CREATE TABLE t (x);");
        string target = File("target.db");
        System.IO.File.WriteAllText(target, "existing");
        using StoreKey key = Key("sessions");
        Assert.Throws<IOException>(() => SqlCipherConversion.Encrypt(plain, target, key));
        Assert.Equal("existing", System.IO.File.ReadAllText(target));
    }

    [Fact]
    public void ApplyKeyKeysAConnectionOpenedElsewhereAndThePoolKeepsIt()
    {
        string path = CreateEncrypted("sessions");
        string connectionString = new SqliteConnectionStringBuilder { DataSource = path, Pooling = true }.ToString();
        using StoreKey key = Key("sessions");
        using (SqliteConnection connection = new(connectionString))
        {
            connection.Open();
            SqlCipherDatabase.ApplyKey(connection, key);
            Assert.Equal(Secret, Scalar(connection, "SELECT body FROM messages;"));
        }

        using SqliteConnection pooled = new(connectionString);
        pooled.Open();
        Assert.Equal(Secret, Scalar(pooled, "SELECT body FROM messages;"));
    }

    [Fact]
    public void ApplyKeyWithTheWrongKeyReportsKeyRejected()
    {
        string path = CreateEncrypted("sessions");
        using StoreKey wrong = Key("memory");
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        EncryptionException error = Assert.Throws<EncryptionException>(() => SqlCipherDatabase.ApplyKey(connection, wrong));
        Assert.Equal(EncryptionFailure.KeyRejected, error.Failure);
    }

    [Fact]
    public void InPlaceConversionRoundTripKeepsContentAndLeavesNoCopy()
    {
        string path = File("live.db");
        using (SqliteConnection connection = SqlCipherDatabase.OpenPlain(path, pooling: false))
        {
            Execute(connection, "PRAGMA journal_mode = WAL; PRAGMA user_version = 3; CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT);");
            Insert(connection, Secret);
        }

        using StoreKey key = Key("sessions");
        ConversionResult? encrypted = SqlCipherConversion.EncryptInPlace(path, key);
        Assert.NotNull(encrypted);
        Assert.True(SqlCipherDatabase.IsEncrypted(path));
        AssertAbsent(path);
        AssertNoCopy(path);
        Assert.Null(SqlCipherConversion.EncryptInPlace(path, key));

        ConversionResult? decrypted = SqlCipherConversion.DecryptInPlace(path, key);
        Assert.Equal(encrypted, decrypted);
        Assert.False(SqlCipherDatabase.IsEncrypted(path));
        AssertNoCopy(path);
        Assert.Null(SqlCipherConversion.DecryptInPlace(path, key));
        using SqliteConnection check = SqlCipherDatabase.OpenPlain(path, pooling: false);
        Assert.Equal(3L, Scalar(check, "PRAGMA user_version;"));
        Assert.Equal(Secret, Scalar(check, "SELECT body FROM messages;"));
    }

    [Fact]
    public void InPlaceConversionDiscardsACopyLeftByAnInterruptedRun()
    {
        string path = File("live.db");
        using (SqliteConnection connection = SqlCipherDatabase.OpenPlain(path, pooling: false))
        {
            Execute(connection, "CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT);");
            Insert(connection, Secret);
        }
        System.IO.File.WriteAllText(path + SqlCipherConversion.ConvertingSuffix, "partial");
        System.IO.File.WriteAllText(path + SqlCipherConversion.ConvertingSuffix + "-wal", "partial");

        using StoreKey key = Key("sessions");
        Assert.NotNull(SqlCipherConversion.EncryptInPlace(path, key));
        Assert.True(SqlCipherDatabase.IsEncrypted(path));
        AssertNoCopy(path);
    }

    [Fact]
    public void InPlaceDecryptionWithTheWrongKeyLeavesTheFileEncrypted()
    {
        string path = CreateEncrypted("sessions");
        using StoreKey wrong = Key("memory");
        EncryptionException error = Assert.Throws<EncryptionException>(() => SqlCipherConversion.DecryptInPlace(path, wrong));
        Assert.Equal(EncryptionFailure.KeyRejected, error.Failure);
        Assert.True(SqlCipherDatabase.IsEncrypted(path));
        AssertNoCopy(path);
    }

    [Fact]
    public void BackupApiCopiesBetweenDatabasesWithTheSameKey()
    {
        string source = CreateEncrypted("sessions");
        string copy = File("copy.db");
        using StoreKey key = Key("sessions");
        using (SqlCipherDatabase from = new(source, key))
        using (SqlCipherDatabase to = new(copy, key))
        using (SqliteConnection fromConnection = from.Open())
        using (SqliteConnection toConnection = to.Open())
        {
            fromConnection.BackupDatabase(toConnection);
        }

        Assert.True(SqlCipherDatabase.IsEncrypted(copy));
        AssertAbsent(copy);
        using SqlCipherDatabase check = new(copy, key);
        using SqliteConnection connection = check.Open();
        Assert.Equal(Secret, Scalar(connection, "SELECT body FROM messages;"));
    }

    public void Dispose()
    {
        root.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(folder, recursive: true); }
        catch (IOException) { }
    }

    private string CreateEncrypted(string storeId)
    {
        string path = File(storeId + ".db");
        using StoreKey key = Key(storeId);
        using SqlCipherDatabase database = new(path, key);
        using SqliteConnection connection = database.Open();
        Execute(connection, "CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT);");
        Insert(connection, Secret);
        return path;
    }

    private StoreKey Key(string storeId) => root.DeriveStoreKey("agent-ds", StoreKind.Database, storeId);

    private string File(string name) => Path.Combine(folder, name);

    private static byte[] Bytes(StoreKey key)
    {
        byte[] bytes = new byte[StoreKey.Length];
        key.CopyTo(bytes);
        return bytes;
    }

    private static void AssertAbsent(string path)
    {
        if (!System.IO.File.Exists(path)) return;
        byte[] content;
        using (FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            content = new byte[stream.Length];
            stream.ReadExactly(content);
        }
        Assert.Equal(-1, content.AsSpan().IndexOf(Encoding.UTF8.GetBytes("lighthouse")));
    }

    private static void AssertNoCopy(string path)
    {
        foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
            Assert.False(System.IO.File.Exists(path + SqlCipherConversion.ConvertingSuffix + suffix));
    }

    private static void Insert(SqliteConnection connection, string body)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "INSERT INTO messages (body) VALUES ($body);";
        command.Parameters.AddWithValue("$body", body);
        command.ExecuteNonQuery();
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static object? Scalar(SqliteConnection connection, string sql)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
}
