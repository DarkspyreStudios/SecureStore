using Microsoft.Data.Sqlite;

namespace Darkspyre.Encryption;

/// <summary>
/// One SQLCipher database file and the store key that opens it. It creates keyed connections and locks the
/// database by clearing their pool.
/// </summary>
/// <remarks>
/// <para>
/// The key is applied as a raw 256-bit SQLCipher key through the connection string's <c>Password</c> keyword, so
/// Microsoft.Data.Sqlite runs <c>PRAGMA key</c> once on each new native connection, before any other statement. EF
/// Core and other callers that take a connection string use <see cref="ConnectionString"/> unchanged.
/// </para>
/// <para>
/// <see cref="ConnectionString"/> contains the key. It must never be logged, persisted or shown.
/// </para>
/// </remarks>
public sealed class SqlCipherDatabase : IDisposable
{
    private static readonly byte[] PlainHeader = "SQLite format 3\0"u8.ToArray();
    private bool disposed;

    /// <summary>Describes a keyed database.</summary>
    /// <param name="path">The database file.</param>
    /// <param name="key">The store key. The instance reads it now and does not keep it.</param>
    /// <param name="mode">How connections open the file.</param>
    /// <param name="pooling">Whether connections are pooled. <see cref="Lock"/> clears the pool.</param>
    public SqlCipherDatabase(string path, StoreKey key, SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate, bool pooling = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(key);
        Path = System.IO.Path.GetFullPath(path);
        StoreId = key.StoreId;
        ConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path,
            Mode = mode,
            Pooling = pooling,
            Password = RawKey(key),
        }.ToString();
    }

    /// <summary>The database file.</summary>
    public string Path { get; }

    /// <summary>The store id of the key.</summary>
    public string StoreId { get; }

    /// <summary>The keyed connection string. It contains the key: never log, persist or show it.</summary>
    public string ConnectionString { get; }

    /// <summary>
    /// Whether the file at <paramref name="path"/> exists and is not a plaintext SQLite database. An empty or missing
    /// file is not encrypted.
    /// </summary>
    public static bool IsEncrypted(string path)
    {
        FileInfo file = new(path);
        if (!file.Exists || file.Length == 0) return false;
        Span<byte> header = stackalloc byte[16];
        using FileStream stream = file.OpenRead();
        return stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) < header.Length || !header.SequenceEqual(PlainHeader);
    }

    /// <summary>
    /// Opens a plaintext database. An encrypted file fails with <see cref="EncryptionFailure.KeyRequired"/> instead of
    /// SQLite's generic "file is not a database" error.
    /// </summary>
    public static SqliteConnection OpenPlain(string path, SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate, bool pooling = true)
    {
        if (IsEncrypted(path))
            throw new EncryptionException(EncryptionFailure.KeyRequired, $"Database '{System.IO.Path.GetFileName(path)}' is encrypted and no key was supplied.");
        SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Mode = mode, Pooling = pooling }.ToString());
        connection.Open();
        return connection;
    }

    /// <summary>Opens a keyed connection and checks that the key opens the file.</summary>
    /// <exception cref="EncryptionException">
    /// The key does not open the file (<see cref="EncryptionFailure.KeyRejected"/>), or SQLCipher is not serving the
    /// connection (<see cref="EncryptionFailure.SqlCipherUnavailable"/>).
    /// </exception>
    public SqliteConnection Open()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        SqliteConnection connection = new(ConnectionString);
        try
        {
            connection.Open();
            SqlCipher.RequireCipher(connection, StoreId);
            Verify(connection, StoreId);
            return connection;
        }
        catch (SqliteException error) when (error.SqliteErrorCode == NotADatabase)
        {
            connection.Dispose();
            throw Rejected(StoreId, error);
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Locks the database: clears the connection pool so idle native connections close and release their cipher
    /// contexts. Connections still open close when they are disposed and are not returned to the pool.
    /// </summary>
    public void Lock()
    {
        using SqliteConnection connection = new(ConnectionString);
        SqliteConnection.ClearPool(connection);
    }

    /// <summary>Locks the database.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        Lock();
    }

    /// <summary>Reads the schema, which fails when the key does not open the file.</summary>
    internal static void Verify(SqliteConnection connection, string storeId)
    {
        try
        {
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_master;";
            command.ExecuteScalar();
        }
        catch (SqliteException error) when (error.SqliteErrorCode == NotADatabase)
        {
            throw Rejected(storeId, error);
        }
    }

    private const int NotADatabase = 26;

    private static EncryptionException Rejected(string storeId, Exception error) =>
        new(EncryptionFailure.KeyRejected, $"The key for store '{storeId}' does not open its database.", error);

    /// <summary>The SQLCipher raw key form, <c>x'&lt;64 hex&gt;'</c>.</summary>
    internal static string RawKey(StoreKey key) => "x'" + Convert.ToHexString(key.Bytes) + "'";
}
