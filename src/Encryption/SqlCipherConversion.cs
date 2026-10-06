using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Darkspyre.Encryption;

/// <summary>What a conversion copied and verified.</summary>
/// <param name="Tables">The number of tables whose rows were compared.</param>
/// <param name="Rows">The number of rows compared across those tables.</param>
/// <param name="ContentDigest">SHA-256 over the schema and every compared row, as lowercase hex. Source and copy match.</param>
public sealed record ConversionResult(int Tables, long Rows, string ContentDigest);

/// <summary>
/// Converts a whole SQLite database between plaintext and SQLCipher with <c>sqlcipher_export</c>, and verifies the
/// copy before reporting success.
/// </summary>
/// <remarks>
/// <para>
/// A conversion reads the source and writes a new file at the target path. It never changes or deletes the source.
/// The caller replaces the source with the target once its own journal records the verified copy.
/// </para>
/// <para>
/// The copy keeps the source's <c>user_version</c> and its WAL journal mode. Verification compares the schema, the
/// row count of every ordinary table and a digest of every row, including the shadow tables of virtual tables such
/// as FTS5. A mismatch deletes the target and fails with <see cref="EncryptionFailure.ConversionMismatch"/>.
/// </para>
/// </remarks>
public static class SqlCipherConversion
{
    private static readonly string[] Companions = ["-wal", "-shm", "-journal"];

    /// <summary>Writes an encrypted copy of the plaintext database at <paramref name="plainPath"/>.</summary>
    /// <exception cref="FileNotFoundException">The source does not exist.</exception>
    /// <exception cref="IOException">The target already exists.</exception>
    public static ConversionResult Encrypt(string plainPath, string encryptedPath, StoreKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        RequireSource(plainPath);
        RequireFreeTarget(encryptedPath);
        // ATTACH inherits the main connection's open flags, so the source opens with create permission.
        using SqliteConnection source = SqlCipherDatabase.OpenPlain(plainPath, SqliteOpenMode.ReadWriteCreate, pooling: false);
        SqlCipher.RequireCipher(source, key.StoreId);
        Export(source, encryptedPath, "encrypted", SqlCipherDatabase.RawKey(key));
        using SqlCipherDatabase target = new(encryptedPath, key, SqliteOpenMode.ReadWrite, pooling: false);
        using SqliteConnection copy = target.Open();
        return Compare(source, copy, encryptedPath, key.StoreId);
    }

    /// <summary>Writes a plaintext copy of the encrypted database at <paramref name="encryptedPath"/>.</summary>
    /// <exception cref="FileNotFoundException">The source does not exist.</exception>
    /// <exception cref="IOException">The target already exists.</exception>
    public static ConversionResult Decrypt(string encryptedPath, StoreKey key, string plainPath)
    {
        ArgumentNullException.ThrowIfNull(key);
        RequireSource(encryptedPath);
        RequireFreeTarget(plainPath);
        using SqlCipherDatabase sourceDatabase = new(encryptedPath, key, SqliteOpenMode.ReadWriteCreate, pooling: false);
        using SqliteConnection source = sourceDatabase.Open();
        Export(source, plainPath, "plaintext", "");
        using SqliteConnection copy = SqlCipherDatabase.OpenPlain(plainPath, SqliteOpenMode.ReadWrite, pooling: false);
        return Compare(source, copy, plainPath, key.StoreId);
    }

    /// <summary>Computes the verification digest of one open database.</summary>
    public static ConversionResult Measure(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        int tables = 0;
        long rows = 0;
        List<(string Name, bool WithoutRowId)> ordinary = [];
        using (SqliteCommand schema = connection.CreateCommand())
        {
            schema.CommandText =
                "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name;";
            using SqliteDataReader reader = schema.ExecuteReader();
            while (reader.Read())
            {
                AppendRow(hash, reader);
                string sql = reader.IsDBNull(3) ? "" : reader.GetString(3);
                if (reader.GetString(0) == "table" && !sql.StartsWith("CREATE VIRTUAL TABLE", StringComparison.OrdinalIgnoreCase))
                    ordinary.Add((reader.GetString(1), sql.Contains("WITHOUT ROWID", StringComparison.OrdinalIgnoreCase)));
            }
        }
        foreach ((string name, bool withoutRowId) in ordinary)
        {
            tables++;
            hash.AppendData(Encoding.UTF8.GetBytes("\u0001table:" + name));
            using SqliteCommand select = connection.CreateCommand();
            select.CommandText = $"SELECT * FROM \"{name.Replace("\"", "\"\"", StringComparison.Ordinal)}\"" + (withoutRowId ? ";" : " ORDER BY rowid;");
            using SqliteDataReader reader = select.ExecuteReader();
            while (reader.Read())
            {
                rows++;
                AppendRow(hash, reader);
            }
        }
        return new ConversionResult(tables, rows, Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    private static void Export(SqliteConnection source, string targetPath, string alias, string key)
    {
        long userVersion = Scalar(source, "PRAGMA main.user_version;");
        bool wal = string.Equals(Text(source, "PRAGMA main.journal_mode;"), "wal", StringComparison.OrdinalIgnoreCase);
        try
        {
            using (SqliteCommand attach = source.CreateCommand())
            {
                attach.CommandText = $"ATTACH DATABASE $path AS {alias} KEY $key;";
                attach.Parameters.AddWithValue("$path", Path.GetFullPath(targetPath));
                attach.Parameters.AddWithValue("$key", key);
                attach.ExecuteNonQuery();
            }
            Execute(source, $"SELECT sqlcipher_export('{alias}');");
            Execute(source, $"PRAGMA {alias}.user_version = {userVersion};");
            if (wal) Text(source, $"PRAGMA {alias}.journal_mode = WAL;");
            Execute(source, $"DETACH DATABASE {alias};");
        }
        catch
        {
            TryDetach(source, alias);
            DeleteSet(targetPath);
            throw;
        }
    }

    private static ConversionResult Compare(SqliteConnection source, SqliteConnection copy, string targetPath, string storeId)
    {
        ConversionResult expected = Measure(source);
        ConversionResult actual = Measure(copy);
        if (expected == actual) return actual;
        copy.Close();
        SqliteConnection.ClearPool(copy);
        DeleteSet(targetPath);
        throw new EncryptionException(EncryptionFailure.ConversionMismatch,
            $"The converted copy of store '{storeId}' does not match its source ({expected.Tables} tables, {expected.Rows} rows expected; {actual.Tables} tables, {actual.Rows} rows copied). The copy was deleted.");
    }

    private static void AppendRow(IncrementalHash hash, SqliteDataReader reader)
    {
        Span<byte> length = stackalloc byte[8];
        for (int column = 0; column < reader.FieldCount; column++)
        {
            object value = reader.GetValue(column);
            (byte tag, byte[] bytes) = value switch
            {
                DBNull => ((byte)0, Array.Empty<byte>()),
                long number => ((byte)1, BitConverter.GetBytes(number)),
                double real => ((byte)2, BitConverter.GetBytes(real)),
                string text => ((byte)3, Encoding.UTF8.GetBytes(text)),
                byte[] blob => ((byte)4, blob),
                _ => ((byte)5, Encoding.UTF8.GetBytes(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "")),
            };
            hash.AppendData([tag]);
            BitConverter.TryWriteBytes(length, (long)bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        hash.AppendData([0xFF]);
    }

    private static void RequireSource(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path)) throw new FileNotFoundException($"The conversion source '{Path.GetFileName(path)}' does not exist.");
    }

    private static void RequireFreeTarget(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        foreach (string suffix in Companions.Prepend(""))
            if (File.Exists(path + suffix))
                throw new IOException($"The conversion target '{Path.GetFileName(path + suffix)}' already exists.");
    }

    private static void DeleteSet(string path)
    {
        foreach (string suffix in Companions.Prepend(""))
        {
            try { File.Delete(path + suffix); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void TryDetach(SqliteConnection connection, string alias)
    {
        try { Execute(connection, $"DETACH DATABASE {alias};"); }
        catch (SqliteException) { }
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string? Text(SqliteConnection connection, string sql)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar() as string;
    }
}
