using System.Collections.Concurrent;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace Darkspyre.Encryption;

/// <summary>
/// One SQLCipher database file and the store key that opens it. It opens keyed connections and locks the database
/// by closing them.
/// </summary>
/// <remarks>
/// <para>
/// The key never appears in a connection string or in SQL text. <see cref="Open"/> opens a connection with a keyless
/// connection string, then passes the raw 256-bit key to SQLCipher through the native <c>sqlite3_key</c> call before
/// any statement runs. EF Core and other callers receive the open <see cref="SqliteConnection"/>, not a string.
/// </para>
/// <para>
/// Connections are never pooled. A pooled native connection keeps its key, and Microsoft.Data.Sqlite would hand it
/// to any caller that opens the same keyless connection string. Opening a connection with a raw key does no key
/// stretching, so an unpooled open is cheap. The instance keeps its own copy of the key until <see cref="Dispose"/>.
/// </para>
/// </remarks>
public sealed class SqlCipherDatabase : IDisposable
{
    private const int NotADatabase = 26;
    private static readonly byte[] PlainHeader = "SQLite format 3\0"u8.ToArray();

    private readonly string connectionString;
    private readonly byte[] keyMaterial;
    private readonly ConcurrentDictionary<SqliteConnection, byte> open = new();
    private readonly Lock gate = new();
    private bool disposed;

    /// <summary>Describes a keyed database.</summary>
    /// <param name="path">The database file.</param>
    /// <param name="key">The store key. The instance copies it and zeroes the copy on <see cref="Dispose"/>.</param>
    /// <param name="mode">How connections open the file.</param>
    public SqlCipherDatabase(string path, StoreKey key, SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(key);
        Path = System.IO.Path.GetFullPath(path);
        StoreId = key.StoreId;
        connectionString = new SqliteConnectionStringBuilder { DataSource = Path, Mode = mode, Pooling = false }.ToString();
        keyMaterial = RawKeyBytes(key);
    }

    /// <summary>The database file.</summary>
    public string Path { get; }

    /// <summary>The store id of the key.</summary>
    public string StoreId { get; }

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

    /// <summary>Opens a keyed connection and checks that the key opens the file. The caller disposes it.</summary>
    /// <exception cref="EncryptionException">
    /// The key does not open the file (<see cref="EncryptionFailure.KeyRejected"/>), or SQLCipher is not serving the
    /// connection (<see cref="EncryptionFailure.SqlCipherUnavailable"/>).
    /// </exception>
    /// <exception cref="ObjectDisposedException">The database was locked by <see cref="Dispose"/>.</exception>
    public SqliteConnection Open()
    {
        SqliteConnection connection = new(connectionString);
        try
        {
            connection.Open();
            SqlCipher.RequireCipher(connection, StoreId);
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                int result = raw.sqlite3_key(connection.Handle, keyMaterial);
                if (result != raw.SQLITE_OK)
                    throw new EncryptionException(EncryptionFailure.SqlCipherUnavailable, $"SQLCipher refused the key for store '{StoreId}' (result {result}).");
            }
            Verify(connection, StoreId);
            Track(connection);
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
    /// Keys a connection another component opened, such as EF Core, before it runs any statement. The connection must be
    /// open, served by SQLCipher, and must not have read the database yet: open it without pragmas in its connection
    /// string. Call it once per native connection; a pooled connection that comes back keeps its key.
    /// </summary>
    /// <exception cref="EncryptionException">
    /// The key does not open the file (<see cref="EncryptionFailure.KeyRejected"/>), or SQLCipher is not serving the
    /// connection (<see cref="EncryptionFailure.SqlCipherUnavailable"/>).
    /// </exception>
    public static void ApplyKey(SqliteConnection connection, StoreKey key)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(key);
        if (connection.State != ConnectionState.Open)
            throw new InvalidOperationException("The connection must be open before it is keyed.");
        SqlCipher.RequireCipher(connection, key.StoreId);
        byte[] material = RawKeyBytes(key);
        try
        {
            int result = raw.sqlite3_key(connection.Handle, material);
            if (result != raw.SQLITE_OK)
                throw new EncryptionException(EncryptionFailure.SqlCipherUnavailable, $"SQLCipher refused the key for store '{key.StoreId}' (result {result}).");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }

        Verify(connection, key.StoreId);
    }

    /// <summary>
    /// Locks the database: closes every connection this instance opened that is still open, which releases their
    /// native cipher contexts. A caller still holding one sees it closed. New opens still work until
    /// <see cref="Dispose"/>.
    /// </summary>
    public void Lock()
    {
        foreach (SqliteConnection connection in open.Keys)
        {
            open.TryRemove(connection, out _);
            connection.Close();
        }
    }

    /// <summary>Locks the database and zeroes the key copy. Later calls to <see cref="Open"/> fail.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            CryptographicOperations.ZeroMemory(keyMaterial);
        }
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

    /// <summary>The SQLCipher raw key form <c>x'&lt;64 hex&gt;'</c> as ASCII bytes. The caller zeroes them.</summary>
    internal static byte[] RawKeyBytes(StoreKey key) => Encoding.ASCII.GetBytes("x'" + Convert.ToHexString(key.Bytes) + "'");

    private void Track(SqliteConnection connection)
    {
        open[connection] = 0;
        connection.StateChange += (_, change) =>
        {
            if (change.CurrentState == ConnectionState.Closed) open.TryRemove(connection, out byte _);
        };
    }

    private static EncryptionException Rejected(string storeId, Exception error) =>
        new(EncryptionFailure.KeyRejected, $"The key for store '{storeId}' does not open its database.", error);
}
