using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Data.Sqlite;
using SQLitePCL;

namespace Darkspyre.Encryption;

/// <summary>
/// Loads the SQLCipher native library and makes it the SQLite provider for Microsoft.Data.Sqlite in this process.
/// </summary>
/// <remarks>
/// <para>
/// Call <see cref="Initialize"/> once, before anything else in the process opens a SQLite connection. It runs the
/// <see cref="SqliteConnection"/> static constructor first, so a SQLitePCLRaw bundle referenced elsewhere installs
/// its provider before this one replaces it.
/// </para>
/// <para>
/// Every keyed open and every conversion checks <c>PRAGMA cipher_version</c> on its own connection. If another
/// SQLite build serves the connection, the operation fails with <see cref="EncryptionFailure.SqlCipherUnavailable"/>
/// before it reads or writes data, so a key is never silently ignored by a plain SQLite build.
/// </para>
/// </remarks>
public static class SqlCipher
{
    private static readonly Lock Gate = new();
    private static string? loadedPath;

    /// <summary>The full path of the loaded SQLCipher library, or null before <see cref="Initialize"/>.</summary>
    public static string? LibraryPath
    {
        get
        {
            lock (Gate) return loadedPath;
        }
    }

    /// <summary>The SQLCipher version string, such as <c>4.19.0 community</c>.</summary>
    /// <exception cref="EncryptionException">SQLCipher is not serving connections.</exception>
    public static string Version
    {
        get
        {
            using SqliteConnection connection = new("Data Source=:memory:;Pooling=False");
            connection.Open();
            return RequireCipher(connection, ":memory:");
        }
    }

    /// <summary>
    /// Loads the SQLCipher library at <paramref name="libraryPath"/> and installs it as the SQLite provider.
    /// Calling it again with the same path does nothing.
    /// </summary>
    /// <exception cref="InvalidOperationException">A different library was already loaded.</exception>
    /// <exception cref="EncryptionException">The library loaded, but it is not SQLCipher.</exception>
    public static void Initialize(string libraryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);
        string full = Path.GetFullPath(libraryPath);
        lock (Gate)
        {
            if (loadedPath is not null)
            {
                if (string.Equals(loadedPath, full, StringComparison.Ordinal)) return;
                throw new InvalidOperationException($"SQLCipher is already loaded from '{loadedPath}'.");
            }
            if (!File.Exists(full))
                throw new EncryptionException(EncryptionFailure.SqlCipherUnavailable, $"The SQLCipher library '{full}' does not exist.");

            RuntimeHelpers.RunClassConstructor(typeof(SqliteConnection).TypeHandle);
            IntPtr handle = NativeLibrary.Load(full);
            SQLite3Provider_dynamic_cdecl.Setup("sqlcipher", new NativeExports(handle));
            raw.SetProvider(new SQLite3Provider_dynamic_cdecl());
            loadedPath = full;
        }
        _ = Version;
    }

    /// <summary>Returns the cipher version on <paramref name="connection"/>, or fails when SQLCipher is not serving it.</summary>
    internal static string RequireCipher(SqliteConnection connection, string database)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "PRAGMA cipher_version;";
        if (command.ExecuteScalar() is string version && version.Length > 0) return version;
        throw new EncryptionException(EncryptionFailure.SqlCipherUnavailable,
            $"Database '{database}' was opened by a SQLite build without SQLCipher. Call SqlCipher.Initialize before any SQLite use.");
    }

    private sealed class NativeExports(IntPtr handle) : IGetFunctionPointer
    {
        public IntPtr GetFunctionPointer(string name) =>
            NativeLibrary.TryGetExport(handle, name, out IntPtr address) ? address : IntPtr.Zero;
    }
}
