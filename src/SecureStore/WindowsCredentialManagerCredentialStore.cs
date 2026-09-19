using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SecureStore.Internal;

namespace SecureStore;

/// <summary>
/// Stores secrets as generic credentials in Windows Credential Manager.
/// </summary>
/// <remarks>
/// Credential Manager caps one credential blob at 2560 bytes, and an OAuth bundle carrying an
/// access token, a refresh token, and an identity token exceeds that. A secret over the cap is
/// split across numbered entries and rejoined on read, so the same value stores on every platform.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsCredentialManagerCredentialStore : ICredentialStore, IDisposable
{
    private const uint CredentialTypeGeneric = 1;
    private const uint CredentialPersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;

    private readonly string _targetPrefix;
    private readonly string _label;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsCredentialManagerCredentialStore(SecureStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _targetPrefix = options.ServiceName + "/";
        _label = options.ResolvedLabel;
    }

    public async ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        string target = Target(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string? stored = ReadEntry(target);
            if (stored is null)
            {
                return null;
            }

            return ChunkedSecret.IsHeader(stored) ? ReadChunks(target, stored) : stored;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default)
    {
        string target = Target(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
            try
            {
                if (ChunkedSecret.Fits(secretBytes))
                {
                    WriteEntry(target, secretBytes);
                    DeleteChunksFrom(target, 1);
                    return;
                }

                WriteChunked(target, secretBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secretBytes);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        string target = Target(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            DeleteEntry(target);
            DeleteChunksFrom(target, 1);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    /// <summary>
    /// Writes the pieces before the header, so a process that stops part way leaves the previous
    /// complete secret in the primary entry.
    /// </summary>
    private void WriteChunked(string target, byte[] secretBytes)
    {
        IReadOnlyList<string> pieces = ChunkedSecret.Split(secretBytes);
        for (int index = 0; index < pieces.Count; index++)
        {
            byte[] piece = Encoding.UTF8.GetBytes(pieces[index]);
            try
            {
                WriteEntry(ChunkTarget(target, index + 1), piece);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(piece);
            }
        }

        WriteEntry(target, Encoding.UTF8.GetBytes(ChunkedSecret.Header(pieces.Count)));
        DeleteChunksFrom(target, pieces.Count + 1);
    }

    private static string ReadChunks(string target, string header)
    {
        int count = ChunkedSecret.ReadCount(header);
        var pieces = new List<string>(count);
        for (int index = 1; index <= count; index++)
        {
            pieces.Add(ReadEntry(ChunkTarget(target, index))
                ?? throw new SecureStoreException(
                    $"The secret '{target}' is stored in {count} pieces and piece {index} is missing."));
        }

        return ChunkedSecret.Join(pieces);
    }

    /// <summary>Removes numbered pieces from <paramref name="start"/> up, stopping at the first gap.</summary>
    private static void DeleteChunksFrom(string target, int start)
    {
        for (int index = start; ; index++)
        {
            if (!DeleteEntry(ChunkTarget(target, index)))
            {
                return;
            }
        }
    }

    private static string ChunkTarget(string target, int index) =>
        $"{target}#{index.ToString(System.Globalization.CultureInfo.InvariantCulture)}";

    private static string? ReadEntry(string target)
    {
        if (!CredRead(target, CredentialTypeGeneric, 0, out IntPtr credentialPointer))
        {
            int error = Marshal.GetLastWin32Error();
            return error == ErrorNotFound ? null : throw CreateException("read", error);
        }

        try
        {
            NativeCredential credential = Marshal.PtrToStructure<NativeCredential>(credentialPointer);
            int length = checked((int)credential.CredentialBlobSize);
            byte[] bytes = new byte[length];
            try
            {
                if (length > 0)
                {
                    Marshal.Copy(credential.CredentialBlob, bytes, 0, length);
                }

                return Encoding.UTF8.GetString(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
        finally
        {
            CredFree(credentialPointer);
        }
    }

    private void WriteEntry(string target, byte[] blob)
    {
        GCHandle handle = default;
        try
        {
            handle = GCHandle.Alloc(blob, GCHandleType.Pinned);
            var credential = new NativeCredential
            {
                Type = CredentialTypeGeneric,
                TargetName = target,
                Comment = _label,
                CredentialBlobSize = checked((uint)blob.Length),
                CredentialBlob = handle.AddrOfPinnedObject(),
                Persist = CredentialPersistLocalMachine,
                UserName = Environment.UserName
            };

            if (!CredWrite(ref credential, 0))
            {
                throw CreateException("save", Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            if (handle.IsAllocated)
            {
                handle.Free();
            }
        }
    }

    private static bool DeleteEntry(string target)
    {
        if (CredDelete(target, CredentialTypeGeneric, 0))
        {
            return true;
        }

        int error = Marshal.GetLastWin32Error();
        return error == ErrorNotFound ? false : throw CreateException("delete", error);
    }

    private string Target(string name)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "WindowsCredentialManagerCredentialStore requires Windows.");
        }

        return _targetPrefix + CredentialName.Normalize(name);
    }

    private static SecureStoreException CreateException(string operation, int error) =>
        new SecureStoreException(
            $"Windows Credential Manager could not {operation} the secret.",
            new Win32Exception(error));

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public uint Flags;
        public uint Type;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string? TargetName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string? Comment;

        public FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string? TargetAlias;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string? UserName;
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredRead(string target, uint type, int reservedFlag, out IntPtr credentialPointer);

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite(ref NativeCredential credential, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("Advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
}
