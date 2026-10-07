using System.Security.Cryptography;
using System.Text;

namespace Darkspyre.Encryption;

/// <summary>What a store key protects. It is part of the derivation, so a database key never opens an asset.</summary>
public enum StoreKind
{
    /// <summary>A SQLCipher database, with its journal and write-ahead log.</summary>
    Database,

    /// <summary>A file sealed with <see cref="Envelope"/>, such as a settings file or a persisted asset.</summary>
    Asset,

    /// <summary>
    /// A whole plugin's key, with the plugin id as the store id. The plugin uses it for every store it owns, databases
    /// and files alike.
    /// </summary>
    Plugin,
}

/// <summary>
/// A vault root key: 32 random bytes that every store key derives from. The instance owns its copy of the bytes and
/// zeroes it on <see cref="Dispose"/>.
/// </summary>
/// <remarks>
/// The fingerprint identifies a root without revealing it: HMAC-SHA256 keyed by the root over the fixed label
/// <c>darkspyre-vault-fingerprint-v1</c>, as lowercase hex. Store keys use HKDF-SHA256 with the info label
/// <c>darkspyre-store-key-v1|&lt;application&gt;|&lt;database, asset or plugin&gt;|&lt;store id&gt;</c>. A store id must be stable across
/// moves and restarts; a file path is never a store id.
/// </remarks>
public sealed class VaultKey : IDisposable
{
    /// <summary>The length of a root key in bytes.</summary>
    public const int Length = 32;

    /// <summary>The subkey derivation this library implements.</summary>
    public const int DerivationVersion = 1;

    private static readonly byte[] FingerprintLabel = Encoding.ASCII.GetBytes("darkspyre-vault-fingerprint-v1");

    private readonly byte[] root;
    private bool disposed;

    private VaultKey(byte[] root, int keyVersion)
    {
        this.root = root;
        KeyVersion = keyVersion;
        Fingerprint = ComputeFingerprint(root);
    }

    /// <summary>The root key version. Store keys carry it into envelopes.</summary>
    public int KeyVersion { get; }

    /// <summary>The fingerprint of this root, as 64 lowercase hex characters.</summary>
    public string Fingerprint { get; }

    /// <summary>Creates a new random root.</summary>
    public static VaultKey Generate(int keyVersion = 1) =>
        new(RandomNumberGenerator.GetBytes(Length), CheckVersion(keyVersion));

    /// <summary>Copies an existing root. The caller keeps and clears its own buffer.</summary>
    /// <exception cref="ArgumentException">The root is not <see cref="Length"/> bytes.</exception>
    public static VaultKey FromBytes(ReadOnlySpan<byte> root, int keyVersion = 1)
    {
        if (root.Length != Length)
            throw new ArgumentException($"A vault root key is {Length} bytes.", nameof(root));
        return new VaultKey(root.ToArray(), CheckVersion(keyVersion));
    }

    /// <summary>The fingerprint of a root held elsewhere, such as a key file being validated.</summary>
    public static string ComputeFingerprint(ReadOnlySpan<byte> root)
    {
        if (root.Length != Length)
            throw new ArgumentException($"A vault root key is {Length} bytes.", nameof(root));
        Span<byte> mac = stackalloc byte[HMACSHA256.HashSizeInBytes];
        HMACSHA256.HashData(root, FingerprintLabel, mac);
        return Convert.ToHexStringLower(mac);
    }

    /// <summary>
    /// Copies the root into <paramref name="destination"/>, for a key file or a broker store request. The caller
    /// clears the destination when it is done.
    /// </summary>
    public void CopyTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (destination.Length < Length)
            throw new ArgumentException($"The destination must hold {Length} bytes.", nameof(destination));
        root.CopyTo(destination);
    }

    private static string KindLabel(StoreKind kind) => kind switch
    {
        StoreKind.Database => "database",
        StoreKind.Asset => "asset",
        StoreKind.Plugin => "plugin",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown store kind."),
    };

    /// <summary>Derives the key for one store.</summary>
    /// <param name="application">The application that owns the store, such as <c>agent-ds</c>.</param>
    /// <param name="kind">What the store is.</param>
    /// <param name="storeId">The store's stable id.</param>
    public StoreKey DeriveStoreKey(string application, StoreKind kind, string storeId)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(application);
        ArgumentException.ThrowIfNullOrWhiteSpace(storeId);
        if (application.Contains('|', StringComparison.Ordinal))
            throw new ArgumentException("An application name cannot contain '|'.", nameof(application));
        byte[] info = Encoding.UTF8.GetBytes(
            $"darkspyre-store-key-v{DerivationVersion}|{application}|{KindLabel(kind)}|{storeId}");
        byte[] subkey = HKDF.DeriveKey(HashAlgorithmName.SHA256, root, StoreKey.Length, salt: [], info);
        try
        {
            return StoreKey.FromBytes(storeId, KeyVersion, subkey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
        }
    }

    /// <summary>Zeroes the root.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(root);
    }

    private static int CheckVersion(int keyVersion) =>
        keyVersion > 0 ? keyVersion : throw new ArgumentOutOfRangeException(nameof(keyVersion), "A key version is positive.");
}

/// <summary>
/// The key for one store: 32 bytes derived from a vault root, with the store id and root key version it belongs to.
/// The instance owns its copy of the bytes and zeroes it on <see cref="Dispose"/>.
/// </summary>
/// <remarks>
/// A process that never holds the root, such as a service that receives store keys from its host, creates one with
/// <see cref="FromBytes"/>.
/// </remarks>
public sealed class StoreKey : IDisposable
{
    /// <summary>The length of a store key in bytes.</summary>
    public const int Length = 32;

    private readonly byte[] key;
    private bool disposed;

    private StoreKey(string storeId, int keyVersion, byte[] key)
    {
        StoreId = storeId;
        KeyVersion = keyVersion;
        this.key = key;
    }

    /// <summary>The stable id of the store this key opens.</summary>
    public string StoreId { get; }

    /// <summary>The version of the root this key derives from.</summary>
    public int KeyVersion { get; }

    /// <summary>Copies key bytes received from elsewhere. The caller keeps and clears its own buffer.</summary>
    public static StoreKey FromBytes(string storeId, int keyVersion, ReadOnlySpan<byte> key)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storeId);
        if (keyVersion <= 0) throw new ArgumentOutOfRangeException(nameof(keyVersion), "A key version is positive.");
        if (key.Length != Length) throw new ArgumentException($"A store key is {Length} bytes.", nameof(key));
        return new StoreKey(storeId, keyVersion, key.ToArray());
    }

    /// <summary>Copies the key into <paramref name="destination"/>, for delivery to another process.</summary>
    public void CopyTo(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (destination.Length < Length)
            throw new ArgumentException($"The destination must hold {Length} bytes.", nameof(destination));
        key.CopyTo(destination);
    }

    /// <summary>Zeroes the key.</summary>
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(key);
    }

    internal ReadOnlySpan<byte> Bytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return key;
        }
    }
}
