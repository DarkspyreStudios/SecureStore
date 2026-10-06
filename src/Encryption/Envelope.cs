using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Darkspyre.Encryption;

/// <summary>
/// Seals whole files with AES-256-GCM in the Darkspyre envelope format, version 1.
/// </summary>
/// <remarks>
/// <para>Layout, little-endian:</para>
/// <list type="table">
/// <item><term>magic</term><description>4 bytes, ASCII <c>DSEV</c></description></item>
/// <item><term>format version</term><description>1 byte, 1</description></item>
/// <item><term>key version</term><description>int32</description></item>
/// <item><term>store id length</term><description>uint16, then the store id in UTF-8</description></item>
/// <item><term>nonce</term><description>12 random bytes, new on every seal</description></item>
/// <item><term>ciphertext</term><description>the same length as the plaintext</description></item>
/// <item><term>tag</term><description>16 bytes</description></item>
/// </list>
/// <para>
/// The associated data is the header from the magic through the nonce, then the asset name's UTF-8 length as a
/// uint32 and its bytes. A file copied to another asset name or into another store fails to open. A wrong key and
/// altered bytes both fail authentication; the envelope cannot tell them apart and reports
/// <see cref="EncryptionFailure.Tampered"/>.
/// </para>
/// </remarks>
public static class Envelope
{
    /// <summary>The largest plaintext sealed in one envelope: 64 MiB.</summary>
    public const int MaxPlaintextBytes = 64 * 1024 * 1024;

    /// <summary>The format version this library writes.</summary>
    public const byte FormatVersion = 1;

    private const int NonceLength = 12;
    private const int TagLength = 16;
    private static readonly byte[] Magic = "DSEV"u8.ToArray();

    /// <summary>Whether <paramref name="data"/> starts with the envelope magic bytes.</summary>
    public static bool IsSealed(ReadOnlySpan<byte> data) => data.StartsWith(Magic);

    /// <summary>Encrypts <paramref name="plaintext"/> for the asset named <paramref name="assetName"/>.</summary>
    /// <exception cref="EncryptionException">The plaintext exceeds <see cref="MaxPlaintextBytes"/>.</exception>
    public static byte[] Seal(StoreKey key, string assetName, ReadOnlySpan<byte> plaintext)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(assetName);
        if (plaintext.Length > MaxPlaintextBytes)
            throw new EncryptionException(EncryptionFailure.TooLarge,
                $"Asset '{assetName}' in store '{key.StoreId}' is larger than the {MaxPlaintextBytes} byte envelope limit.");

        byte[] storeId = Encoding.UTF8.GetBytes(key.StoreId);
        if (storeId.Length > ushort.MaxValue)
            throw new ArgumentException("The store id is too long for an envelope.", nameof(key));
        int headerLength = Magic.Length + 1 + 4 + 2 + storeId.Length + NonceLength;
        byte[] output = new byte[headerLength + plaintext.Length + TagLength];

        Span<byte> header = output.AsSpan(0, headerLength);
        Magic.CopyTo(header);
        int offset = Magic.Length;
        header[offset++] = FormatVersion;
        BinaryPrimitives.WriteInt32LittleEndian(header[offset..], key.KeyVersion);
        offset += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(header[offset..], (ushort)storeId.Length);
        offset += 2;
        storeId.CopyTo(header[offset..]);
        offset += storeId.Length;
        RandomNumberGenerator.Fill(header.Slice(offset, NonceLength));

        byte[] associated = AssociatedData(header, assetName);
        using AesGcm aes = new(key.Bytes, TagLength);
        aes.Encrypt(header.Slice(offset, NonceLength), plaintext,
            output.AsSpan(headerLength, plaintext.Length), output.AsSpan(headerLength + plaintext.Length, TagLength), associated);
        return output;
    }

    /// <summary>Authenticates and decrypts an envelope sealed for <paramref name="assetName"/>.</summary>
    /// <exception cref="EncryptionException">
    /// The data is not an envelope (<see cref="EncryptionFailure.UnsupportedFormat"/>), was sealed under another root
    /// key version (<see cref="EncryptionFailure.KeyRejected"/>), or fails authentication
    /// (<see cref="EncryptionFailure.Tampered"/>).
    /// </exception>
    public static byte[] Open(StoreKey key, string assetName, ReadOnlySpan<byte> sealedData)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentException.ThrowIfNullOrEmpty(assetName);
        int minimum = Magic.Length + 1 + 4 + 2 + NonceLength + TagLength;
        if (sealedData.Length < minimum || !IsSealed(sealedData))
            throw Failure(EncryptionFailure.UnsupportedFormat, key, assetName, "is not an encrypted envelope");
        int offset = Magic.Length;
        if (sealedData[offset++] != FormatVersion)
            throw Failure(EncryptionFailure.UnsupportedFormat, key, assetName, "uses an envelope format this library does not read");
        int keyVersion = BinaryPrimitives.ReadInt32LittleEndian(sealedData[offset..]);
        offset += 4;
        int storeIdLength = BinaryPrimitives.ReadUInt16LittleEndian(sealedData[offset..]);
        offset += 2;
        if (sealedData.Length < minimum + storeIdLength)
            throw Failure(EncryptionFailure.Tampered, key, assetName, "is truncated");
        string storeId = Encoding.UTF8.GetString(sealedData.Slice(offset, storeIdLength));
        offset += storeIdLength;
        if (!string.Equals(storeId, key.StoreId, StringComparison.Ordinal))
            throw Failure(EncryptionFailure.Tampered, key, assetName, "belongs to another store");
        if (keyVersion != key.KeyVersion)
            throw Failure(EncryptionFailure.KeyRejected, key, assetName, $"was sealed under key version {keyVersion}");

        int headerLength = offset + NonceLength;
        int cipherLength = sealedData.Length - headerLength - TagLength;
        if (cipherLength > MaxPlaintextBytes)
            throw Failure(EncryptionFailure.TooLarge, key, assetName, "is larger than the envelope limit");
        ReadOnlySpan<byte> header = sealedData[..headerLength];
        byte[] plaintext = new byte[cipherLength];
        try
        {
            using AesGcm aes = new(key.Bytes, TagLength);
            aes.Decrypt(header.Slice(offset, NonceLength), sealedData.Slice(headerLength, cipherLength),
                sealedData.Slice(headerLength + cipherLength, TagLength), plaintext, AssociatedData(header, assetName));
        }
        catch (AuthenticationTagMismatchException error)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw Failure(EncryptionFailure.Tampered, key, assetName,
                "failed authentication: it was altered, moved from another name, or sealed with another key", error);
        }
        return plaintext;
    }

    private static byte[] AssociatedData(ReadOnlySpan<byte> header, string assetName)
    {
        byte[] name = Encoding.UTF8.GetBytes(assetName);
        byte[] associated = new byte[header.Length + 4 + name.Length];
        header.CopyTo(associated);
        BinaryPrimitives.WriteUInt32LittleEndian(associated.AsSpan(header.Length), (uint)name.Length);
        name.CopyTo(associated, header.Length + 4);
        return associated;
    }

    private static EncryptionException Failure(EncryptionFailure failure, StoreKey key, string assetName, string reason,
        Exception? inner = null) =>
        new(failure, $"Asset '{assetName}' in store '{key.StoreId}' {reason}.", inner);
}
