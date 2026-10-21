using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Darkspyre.Encryption.Relay;

/// <summary>ECDH on NIST P-256 with an ephemeral sender key, HKDF-SHA256 and AES-256-GCM.</summary>
/// <remarks>
/// A sealed message is the big-endian u16 length of the ephemeral SubjectPublicKeyInfo, that key, a 12-byte nonce, the
/// ciphertext and a 16-byte tag. Only the recipient's private key opens a message. The message does not authenticate its sender.
/// </remarks>
public sealed class EcdhP256RelayCipher : IRelayCipher
{
    private const int LengthPrefixBytes = 2;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int KeyBytes = 32;

    private static readonly byte[] InfoPrefix = Encoding.ASCII.GetBytes("darkspyre-relay");

    /// <inheritdoc />
    public RelayKeyPair CreateKeyPair()
    {
        using ECDiffieHellman key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return new RelayKeyPair(key.ExportSubjectPublicKeyInfo(), key.ExportPkcs8PrivateKey());
    }

    /// <inheritdoc />
    public byte[] Seal(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> plaintext)
    {
        using ECDiffieHellman recipient = ECDiffieHellman.Create();
        recipient.ImportSubjectPublicKeyInfo(recipientPublicKey, out _);
        using ECDiffieHellman ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] ephemeralPublicKey = ephemeral.ExportSubjectPublicKeyInfo();

        byte[] secret = ephemeral.DeriveRawSecretAgreement(recipient.PublicKey);
        byte[] key = DeriveKey(secret, recipientPublicKey, ephemeralPublicKey);
        CryptographicOperations.ZeroMemory(secret);

        byte[] message = new byte[LengthPrefixBytes + ephemeralPublicKey.Length + NonceBytes + plaintext.Length + TagBytes];
        Span<byte> span = message;
        BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)ephemeralPublicKey.Length);
        ephemeralPublicKey.CopyTo(span[LengthPrefixBytes..]);
        Span<byte> nonce = span.Slice(LengthPrefixBytes + ephemeralPublicKey.Length, NonceBytes);
        RandomNumberGenerator.Fill(nonce);
        Span<byte> ciphertext = span.Slice(LengthPrefixBytes + ephemeralPublicKey.Length + NonceBytes, plaintext.Length);
        Span<byte> tag = span[^TagBytes..];

        using (AesGcm aes = new(key, TagBytes))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        CryptographicOperations.ZeroMemory(key);
        return message;
    }

    /// <inheritdoc />
    public byte[] Open(RelayKeyPair keyPair, ReadOnlySpan<byte> sealedMessage)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        if (sealedMessage.Length < LengthPrefixBytes)
        {
            throw new CryptographicException("The sealed message is too short.");
        }

        int ephemeralLength = BinaryPrimitives.ReadUInt16BigEndian(sealedMessage);
        if (sealedMessage.Length < LengthPrefixBytes + ephemeralLength + NonceBytes + TagBytes)
        {
            throw new CryptographicException("The sealed message is too short.");
        }

        ReadOnlySpan<byte> ephemeralPublicKey = sealedMessage.Slice(LengthPrefixBytes, ephemeralLength);
        ReadOnlySpan<byte> nonce = sealedMessage.Slice(LengthPrefixBytes + ephemeralLength, NonceBytes);
        ReadOnlySpan<byte> body = sealedMessage[(LengthPrefixBytes + ephemeralLength + NonceBytes)..];
        ReadOnlySpan<byte> ciphertext = body[..^TagBytes];
        ReadOnlySpan<byte> tag = body[^TagBytes..];

        using ECDiffieHellman own = ECDiffieHellman.Create();
        own.ImportPkcs8PrivateKey(keyPair.PrivateKey.Span, out _);
        using ECDiffieHellman sender = ECDiffieHellman.Create();
        sender.ImportSubjectPublicKeyInfo(ephemeralPublicKey, out _);

        byte[] secret = own.DeriveRawSecretAgreement(sender.PublicKey);
        byte[] key = DeriveKey(secret, keyPair.PublicKey.Span, ephemeralPublicKey);
        CryptographicOperations.ZeroMemory(secret);

        byte[] plaintext = new byte[ciphertext.Length];
        try
        {
            using AesGcm aes = new(key, TagBytes);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return plaintext;
    }

    private static byte[] DeriveKey(byte[] secret, ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> ephemeralPublicKey)
    {
        byte[] info = new byte[InfoPrefix.Length + recipientPublicKey.Length + ephemeralPublicKey.Length];
        InfoPrefix.CopyTo(info, 0);
        recipientPublicKey.CopyTo(info.AsSpan(InfoPrefix.Length));
        ephemeralPublicKey.CopyTo(info.AsSpan(InfoPrefix.Length + recipientPublicKey.Length));
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, KeyBytes, salt: [], info: info);
    }
}
