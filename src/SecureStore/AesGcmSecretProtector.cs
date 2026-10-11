using System.Security.Cryptography;

namespace SecureStore;

/// <summary>
/// Encrypts with AES-GCM under a key the host holds. The output is the nonce, then the
/// authentication tag, then the ciphertext, so a tampered file fails to decrypt instead of
/// yielding a wrong secret.
/// </summary>
public sealed class AesGcmSecretProtector : ISecretProtector, IDisposable
{
    private const int NonceLength = 12;
    private const int TagLength = 16;

    private readonly AesGcm _cipher;

    /// <param name="key">A 16, 24, or 32 byte key. The host is responsible for holding it.</param>
    public AesGcmSecretProtector(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException("An AES key must be 16, 24, or 32 bytes.", nameof(key));
        }

        _cipher = new AesGcm(key, TagLength);
    }

    /// <summary>Encrypts <paramref name="plaintext"/> under a fresh random nonce and returns the nonce, tag and ciphertext.</summary>
    public byte[] Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] output = new byte[NonceLength + TagLength + plaintext.Length];
        Span<byte> nonce = output.AsSpan(0, NonceLength);
        Span<byte> tag = output.AsSpan(NonceLength, TagLength);
        Span<byte> ciphertext = output.AsSpan(NonceLength + TagLength);

        RandomNumberGenerator.Fill(nonce);
        _cipher.Encrypt(nonce, plaintext, ciphertext, tag);
        return output;
    }

    /// <summary>Verifies and decrypts output of <see cref="Protect"/>. Throws <see cref="SecureStoreException"/> when the data is truncated or fails authentication.</summary>
    public byte[] Unprotect(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length < NonceLength + TagLength)
        {
            throw new SecureStoreException("The stored secret is truncated.");
        }

        ReadOnlySpan<byte> nonce = ciphertext.AsSpan(0, NonceLength);
        ReadOnlySpan<byte> tag = ciphertext.AsSpan(NonceLength, TagLength);
        ReadOnlySpan<byte> body = ciphertext.AsSpan(NonceLength + TagLength);

        byte[] plaintext = new byte[body.Length];
        try
        {
            _cipher.Decrypt(nonce, body, tag, plaintext);
            return plaintext;
        }
        catch (AuthenticationTagMismatchException exception)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new SecureStoreException(
                "The stored secret failed its authentication check. The file is damaged, or it was written under a different key.",
                exception);
        }
    }

    /// <summary>Releases the AES-GCM cipher.</summary>
    public void Dispose() => _cipher.Dispose();
}
