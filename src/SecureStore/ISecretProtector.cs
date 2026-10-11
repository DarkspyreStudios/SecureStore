namespace SecureStore;

/// <summary>
/// Encrypts the secrets <see cref="EncryptedFileCredentialStore"/> writes. The host supplies the
/// implementation, because a host with no credential vault has no operating system secret to
/// derive a key from, and a key the library invented for itself would sit in the same file it
/// protects.
/// </summary>
public interface ISecretProtector
{
    /// <summary>Encrypts <paramref name="plaintext"/> and returns data that <see cref="Unprotect"/> accepts.</summary>
    byte[] Protect(byte[] plaintext);

    /// <summary>Verifies and decrypts data that <see cref="Protect"/> returned, and returns the plaintext.</summary>
    byte[] Unprotect(byte[] ciphertext);
}
