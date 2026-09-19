namespace SecureStore;

/// <summary>
/// Encrypts the secrets <see cref="EncryptedFileCredentialStore"/> writes. The host supplies the
/// implementation, because a host with no credential vault has no operating system secret to
/// derive a key from, and a key the library invented for itself would sit in the same file it
/// protects.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] ciphertext);
}
