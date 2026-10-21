using System.Security.Cryptography;

namespace Darkspyre.Encryption.Relay;

/// <summary>A key pair: SubjectPublicKeyInfo public key and PKCS#8 private key.</summary>
/// <param name="publicKey">The SubjectPublicKeyInfo encoding of the public key.</param>
/// <param name="privateKey">The PKCS#8 encoding of the private key. The pair owns this array and zeroes it on <see cref="Dispose"/>.</param>
public sealed class RelayKeyPair(byte[] publicKey, byte[] privateKey) : IDisposable
{
    private readonly byte[] _privateKey = privateKey;

    /// <summary>The SubjectPublicKeyInfo encoding of the public key.</summary>
    public ReadOnlyMemory<byte> PublicKey { get; } = publicKey;

    /// <summary>The PKCS#8 encoding of the private key. <see cref="Dispose"/> zeroes it.</summary>
    public ReadOnlyMemory<byte> PrivateKey => _privateKey;

    /// <summary>Zeroes the private key.</summary>
    public void Dispose() => CryptographicOperations.ZeroMemory(_privateKey);
}
