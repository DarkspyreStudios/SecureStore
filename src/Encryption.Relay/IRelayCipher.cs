namespace Darkspyre.Encryption.Relay;

/// <summary>Seals a message to one recipient's public key, and opens messages sealed to this client's key pair.</summary>
public interface IRelayCipher
{
    /// <summary>Creates a new key pair.</summary>
    RelayKeyPair CreateKeyPair();

    /// <summary>Seals plaintext so that only the holder of the recipient's private key can open it.</summary>
    byte[] Seal(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> plaintext);

    /// <summary>Opens a sealed message. Throws <see cref="System.Security.Cryptography.CryptographicException"/> when it fails.</summary>
    byte[] Open(RelayKeyPair keyPair, ReadOnlySpan<byte> sealedMessage);
}
