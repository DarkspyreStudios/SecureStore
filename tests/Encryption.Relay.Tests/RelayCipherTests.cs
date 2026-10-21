using System.Security.Cryptography;
using System.Text;
using Darkspyre.Encryption.Relay;

namespace Encryption.Relay.Tests;

public sealed class RelayCipherTests
{
    [Fact]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "The test name states the behaviour as a sentence.")]
    public void Sealed_message_opens_only_with_the_recipient_private_key()
    {
        EcdhP256RelayCipher cipher = new();
        using RelayKeyPair recipient = cipher.CreateKeyPair();
        using RelayKeyPair other = cipher.CreateKeyPair();
        byte[] plaintext = Encoding.UTF8.GetBytes("{\"type\":\"projects.list\"}");

        byte[] sealedMessage = cipher.Seal(recipient.PublicKey.Span, plaintext);

        Assert.Equal(plaintext, cipher.Open(recipient, sealedMessage));
        Assert.ThrowsAny<CryptographicException>(() => cipher.Open(other, sealedMessage));
    }
}
