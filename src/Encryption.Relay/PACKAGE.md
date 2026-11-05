# Darkspyre.Encryption.Relay

Recipient-only message sealing for .NET applications using ECDH on NIST P-256, HKDF-SHA256 and AES-256-GCM. A relay
can transport the sealed bytes without holding the recipient's private key. The package targets .NET 11, has no
package dependencies, and uses the namespace `Darkspyre.Encryption.Relay`.

## Install

```bash
dotnet add package Darkspyre.Encryption.Relay
```

## Setup and usage

No registration or native library is required. Construct `EcdhP256RelayCipher` through its `IRelayCipher` contract.
Create and securely retain one recipient key pair; distribute only its public key to senders.

```csharp
using Darkspyre.Encryption.Relay;

IRelayCipher cipher = new EcdhP256RelayCipher();
using RelayKeyPair recipient = cipher.CreateKeyPair();
byte[] sealedMessage = cipher.Seal(recipient.PublicKey.Span, plaintext);
byte[] opened = cipher.Open(recipient, sealedMessage);
```

`Seal` creates a fresh ephemeral sender key and nonce for each message. `Open` returns the original bytes only when
the message is valid for that recipient. It throws `CryptographicException` for malformed, altered or wrong-recipient
messages. Do not interpret a failed open as an empty message.

`RelayKeyPair.PublicKey` holds SubjectPublicKeyInfo bytes. `PrivateKey` holds PKCS#8 bytes. A host restoring a saved
pair constructs `new RelayKeyPair(publicKeyBytes, privateKeyBytes)`. The pair owns the supplied private-key array and
zeroes it on `Dispose`; the host protects stored key material and clears any other copies itself. Losing the private
key makes messages sealed to it unreadable.

## Security boundaries

A sealed message does not authenticate its sender. The application authenticates the relay and the identity attached
to each message through its own protocol. Keep private keys and opened plaintext out of logs, URLs and relay metadata.
The package does not own key distribution, persistence, sender identity, replay control or transport.

The library is licensed under MIT. `LICENSE.md` contains the license text.
