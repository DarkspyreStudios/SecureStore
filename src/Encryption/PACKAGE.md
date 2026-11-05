# Darkspyre.Encryption

Encryption at rest for .NET applications: a vault root key, per-store derived keys, authenticated file envelopes and
keyed SQLCipher connections. The package targets .NET 10. Its namespace is `Darkspyre.Encryption`.

## Install

```bash
dotnet add package Darkspyre.Encryption
```

File envelopes use managed cryptography and need no native database library. SQLCipher support additionally requires
a native SQLCipher library supplied by the application.

## Root keys and file envelopes

Create a root once with `VaultKey.Generate()` and protect it in the application's credential vault or key-management
system. Restore that same root on later runs with `VaultKey.FromBytes`; generating another root does not open existing
assets. The application owns backup, delivery and retention of the root bytes.

```csharp
using Darkspyre.Encryption;

using VaultKey root = VaultKey.FromBytes(protectedRootBytes);
using StoreKey assetKey = root.DeriveStoreKey("com.example.app", StoreKind.Asset, "documents");
byte[] sealedData = Envelope.Seal(assetKey, "notes/welcome.txt", plaintext);
byte[] opened = Envelope.Open(assetKey, "notes/welcome.txt", sealedData);
```

The example's `protectedRootBytes` is the 32-byte root obtained securely by the host, not a hard-coded key. The host
clears its buffers when finished. Disposing `VaultKey` and `StoreKey` zeroes their key material.

Key derivation binds the application, store kind and stable store ID. A path is not a store ID. `StoreKind.Database`,
`Asset` and `Plugin` derive different keys. The envelope authenticates its store ID and asset name; moving ciphertext
to another name or store does not make it readable. A wrong key or altered data reports `EncryptionFailure.Tampered`.
The authenticated envelope accepts whole files up to 64 MiB.

## SQLCipher setup

Supply a community SQLCipher native library for the application's operating system and architecture, with FTS5 when
the application uses full-text search. This package does not download or bundle that binary. Deploy its native
crypto dependencies too, and redistribute the included `SQLCIPHER-LICENSE.md` with the binary.

Initialize it once, before any Microsoft.Data.Sqlite or EF Core connection is opened:

```csharp
SqlCipher.Initialize(absoluteSqlCipherLibraryPath);
using StoreKey databaseKey = root.DeriveStoreKey("com.example.app", StoreKind.Database, "catalog");
using var database = new SqlCipherDatabase(databasePath, databaseKey);
using var connection = database.Open();
```

The path identifies the native library file. Reinitializing the same path does nothing; selecting a different library
in that process throws. Every keyed connection verifies `PRAGMA cipher_version`, so plain SQLite never silently
ignores encryption. Do not initialize a different SQLite provider in the same process.

`Open()` passes the raw key through SQLCipher's native key API before running any statement. Keys are absent from SQL
text and connection strings. Connections are unpooled. Pass the open connection to EF Core. `Lock()` closes the
instance's open connections; `Dispose()` locks and clears its key copy. `OpenPlain(path)` refuses an encrypted file
with `KeyRequired`.

`SqlCipherConversion.Encrypt` and `Decrypt` write a converted copy at a new path and verify its schema and rows. The
source remains unchanged. The application decides when to replace it with the verified copy.

## Failures

`EncryptionException.Failure` identifies `KeyRequired`, `KeyRejected`, `Tampered`, `UnsupportedFormat`, `TooLarge`,
`SqlCipherUnavailable` or `ConversionMismatch`. The application must not log root keys, store keys or plaintext.
Keep the root's application/store identities stable so existing data remains addressable.

The library is licensed under MIT. `LICENSE.md` and `SQLCIPHER-LICENSE.md` contain the applicable notices.
