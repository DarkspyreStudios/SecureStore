# Darkspyre.Encryption

Encryption at rest for Darkspyre applications. The library holds a vault root key, derives one key per store, seals files in an authenticated envelope, and opens, locks and converts SQLCipher databases. It has no knowledge of brokers, settings, user interface or any one application.

## Keys

`VaultKey` holds a 32-byte root and zeroes it on `Dispose`.

- `VaultKey.Generate()` creates a random root. `VaultKey.FromBytes(root)` copies one from a broker reply or a key file.
- `Fingerprint` identifies the root without revealing it: HMAC-SHA256 keyed by the root over `darkspyre-vault-fingerprint-v1`, as lowercase hex. `VaultKey.ComputeFingerprint` computes it for bytes held elsewhere.
- `DeriveStoreKey(application, kind, storeId)` returns a `StoreKey` through HKDF-SHA256 with the info label `darkspyre-store-key-v1|<application>|<database, asset or plugin>|<store id>`. A store id is stable across moves and restarts. A file path is never a store id. A `Plugin` key uses the plugin id as its store id and covers every store that plugin owns.

`StoreKey` holds one 32-byte store key, its store id and the root key version. A process that never holds the root, such as a service that receives keys from its host, creates one with `StoreKey.FromBytes`. `CopyTo` copies the bytes out for delivery; the caller clears its buffer.

## Envelope

`Envelope.Seal(key, assetName, plaintext)` and `Envelope.Open(key, assetName, sealedData)` encrypt whole files with AES-256-GCM, up to 64 MiB. The header holds the magic bytes `DSEV`, the format version, the key version, the store id and a random nonce. The store id and asset name are authenticated, so a file copied to another name or store fails to open. A wrong key and altered bytes both report `EncryptionFailure.Tampered`.

## SQLCipher databases

Call `SqlCipher.Initialize(libraryPath)` once, before anything in the process opens a SQLite connection. It installs the SQLCipher build at that path as the SQLite provider for Microsoft.Data.Sqlite and EF Core. Every keyed open and every conversion checks `PRAGMA cipher_version` on its connection, so a plain SQLite build never silently ignores a key.

`SqlCipherDatabase` describes one database file and its store key. The key never appears in a connection string or in SQL text:

- `Open()` opens a connection with a keyless connection string, then passes the raw 256-bit key to SQLCipher through the native `sqlite3_key` call before any statement runs. A wrong key reports `KeyRejected`. EF Core receives the open connection object.
- Connections are never pooled, so a keyed native connection is never handed to a caller that opens the same path without the key. A raw key needs no key stretching, so an unpooled open is cheap.
- `Lock()` closes every connection the instance opened that is still open, releasing their cipher contexts. `Dispose()` locks and zeroes the instance's copy of the key.
- `SqlCipherDatabase.OpenPlain(path)` opens a plaintext database and reports `KeyRequired` for an encrypted file.
- `SqlCipherDatabase.IsEncrypted(path)` reports whether a file is not plaintext SQLite.

`SqlCipherConversion.Encrypt` and `SqlCipherConversion.Decrypt` write a converted copy to a new path with `sqlcipher_export`, passing the key as a bound blob parameter. The copy keeps `user_version` and WAL mode. Before returning, the conversion compares the schema, row counts and a SHA-256 digest of every row, including FTS5 shadow tables. A mismatch deletes the copy and reports `ConversionMismatch`. The source is never changed; the caller replaces it.

## Native library

The library loads a prebuilt community SQLCipher with FTS5. The osx-arm64 build is SQLCipher 4.19.0 on SQLite 3.53.4, with CommonCrypto and in-memory temporary storage; its build record is `BUILD.md` beside the binary in the shared drivers folder. An application that ships the binary also ships `SQLCIPHER-LICENSE.md`: the Zetetic copyright notice, licence conditions and disclaimer.

## Failures

Every failure is an `EncryptionException` with an `EncryptionFailure` value: `KeyRequired`, `KeyRejected`, `Tampered`, `UnsupportedFormat`, `TooLarge`, `SqlCipherUnavailable` or `ConversionMismatch`. Messages name the store and asset. They never contain key material or plaintext.

## Tests

`tests/Encryption.Tests` needs the SQLCipher binary. Set `DARKSPYRE_SQLCIPHER_LIBRARY` to the library file, or `DARKSPYRE_NATIVE_DRIVERS` to the drivers folder that holds `sqlcipher/4.19.0-osx-arm64/libsqlcipher.dylib`. Without either, the database tests fail with a message naming the variables.
