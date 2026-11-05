# Darkspyre.SecureStore

Operating-system credential storage for .NET applications through `ICredentialStore`. The desktop backends use macOS
Keychain, Windows Credential Manager and the Linux Secret Service. The package targets .NET 10. Its namespace is
`SecureStore`.

## Install

```bash
dotnet add package Darkspyre.SecureStore
```

## Register and use

```csharp
using SecureStore;

services.AddSecureStore(options =>
{
    options.ServiceName = "com.example.app";
    options.Label = "Example";
});
```

`AddSecureStore` registers one singleton `ICredentialStore` and selects the desktop backend. Inject it into the
application's credential consumer:

```csharp
public sealed class TokenCache(ICredentialStore credentials)
{
    public ValueTask SaveAsync(string token) => credentials.SetAsync("refresh-token", token);
    public ValueTask<string?> ReadAsync() => credentials.GetAsync("refresh-token");
    public ValueTask RemoveAsync() => credentials.DeleteAsync("refresh-token");
}
```

Without dependency injection, create the same store directly:

```csharp
ICredentialStore credentials = CredentialStoreFactory.Create(new SecureStoreOptions
{
    ServiceName = "com.example.app",
    Label = "Example"
});
```

`ServiceName` is required and has no default. It addresses every secret already saved by the application. Keep it
unchanged across releases. `Label` controls the name shown in system tools and defaults to `ServiceName`.

`GetAsync` returns null for a missing secret. Deleting a missing secret succeeds. Empty or whitespace names and secret
values are invalid; delete a secret to clear it. Names are trimmed. Every operation accepts a cancellation token.
Windows transparently splits values larger than its credential-blob limit and rejoins them on read.

## Platform setup

| Host | Requirement |
| --- | --- |
| macOS login keychain | The person may need to approve the application's access prompt. |
| Windows | Credential Manager is supplied by the operating system. |
| Linux | Install `libsecret-tools` and provide the user's session bus and an unlocked Secret Service. |

On Debian and Ubuntu, install the Linux tool with `sudo apt install libsecret-tools`. A missing tool throws
`PlatformNotSupportedException`. A Secret Service call that gives no answer within ten seconds throws
`SecureStoreException`, including a keyring waiting for an unlock prompt.

### macOS application isolation

`RequireApplicationIsolation = true` selects the data protection keychain. It requires a signed application bundle,
a provisioning profile for the application's App ID at `Contents/embedded.provisionprofile`, and these entitlements:

```xml
<key>com.apple.application-identifier</key>
<string>TEAMID.com.example.app</string>
<key>com.apple.developer.team-identifier</key>
<string>TEAMID</string>
<key>keychain-access-groups</key>
<array><string>TEAMID.com.example.app</string></array>
```

Use the application's Apple Developer Team ID and its own App ID. A bare command-line executable cannot carry the
required profile. A hardened-runtime .NET application also needs its runtime execution entitlements:

```xml
<key>com.apple.security.cs.allow-jit</key><true/>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
<key>com.apple.security.cs.disable-library-validation</key><true/>
```

Missing keychain access-group entitlements cause `SecureStoreException` on every operation.

Data-protection items are device-only and become accessible after the first unlock since boot. They do not sync to
iCloud or restore onto another Mac. They are separate from login-keychain items; choosing this backend does not move
existing secrets. Windows and Linux ignore this option.

## Hosts without a vault

An unsupported host throws `PlatformNotSupportedException` unless the application supplies `SecureStoreOptions.Fallback`.
An explicit in-memory fallback retains secrets only for the process lifetime:

```csharp
options.Fallback = () => new InMemoryCredentialStore();
```

An encrypted-file fallback needs a host-owned key:

```csharp
options.Fallback = () => new EncryptedFileCredentialStore(
    new AesGcmSecretProtector(key), Path.Combine(dataDirectory, "credentials"));
```

`AesGcmSecretProtector` accepts a 16-, 24- or 32-byte key. The application protects and retains it separately; the
library cannot recover a lost key. An application with its own protection mechanism implements `ISecretProtector`.

## Security boundaries and failures

`ServiceName` is a lookup identity, not access control. On Windows and Linux, other processes running as the same user
can reach that user's unlocked vault. The default macOS backend uses the item's access list; programs sharing a
`dotnet` host also share that process identity. Data-protection keychain access groups provide macOS application
isolation. No vault prevents hostile code already inside the application's process from reading its memory.

Vault failures, a locked keychain or denied access throw `SecureStoreException`. Invalid arguments throw
`ArgumentException`; a missing `ServiceName` throws `InvalidOperationException` at registration. Do not log credentials
or write them into configuration files.

The package is licensed under MIT. `LICENSE.md` contains the license text.
