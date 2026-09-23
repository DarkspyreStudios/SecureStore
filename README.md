<img src=".github/banner.svg" alt="Darkspyre SecureStore">

# SecureStore

> **Proprietary software.** Copyright © 2026 Brandon Mathis. All rights reserved.
> No permission is granted to use, copy, modify, or distribute this software
> without prior written authorization. See [LICENSE.md](LICENSE.md).

SecureStore keeps an application's secrets in the operating system credential vault. It exposes
one small interface, `ICredentialStore`, over macOS Keychain, Windows Credential Manager, and the
Linux Secret Service. Application code reads, writes, and deletes a secret by name and never
touches a platform API.

## Purpose

Refresh tokens, API keys, and connection passwords do not belong in configuration files, local
databases, or application-data folders. Any process running as the same user can read those
files, and backups copy them. The operating system vault encrypts secrets at rest, ties them to
the signed-in user, and lets a person inspect or revoke them with the system tools.

Each vault has its own API, its own size limits, and its own failure modes. SecureStore hides
those differences:

- One API on every desktop platform. The backend for the current host is chosen at runtime.
- A secret of any length stores on every platform. Windows splits a long secret across entries
  and rejoins it on read.
- A missing secret reads as `null`. Deleting a missing secret succeeds.
- A host with no vault fails loudly by default, or uses a fallback the application chooses.

SecureStore stores secrets only. Use `Darkspyre.Persistence` for ordinary application files and
blobs.

## Install

```
dotnet add package Darkspyre.SecureStore
```

The package targets .NET 10. The namespace is `SecureStore`.

## Quick start

Register the store once, with a `ServiceName` that identifies your application:

```csharp
using SecureStore;

services.AddSecureStore(options =>
{
    options.ServiceName = "com.example.app";
    options.Label = "Example";
});
```

Inject `ICredentialStore` wherever a secret is needed:

```csharp
public sealed class SessionService(ICredentialStore credentials)
{
    public ValueTask SignInAsync(string refreshToken) =>
        credentials.SetAsync("refresh-token", refreshToken);

    public ValueTask<string?> ResumeAsync() =>
        credentials.GetAsync("refresh-token");

    public ValueTask SignOutAsync() =>
        credentials.DeleteAsync("refresh-token");
}
```

`AddSecureStore` registers `ICredentialStore` as a singleton and picks the backend for the current
host.

## The interface

| Method | Behavior |
| --- | --- |
| `GetAsync(name)` | Returns the secret stored under `name`, or `null` when there is none. |
| `SetAsync(name, secret)` | Stores `secret` under `name`, replacing any existing value. |
| `DeleteAsync(name)` | Removes the secret under `name`. Succeeds when there is none. |

A name must not be empty or whitespace, and neither may a secret. To clear a secret, delete it.
Surrounding whitespace in a name is trimmed, so `" api-key "` and `"api-key"` address the same
secret. Every method accepts an optional `CancellationToken`.

## Examples

### Without a service container

`CredentialStoreFactory.Create` builds the same store for a console tool or any application that
has no dependency injection container:

```csharp
using SecureStore;

ICredentialStore credentials = CredentialStoreFactory.Create(new SecureStoreOptions
{
    ServiceName = "com.example.cli",
    Label = "Example CLI",
});

string? apiKey = await credentials.GetAsync("api-key");
if (apiKey is null)
{
    Console.Write("API key: ");
    apiKey = Console.ReadLine()!;
    await credentials.SetAsync("api-key", apiKey);
}
```

### Storing structured secrets

A secret is a string. Serialize a group of related values into one secret so they are written
and removed together:

```csharp
using System.Text.Json;
using SecureStore;

public sealed record TokenBundle(string AccessToken, string RefreshToken, string IdToken);

public sealed class TokenCache(ICredentialStore credentials)
{
    private const string Name = "oauth-tokens";

    public ValueTask SaveAsync(TokenBundle tokens) =>
        credentials.SetAsync(Name, JsonSerializer.Serialize(tokens));

    public async ValueTask<TokenBundle?> LoadAsync()
    {
        string? json = await credentials.GetAsync(Name);
        return json is null ? null : JsonSerializer.Deserialize<TokenBundle>(json);
    }
}
```

A bundle like this often exceeds the Windows Credential Manager limit of 2560 bytes. SecureStore
splits it across numbered entries, so the code above runs unchanged on every platform.

### Handling vault failures

A locked keychain or a denied access prompt throws `SecureStoreException`. Treat it as "no usable
secret" when the application can recover by asking the user again:

```csharp
string? refreshToken;
try
{
    refreshToken = await credentials.GetAsync("refresh-token");
}
catch (SecureStoreException)
{
    refreshToken = null;
}

if (refreshToken is null)
{
    await ShowSignInAsync();
}
```

## ServiceName

`ServiceName` identifies the application inside the vault. It is the service attribute on macOS and
Linux, and the target prefix on Windows. Every application must set its own value and must keep
that value stable across releases. Changing it hides every secret stored under the previous value.
The library has no default, and registration throws `InvalidOperationException` when the value is
missing.

`Label` is the name a person sees when browsing the vault. It defaults to `ServiceName`.

## Threat model

`ServiceName` is a lookup key, not an access control. SecureStore runs inside the calling process,
so it cannot verify which application is calling it. Any check it made would sit in the caller's
own code, and a hostile program can skip the library and call the vault API directly. Only the
operating system can separate one application's secrets from another's.

The vault protects secrets against:

- plain-text configuration and data files that other tools, logs, and bug reports pick up
- backups and synced folders that copy application data
- other user accounts on the same machine
- an attacker who reads the disk of a powered-off or stolen machine

Each vault isolates applications differently when they run as the same user:

| Host | Isolation between applications of one user |
| --- | --- |
| Windows | None. Any process running as the user can read or list every Credential Manager entry. |
| Linux | None. Any process on the user's session bus can read items while the keyring is unlocked. Every read goes through `secret-tool`, so the Secret Service sees the same client for every application. |
| macOS, default | Partial. Each item carries an access list naming the application that created it, and another application triggers a prompt before it reads the item. A person can approve that prompt permanently. An application launched through the shared `dotnet` host is identified as `dotnet`, so every application run that way shares one identity. |
| macOS, `RequireApplicationIsolation` | Full. The data protection keychain files each item under the application's keychain access group, which carries the developer's Team ID. The operating system refuses every other application, with no prompt. |

On Windows and Linux, malicious code running as the same user can read every secret the user's
applications store. On macOS without `RequireApplicationIsolation`, the same code reads a secret
once a person approves the access prompt. That code can also read applications' memory and
keystrokes, so no storage design in a library closes the gap on its own.

## Application isolation on macOS

`RequireApplicationIsolation` selects `MacDataProtectionKeychainCredentialStore` on macOS. Set it in
release builds that ship as a signed application bundle, and leave it off for development builds
and local tools:

```csharp
services.AddSecureStore(options =>
{
    options.ServiceName = "com.example.app";
    options.Label = "Example";
#if !DEBUG
    options.RequireApplicationIsolation = true;
#endif
});
```

Windows Credential Manager and the Linux Secret Service have no isolation between applications of
one user, so the option has no effect on those hosts. One configuration serves every platform.

The data protection keychain accepts only a process with a keychain access group. The application
must ship as a `.app` bundle that carries:

- a Developer ID signature
- a provisioning profile at `Contents/embedded.provisionprofile`, issued for the application's App ID
- these entitlements, where `TEAMID` is the Apple Developer Team ID:

```xml
<key>com.apple.application-identifier</key>
<string>TEAMID.com.example.app</string>
<key>com.apple.developer.team-identifier</key>
<string>TEAMID</string>
<key>keychain-access-groups</key>
<array>
    <string>TEAMID.com.example.app</string>
</array>
```

A bare command-line executable cannot carry a provisioning profile, so it cannot use this backend.

The store checks access on its first call. A process without the entitlement gets a
`SecureStoreException` naming the missing entitlement on every call, reads included, so a release
with broken signing fails at the first secret. The check deletes an item under a service name
reserved for it and a random account name, so it cannot match a stored secret.

Items in the data protection keychain are stored `AfterFirstUnlockThisDeviceOnly`. Background work
can read them once the person has logged in since boot. They never sync to iCloud Keychain and
never restore onto another Mac. They are separate from the items the default macOS backend keeps in
the login keychain, so secrets saved by a development build do not appear in a release build.

## Backends

| Host | Backend | Requirement |
| --- | --- | --- |
| macOS | Login keychain, through the `SecItem` API | none |
| macOS, `RequireApplicationIsolation` | Data protection keychain, through the `SecItem` API | signed `.app` bundle with a keychain access group |
| Windows | Credential Manager | none |
| Linux | Secret Service, through `secret-tool` | `libsecret-tools` |

On Debian and Ubuntu, install the Linux requirement with `sudo apt install libsecret-tools`. The
Linux backend throws `PlatformNotSupportedException` with that instruction when the command is
absent.

Windows Credential Manager caps one credential blob at 2560 bytes. A secret over the cap is split
across numbered entries and rejoined on read, so the caller sees no limit.

## Hosts with no vault

A host that is not macOS, Windows, or Linux gets `SecureStoreOptions.Fallback`. The default throws
`PlatformNotSupportedException` on every operation, so an application that has not chosen a
fallback fails at the first secret instead of losing one quietly.

Keep secrets for the life of the process and write nothing to disk:

```csharp
options.Fallback = () => new InMemoryCredentialStore();
```

Keep secrets across restarts in one encrypted file:

```csharp
options.Fallback = () => new EncryptedFileCredentialStore(
    new AesGcmSecretProtector(key),
    Path.Combine(dataDirectory, "credentials"));
```

The host supplies the key. A host with no credential vault has no operating system secret to derive
a key from, and a key the library invented for itself would sit in the same file it protects. The
file store is weaker than a vault: the secrets are only as private as that key and the permissions
on the directory around the file. On Unix the store restricts the file to `0600` and its directory
to `0700`.

`AesGcmSecretProtector` takes a 16, 24, or 32 byte key. An application that already has a key
management story implements `ISecretProtector` instead.

## Testing

`InMemoryCredentialStore` implements `ICredentialStore` with no vault behind it. Use it in unit
tests of code that depends on `ICredentialStore`:

```csharp
var credentials = new InMemoryCredentialStore();
var session = new SessionService(credentials);

await session.SignInAsync("test-token");

Assert.Equal("test-token", await credentials.GetAsync("refresh-token"));
```

## Errors

| Situation | Result |
| --- | --- |
| Reading a name that holds no secret | returns `null` |
| Deleting a name that holds no secret | succeeds |
| Empty or whitespace name or secret | `ArgumentException` |
| Missing `ServiceName` | `InvalidOperationException` at registration |
| Vault failure, such as a locked keychain or denied access | `SecureStoreException` |
| Host with no vault and no fallback | `PlatformNotSupportedException` |
| macOS with `RequireApplicationIsolation` and no keychain access group | `SecureStoreException` on every call |
| Linux host without `secret-tool` | `PlatformNotSupportedException` |
