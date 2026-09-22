# SecureStore

> **Proprietary software.** Copyright © 2026 Brandon Mathis. All rights reserved.
> No permission is granted to use, copy, modify, or distribute this software
> without prior written authorization. See [LICENSE.md](LICENSE.md).

One interface over the operating system credential vault: macOS Keychain, Windows Credential
Manager, and the Linux Secret Service. A desktop application keeps refresh tokens and API
credentials out of its own files. A server application that keeps secrets outside its database uses
the same interface.

## Install

```
dotnet add package Darkspyre.SecureStore
```

## Use

```csharp
services.AddSecureStore(options =>
{
    options.ServiceName = "com.example.app";
    options.Label = "Example";
});
```

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
host. `CredentialStoreFactory.Create(options)` does the same for an application with no service
container.

## ServiceName

`ServiceName` identifies the application inside the vault. It is the service attribute on macOS and
Linux, and the target prefix on Windows. Every application must set its own value and must keep
that value stable across releases. Changing it hides every secret stored under the previous value.

`Label` is the name a person sees when browsing the vault. It defaults to `ServiceName`.

## Backends

| Host | Backend | Requirement |
| --- | --- | --- |
| macOS | Keychain, through the `SecItem` API | none |
| Windows | Credential Manager | none |
| Linux | Secret Service, through `secret-tool` | `libsecret-tools` |

On Debian and Ubuntu, install the Linux requirement with `sudo apt install libsecret-tools`. The
Linux backend throws `PlatformNotSupportedException` with that instruction when the command is
absent.

Windows Credential Manager caps one credential blob at 2560 bytes. An OAuth bundle carrying an
access token, a refresh token, and an identity token exceeds that. A secret over the cap is split
across numbered entries and rejoined on read, so the same value stores on every platform and the
caller sees no limit.

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

## Errors

A backend failure throws `SecureStoreException`. Reading a name that holds no secret returns `null`,
and deleting one succeeds.
