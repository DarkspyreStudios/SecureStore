using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Foundation;
using Security;
using SecureStore.Internal;

namespace SecureStore;

/// <summary>Stores named secrets in the calling iOS application's device-only Keychain.</summary>
/// <gotcha>Items remain available after the first device unlock and never synchronize through iCloud.</gotcha>
[SupportedOSPlatform("ios17.0")]
public sealed class IosKeychainCredentialStore : ICredentialStore, IDisposable
{
    private readonly string serviceName;
    private readonly string label;
    private readonly SemaphoreSlim gate = new(1, 1);

    /// <summary>Creates the backend with the application's stable, explicit service identity.</summary>
    public IosKeychainCredentialStore(SecureStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        serviceName = options.ServiceName;
        label = options.ResolvedLabel;
    }

    /// <inheritdoc />
    public async ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        string account = CredentialName.Normalize(name);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var query = Identity(account);
            using NSData? data = SecKeyChain.QueryAsData(query, false, out SecStatusCode status);
            if (status == SecStatusCode.ItemNotFound) return null;
            ThrowIfFailed(status, "read");
            if (data is null) throw new SecureStoreException("The iOS Keychain returned no secret data.");
            byte[] bytes = data.ToArray();
            try { return Encoding.UTF8.GetString(bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        finally { gate.Release(); }
    }

    /// <inheritdoc />
    public async ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default)
    {
        string account = CredentialName.Normalize(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes(secret);
            try
            {
                using NSData data = NSData.FromArray(bytes);
                using var query = Identity(account);
                using var update = new SecRecord { ValueData = data };
                SecStatusCode status = SecKeyChain.Update(query, update);
                if (status != SecStatusCode.ItemNotFound)
                {
                    ThrowIfFailed(status, "update");
                    return;
                }

                using var item = Identity(account);
                item.ValueData = data;
                item.Label = label;
                item.Accessible = SecAccessible.AfterFirstUnlockThisDeviceOnly;
                ThrowIfFailed(SecKeyChain.Add(item), "save");
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        finally { gate.Release(); }
    }

    /// <inheritdoc />
    public async ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        string account = CredentialName.Normalize(name);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var query = Identity(account);
            SecStatusCode status = SecKeyChain.Remove(query);
            if (status != SecStatusCode.ItemNotFound) ThrowIfFailed(status, "delete");
        }
        finally { gate.Release(); }
    }

    /// <summary>Releases the lock that serializes access to the credential backend.</summary>
    public void Dispose() => gate.Dispose();

    private SecRecord Identity(string account) => new(SecKind.GenericPassword)
    {
        Service = serviceName,
        Account = account,
        Synchronizable = false,
    };

    private static void ThrowIfFailed(SecStatusCode status, string operation)
    {
        if (status != SecStatusCode.Success)
            throw new SecureStoreException($"The iOS Keychain could not {operation} the secret (status {(int)status}).");
    }
}
