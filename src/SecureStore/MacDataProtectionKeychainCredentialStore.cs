using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SecureStore.Internal;
using SecureStore.Internal.MacOS;

namespace SecureStore;

/// <summary>
/// Stores secrets as generic password items in the macOS data protection keychain. The operating
/// system files each item under the calling application's default keychain access group and refuses
/// every application outside that group, with no prompt a person can approve.
/// </summary>
/// <remarks>
/// The calling process must be a signed application bundle with a <c>keychain-access-groups</c>
/// entitlement and an embedded provisioning profile. Every call from a process without that
/// entitlement throws <see cref="SecureStoreException"/>, reads included. Items never sync to
/// iCloud Keychain and never restore onto another Mac. They are separate from the items
/// <see cref="MacKeychainCredentialStore"/> keeps in the file-based login keychain.
/// </remarks>
[SupportedOSPlatform("macos")]
public sealed class MacDataProtectionKeychainCredentialStore : ICredentialStore, IDisposable
{
    private const string ProbeServiceSuffix = ".securestore-access-probe";

    private readonly string _serviceName;
    private readonly string _label;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _accessVerified;

    public MacDataProtectionKeychainCredentialStore(SecureStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _serviceName = options.ServiceName;
        _label = options.ResolvedLabel;
    }

    public async ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        string account = Prepare(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureAccess();
            using var scope = new CoreFoundationScope();
            IntPtr query = BuildIdentityQuery(scope, account);
            CoreFoundation.CFDictionarySetValue(query, SecurityFramework.ReturnData, CoreFoundation.True);
            CoreFoundation.CFDictionarySetValue(query, SecurityFramework.MatchLimit, SecurityFramework.MatchLimitOne);

            int status = SecurityFramework.SecItemCopyMatching(query, out IntPtr result);
            if (status == SecurityFramework.ItemNotFound)
            {
                return null;
            }

            ThrowIfFailed(status, "read");
            try
            {
                byte[] secretBytes = CoreFoundation.ReadData(result);
                try
                {
                    return Encoding.UTF8.GetString(secretBytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(secretBytes);
                }
            }
            finally
            {
                CoreFoundation.Release(result);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default)
    {
        string account = Prepare(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureAccess();
            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
            try
            {
                using var scope = new CoreFoundationScope();
                IntPtr query = BuildIdentityQuery(scope, account);
                IntPtr update = scope.Dictionary(1);
                CoreFoundation.CFDictionarySetValue(update, SecurityFramework.ValueData, scope.Data(secretBytes));

                int status = SecurityFramework.SecItemUpdate(query, update);
                if (status != SecurityFramework.ItemNotFound)
                {
                    ThrowIfFailed(status, "update");
                    return;
                }

                IntPtr attributes = BuildIdentityQuery(scope, account);
                CoreFoundation.CFDictionarySetValue(attributes, SecurityFramework.ValueData, scope.Data(secretBytes));
                CoreFoundation.CFDictionarySetValue(attributes, SecurityFramework.LabelAttribute, scope.String(_label));
                CoreFoundation.CFDictionarySetValue(
                    attributes,
                    SecurityFramework.AccessibleAttribute,
                    SecurityFramework.AccessibleAfterFirstUnlockThisDeviceOnly);
                ThrowIfFailed(SecurityFramework.SecItemAdd(attributes, IntPtr.Zero), "save");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secretBytes);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        string account = Prepare(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureAccess();
            using var scope = new CoreFoundationScope();
            int status = SecurityFramework.SecItemDelete(BuildIdentityQuery(scope, account));
            if (status != SecurityFramework.ItemNotFound)
            {
                ThrowIfFailed(status, "delete");
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    /// <summary>
    /// Confirms once per instance that the keychain accepts this process. Without a keychain access
    /// group, the data protection keychain answers a read as though the item were absent, and only
    /// a write or delete reports the missing entitlement. The probe deletes an item addressed by a
    /// service name reserved for the probe and a fresh random account. No secret can match that
    /// query: <see cref="SetAsync"/> stores every secret under the plain service name. An entitled
    /// process receives item-not-found; a process without the entitlement receives the error that
    /// every later call would hit.
    /// </summary>
    private void EnsureAccess()
    {
        if (_accessVerified)
        {
            return;
        }

        using var scope = new CoreFoundationScope();
        IntPtr query = scope.Dictionary(4);
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.ClassKey, SecurityFramework.GenericPasswordClass);
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.ServiceAttribute, scope.String(_serviceName + ProbeServiceSuffix));
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.AccountAttribute, scope.String(Guid.NewGuid().ToString("N")));
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.UseDataProtectionKeychain, CoreFoundation.True);

        int status = SecurityFramework.SecItemDelete(query);
        if (status != SecurityFramework.ItemNotFound)
        {
            ThrowIfFailed(status, "reach");
        }

        _accessVerified = true;
    }

    /// <summary>
    /// Builds the attributes that address one item: the generic password class, this application's
    /// service name, the caller's name for the secret, and the flag that routes the query to the
    /// data protection keychain. The query names no access group, so the operating system uses the
    /// application's default group.
    /// </summary>
    private IntPtr BuildIdentityQuery(CoreFoundationScope scope, string account)
    {
        IntPtr query = scope.Dictionary(7);
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.ClassKey, SecurityFramework.GenericPasswordClass);
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.ServiceAttribute, scope.String(_serviceName));
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.AccountAttribute, scope.String(account));
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.UseDataProtectionKeychain, CoreFoundation.True);
        return query;
    }

    private static string Prepare(string name)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("MacDataProtectionKeychainCredentialStore requires macOS.");
        }

        return CredentialName.Normalize(name);
    }

    private static void ThrowIfFailed(int status, string operation)
    {
        if (status == SecurityFramework.MissingEntitlement)
        {
            throw new SecureStoreException(
                $"macOS Keychain could not {operation} the keychain because this process has no keychain access group (status {status}). "
                + "The data protection keychain requires a signed application bundle with a keychain-access-groups entitlement and an embedded provisioning profile. "
                + $"Leave {nameof(SecureStoreOptions)}.{nameof(SecureStoreOptions.RequireApplicationIsolation)} off for unsigned development builds.");
        }

        if (status != SecurityFramework.Success)
        {
            throw new SecureStoreException(
                $"macOS Keychain could not {operation} the secret (status {status}).");
        }
    }
}
