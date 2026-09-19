using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SecureStore.Internal;
using SecureStore.Internal.MacOS;

namespace SecureStore;

/// <summary>Stores secrets as generic password items in the macOS Keychain.</summary>
[SupportedOSPlatform("macos")]
public sealed class MacKeychainCredentialStore : ICredentialStore, IDisposable
{
    private readonly string _serviceName;
    private readonly string _label;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public MacKeychainCredentialStore(SecureStoreOptions options)
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
    /// Builds the three attributes that address one item: the generic password class, this
    /// application's service name, and the caller's name for the secret.
    /// </summary>
    private IntPtr BuildIdentityQuery(CoreFoundationScope scope, string account)
    {
        IntPtr query = scope.Dictionary(5);
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.ClassKey, SecurityFramework.GenericPasswordClass);
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.ServiceAttribute, scope.String(_serviceName));
        CoreFoundation.CFDictionarySetValue(query, SecurityFramework.AccountAttribute, scope.String(account));
        return query;
    }

    private static string Prepare(string name)
    {
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("MacKeychainCredentialStore requires macOS.");
        }

        return CredentialName.Normalize(name);
    }

    private static void ThrowIfFailed(int status, string operation)
    {
        if (status != SecurityFramework.Success)
        {
            throw new SecureStoreException(
                $"macOS Keychain could not {operation} the secret (status {status}).");
        }
    }
}
