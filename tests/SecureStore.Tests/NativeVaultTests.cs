using SecureStore;

namespace SecureStore.Tests;

/// <summary>
/// Exercises the real operating system vault. Each test runs only on its own platform and cleans
/// up the entries it makes. The service name belongs to the test suite, so nothing here can reach
/// a secret an application stored.
/// </summary>
public sealed class NativeVaultTests
{
    private static readonly SecureStoreOptions Options = new()
    {
        ServiceName = "com.darkspyrestudios.securestore.tests",
        Label = "SecureStore tests"
    };

    [Fact]
    public async Task MacKeychainRoundTrip()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        using var store = new MacKeychainCredentialStore(Options);
        await RunVaultContractAsync(store);
    }

    [Fact]
    public async Task WindowsCredentialManagerRoundTrip()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var store = new WindowsCredentialManagerCredentialStore(Options);
        await RunVaultContractAsync(store);
    }

    /// <summary>
    /// An OAuth bundle carrying an access token, a refresh token, and an identity token runs past
    /// the 2560 byte Windows credential limit. It must store whole on every platform.
    /// </summary>
    [Fact]
    public async Task OversizedSecretRoundTripsOnTheNativeVault()
    {
        ICredentialStore? store = CreateNativeStore();
        if (store is null)
        {
            return;
        }

        string name = "oversized-" + Guid.NewGuid().ToString("N");
        string secret = string.Concat(Enumerable.Repeat("eyJhbGciOiJIUzI1NiJ9.payload.signature ", 400));
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(secret) > 2560);

        try
        {
            await store.SetAsync(name, secret);
            Assert.Equal(secret, await store.GetAsync(name));

            // Shrinking back under the limit must not leave pieces of the larger secret behind.
            await store.SetAsync(name, "small");
            Assert.Equal("small", await store.GetAsync(name));
        }
        finally
        {
            await store.DeleteAsync(name);
            (store as IDisposable)?.Dispose();
        }
    }

    private static ICredentialStore? CreateNativeStore()
    {
        if (OperatingSystem.IsMacOS())
        {
            return new MacKeychainCredentialStore(Options);
        }

        return OperatingSystem.IsWindows()
            ? new WindowsCredentialManagerCredentialStore(Options)
            : null;
    }

    private static async Task RunVaultContractAsync(ICredentialStore store)
    {
        string name = "test-" + Guid.NewGuid().ToString("N");
        try
        {
            Assert.Null(await store.GetAsync(name));

            await store.SetAsync(name, "first");
            Assert.Equal("first", await store.GetAsync(name));

            await store.SetAsync(name, "second");
            Assert.Equal("second", await store.GetAsync(name));

            await store.SetAsync(name, "秘密\U0001F510");
            Assert.Equal("秘密\U0001F510", await store.GetAsync(name));

            await store.DeleteAsync(name);
            Assert.Null(await store.GetAsync(name));

            await store.DeleteAsync(name);
        }
        finally
        {
            await store.DeleteAsync(name);
        }
    }
}
