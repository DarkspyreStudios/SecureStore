using Microsoft.Extensions.DependencyInjection;
using SecureStore;

namespace SecureStore.Tests;

public sealed class SecureStoreOptionsTests
{
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ServiceNameIsRequired(string serviceName)
    {
        var services = new ServiceCollection();

        Assert.Throws<InvalidOperationException>(
            () => services.AddSecureStore(options => options.ServiceName = serviceName));
    }

    [Fact]
    public void LabelDefaultsToTheServiceName()
    {
        var options = new SecureStoreOptions { ServiceName = "com.example.app" };

        Assert.Equal("com.example.app", options.ResolvedLabel);
    }

    [Fact]
    public void LabelIsUsedWhenSet()
    {
        var options = new SecureStoreOptions { ServiceName = "com.example.app", Label = "Example" };

        Assert.Equal("Example", options.ResolvedLabel);
    }

    [Fact]
    public void StoreIsRegisteredAsASingleton()
    {
        var services = new ServiceCollection();
        services.AddSecureStore(options => options.ServiceName = "com.example.app");

        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Same(
            provider.GetRequiredService<ICredentialStore>(),
            provider.GetRequiredService<ICredentialStore>());
    }

    [Fact]
    public void ApplicationIsolationIsOffByDefault()
    {
        var options = new SecureStoreOptions { ServiceName = "com.example.app" };

        Assert.False(options.RequireApplicationIsolation);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FactorySelectsTheMacBackendForApplicationIsolation(bool requireApplicationIsolation)
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        var options = new SecureStoreOptions
        {
            ServiceName = "com.example.app",
            RequireApplicationIsolation = requireApplicationIsolation
        };

        ICredentialStore store = CredentialStoreFactory.Create(options);

        Type expected = requireApplicationIsolation
            ? typeof(MacDataProtectionKeychainCredentialStore)
            : typeof(MacKeychainCredentialStore);
        Assert.IsType(expected, store);
    }

    [Fact]
    public void ApplicationIsolationHasNoEffectOnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var options = new SecureStoreOptions { ServiceName = "com.example.app", RequireApplicationIsolation = true };

        Assert.IsType<WindowsCredentialManagerCredentialStore>(CredentialStoreFactory.Create(options));
    }

    [Fact]
    public void ApplicationIsolationHasNoEffectOnLinux()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var options = new SecureStoreOptions { ServiceName = "com.example.app", RequireApplicationIsolation = true };

        Assert.IsType<LinuxSecretServiceCredentialStore>(CredentialStoreFactory.Create(options));
    }

    [Fact]
    public async Task UnsupportedPlatformStoreExplainsTheOption()
    {
        var store = new UnsupportedPlatformCredentialStore();

        PlatformNotSupportedException exception = await Assert.ThrowsAsync<PlatformNotSupportedException>(
            async () => await store.GetAsync("token"));

        Assert.Contains(nameof(SecureStoreOptions.Fallback), exception.Message, StringComparison.Ordinal);
    }
}
