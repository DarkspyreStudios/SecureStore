using Microsoft.Extensions.DependencyInjection;
using SecureStore;

namespace SecureStore.Tests;

public sealed class SecureStoreOptionsTests
{
    [Theory]
    [InlineData("")]
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
    public void StoreIsRegisteredAsASingleton()
    {
        var services = new ServiceCollection();
        services.AddSecureStore(options => options.ServiceName = "com.example.app");

        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Same(
            provider.GetRequiredService<ICredentialStore>(),
            provider.GetRequiredService<ICredentialStore>());
    }

    [Theory]
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

}
