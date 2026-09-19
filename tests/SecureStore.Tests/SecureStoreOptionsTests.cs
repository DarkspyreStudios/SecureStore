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
    public async Task UnsupportedPlatformStoreExplainsTheOption()
    {
        var store = new UnsupportedPlatformCredentialStore();

        PlatformNotSupportedException exception = await Assert.ThrowsAsync<PlatformNotSupportedException>(
            async () => await store.GetAsync("token"));

        Assert.Contains(nameof(SecureStoreOptions.Fallback), exception.Message, StringComparison.Ordinal);
    }
}
