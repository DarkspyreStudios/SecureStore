using Microsoft.Extensions.DependencyInjection;

namespace SecureStore;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="ICredentialStore"/> as a singleton backed by this host's credential
    /// vault. The application must set <see cref="SecureStoreOptions.ServiceName"/> and must keep
    /// that value stable, because it addresses every secret already stored.
    /// </summary>
    public static IServiceCollection AddSecureStore(
        this IServiceCollection services,
        Action<SecureStoreOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new SecureStoreOptions();
        configure(options);
        options.Validate();

        services.AddSingleton<ICredentialStore>(_ => CredentialStoreFactory.Create(options));
        return services;
    }
}
