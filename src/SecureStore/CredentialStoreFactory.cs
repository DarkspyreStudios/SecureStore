namespace SecureStore;

/// <summary>Chooses the credential vault the current operating system provides.</summary>
public static class CredentialStoreFactory
{
    /// <summary>
    /// Builds the store for this host. A host that is not macOS, Windows, or Linux gets
    /// <see cref="SecureStoreOptions.Fallback"/>, and <see cref="UnsupportedPlatformCredentialStore"/>
    /// when the application has not set one.
    /// </summary>
    public static ICredentialStore Create(SecureStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        if (OperatingSystem.IsMacOS())
        {
            return new MacKeychainCredentialStore(options);
        }

        if (OperatingSystem.IsWindows())
        {
            return new WindowsCredentialManagerCredentialStore(options);
        }

        if (OperatingSystem.IsLinux())
        {
            return new LinuxSecretServiceCredentialStore(options);
        }

        return options.Fallback?.Invoke() ?? new UnsupportedPlatformCredentialStore();
    }
}
