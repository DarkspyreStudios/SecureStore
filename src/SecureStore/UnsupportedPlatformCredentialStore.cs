namespace SecureStore;

/// <summary>
/// The default store on a host with no credential vault. Every operation throws, so an application
/// that has not chosen a fallback fails at the first secret instead of losing one quietly.
/// </summary>
public sealed class UnsupportedPlatformCredentialStore : ICredentialStore
{
    private const string Explanation =
        "SecureStore supports macOS Keychain, Windows Credential Manager, and the Linux Secret Service. "
        + "Set SecureStoreOptions.Fallback to choose what this host uses instead.";

    /// <inheritdoc />
    public ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default) =>
        throw new PlatformNotSupportedException(Explanation);

    /// <inheritdoc />
    public ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default) =>
        throw new PlatformNotSupportedException(Explanation);

    /// <inheritdoc />
    public ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default) =>
        throw new PlatformNotSupportedException(Explanation);
}
