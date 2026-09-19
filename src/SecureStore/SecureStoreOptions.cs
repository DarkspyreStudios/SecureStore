namespace SecureStore;

/// <summary>Identifies the calling application inside the operating system credential vault.</summary>
public sealed class SecureStoreOptions
{
    /// <summary>
    /// The vault-wide identity of the calling application, such as <c>com.example.app</c>. It is the
    /// service attribute on macOS and Linux, and the target prefix on Windows. Every application
    /// must set its own value and must keep that value stable across releases, because changing it
    /// hides every secret already stored under the previous value.
    /// </summary>
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>
    /// The application name a person sees when browsing the vault. It defaults to
    /// <see cref="ServiceName"/>.
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// Builds the store used on a host with no credential vault. The default throws
    /// <see cref="PlatformNotSupportedException"/> on every operation. A host that prefers to keep
    /// secrets in memory for the life of the process assigns
    /// <see cref="InMemoryCredentialStore"/>, and a host that needs them to survive a restart
    /// assigns <see cref="EncryptedFileCredentialStore"/>.
    /// </summary>
    public Func<ICredentialStore>? Fallback { get; set; }

    internal string ResolvedLabel =>
        string.IsNullOrWhiteSpace(Label) ? ServiceName : Label;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(ServiceName))
        {
            throw new InvalidOperationException(
                $"{nameof(SecureStoreOptions)}.{nameof(ServiceName)} is required. Set it to a stable identifier for this application, such as com.example.app.");
        }
    }
}
