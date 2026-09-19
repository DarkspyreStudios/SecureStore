namespace SecureStore;

/// <summary>
/// Secure storage for a named secret. A desktop host backs this with the operating system
/// credential vault: Keychain on macOS, Credential Manager on Windows, the Secret Service API on
/// Linux. A server host that keeps secrets outside a database uses the same interface.
/// </summary>
/// <remarks>Implementations must never log a secret value.</remarks>
public interface ICredentialStore
{
    /// <summary>Reads a secret. Returns null when no secret is stored under <paramref name="name"/>.</summary>
    ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Writes a secret, replacing any value already stored under <paramref name="name"/>.</summary>
    ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default);

    /// <summary>Removes a secret. Succeeds when no secret is stored under <paramref name="name"/>.</summary>
    ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default);
}
