using SecureStore.Internal;

namespace SecureStore;

/// <summary>
/// Keeps secrets for the life of the process and writes nothing to disk. A host that lands here
/// asks the person to authenticate again on the next launch.
/// </summary>
public sealed class InMemoryCredentialStore : ICredentialStore
{
    private readonly Dictionary<string, string> _secrets = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        string key = CredentialName.Normalize(name);
        lock (_gate)
        {
            return ValueTask.FromResult(_secrets.TryGetValue(key, out string? secret) ? secret : null);
        }
    }

    /// <inheritdoc />
    public ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default)
    {
        string key = CredentialName.Normalize(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        lock (_gate)
        {
            _secrets[key] = secret;
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        string key = CredentialName.Normalize(name);
        lock (_gate)
        {
            _secrets.Remove(key);
        }

        return ValueTask.CompletedTask;
    }
}
