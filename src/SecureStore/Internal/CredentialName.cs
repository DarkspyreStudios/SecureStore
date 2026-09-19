namespace SecureStore.Internal;

/// <summary>Normalizes the name a caller uses to address a secret.</summary>
internal static class CredentialName
{
    /// <summary>Validates a secret name and trims the surrounding whitespace the vaults ignore.</summary>
    internal static string Normalize(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return name.Trim();
    }
}
