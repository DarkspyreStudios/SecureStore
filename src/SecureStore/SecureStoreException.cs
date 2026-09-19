namespace SecureStore;

/// <summary>Reports a failure from the underlying credential vault.</summary>
public sealed class SecureStoreException : Exception
{
    public SecureStoreException()
    {
    }

    public SecureStoreException(string message)
        : base(message)
    {
    }

    public SecureStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
