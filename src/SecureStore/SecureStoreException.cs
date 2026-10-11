namespace SecureStore;

/// <summary>Reports a failure from the underlying credential vault.</summary>
public sealed class SecureStoreException : Exception
{
    /// <summary>Creates the exception with the default message.</summary>
    public SecureStoreException()
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    public SecureStoreException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and the exception that caused it.</summary>
    public SecureStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
