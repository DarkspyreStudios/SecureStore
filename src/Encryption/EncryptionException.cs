namespace Darkspyre.Encryption;

/// <summary>Why an encryption operation failed. Each value maps to one stable, key-free message.</summary>
public enum EncryptionFailure
{
    /// <summary>The data is encrypted and no key was supplied.</summary>
    KeyRequired,

    /// <summary>A key was supplied and it does not open the data.</summary>
    KeyRejected,

    /// <summary>The data failed authentication: it was altered, truncated, or moved from another name or store.</summary>
    Tampered,

    /// <summary>The data is not in a format this library reads.</summary>
    UnsupportedFormat,

    /// <summary>The data exceeds the size this library encrypts in one piece.</summary>
    TooLarge,

    /// <summary>The SQLCipher library is not loaded, or another SQLite build is serving connections.</summary>
    SqlCipherUnavailable,

    /// <summary>A database conversion produced a copy whose content does not match its source.</summary>
    ConversionMismatch,
}

/// <summary>
/// An encryption operation failed. The message names the failure and the store, never key material or plaintext.
/// </summary>
public sealed class EncryptionException : Exception
{
    /// <summary>Creates the exception for one failure.</summary>
    public EncryptionException(EncryptionFailure failure, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Failure = failure;
    }

    /// <summary>Why the operation failed.</summary>
    public EncryptionFailure Failure { get; }
}
