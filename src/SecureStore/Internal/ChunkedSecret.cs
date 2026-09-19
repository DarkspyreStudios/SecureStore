using System.Globalization;
using System.Text;

namespace SecureStore.Internal;

/// <summary>
/// Splits a secret that exceeds the Windows credential blob limit and rejoins it on read. The
/// pieces are base64, because slicing raw UTF-8 at a fixed byte count would cut a character in
/// half.
/// </summary>
internal static class ChunkedSecret
{
    /// <summary>CRED_MAX_CREDENTIAL_BLOB_SIZE.</summary>
    internal const int MaximumBlobBytes = 2560;

    /// <summary>
    /// Marks a primary entry that holds a piece count in place of a secret. It opens with a NUL,
    /// which no UTF-8 secret can begin with.
    /// </summary>
    private const string HeaderPrefix = "\0SecureStore.Chunked.v1:";

    internal static bool IsHeader(string value) =>
        value.StartsWith(HeaderPrefix, StringComparison.Ordinal);

    internal static string Header(int count) =>
        HeaderPrefix + count.ToString(CultureInfo.InvariantCulture);

    /// <summary>Reads the piece count out of a primary entry.</summary>
    internal static int ReadCount(string header)
    {
        string text = header[HeaderPrefix.Length..];
        if (int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int count) && count > 0)
        {
            return count;
        }

        throw new SecureStoreException("A secret is stored in pieces and its header is unreadable.");
    }

    /// <summary>Returns true when the secret fits one entry and needs no splitting.</summary>
    internal static bool Fits(byte[] secretBytes) => secretBytes.Length <= MaximumBlobBytes;

    /// <summary>Splits a secret into base64 pieces, each within the blob limit.</summary>
    internal static IReadOnlyList<string> Split(byte[] secretBytes)
    {
        string encoded = Convert.ToBase64String(secretBytes);
        int count = (encoded.Length + MaximumBlobBytes - 1) / MaximumBlobBytes;
        var pieces = new List<string>(count);
        for (int index = 0; index < count; index++)
        {
            int offset = index * MaximumBlobBytes;
            pieces.Add(encoded.Substring(offset, Math.Min(MaximumBlobBytes, encoded.Length - offset)));
        }

        return pieces;
    }

    /// <summary>Rejoins the pieces into the original secret.</summary>
    internal static string Join(IReadOnlyList<string> pieces)
    {
        var builder = new StringBuilder();
        foreach (string piece in pieces)
        {
            builder.Append(piece);
        }

        byte[] secretBytes;
        try
        {
            secretBytes = Convert.FromBase64String(builder.ToString());
        }
        catch (FormatException exception)
        {
            throw new SecureStoreException("A secret stored in pieces could not be reassembled.", exception);
        }

        return Encoding.UTF8.GetString(secretBytes);
    }
}
