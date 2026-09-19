using System.Text;
using SecureStore;
using SecureStore.Internal;

namespace SecureStore.Tests;

/// <summary>
/// The splitting only runs on Windows, where Credential Manager caps a blob at 2560 bytes. The
/// logic is tested here on every platform, because a mistake in it corrupts a secret silently.
/// </summary>
public sealed class ChunkedSecretTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2559)]
    [InlineData(2560)]
    public void SecretWithinTheBlobLimitIsNotSplit(int length)
    {
        Assert.True(ChunkedSecret.Fits(new byte[length]));
    }

    [Fact]
    public void SecretOverTheBlobLimitIsSplit()
    {
        Assert.False(ChunkedSecret.Fits(new byte[2561]));
    }

    [Theory]
    [InlineData(2561)]
    [InlineData(6144)]
    [InlineData(65536)]
    public void SplitAndJoinReturnTheOriginalSecret(int length)
    {
        string secret = new('x', length);
        byte[] bytes = Encoding.UTF8.GetBytes(secret);

        IReadOnlyList<string> pieces = ChunkedSecret.Split(bytes);

        Assert.All(pieces, piece => Assert.True(Encoding.UTF8.GetByteCount(piece) <= ChunkedSecret.MaximumBlobBytes));
        Assert.Equal(secret, ChunkedSecret.Join(pieces));
    }

    /// <summary>
    /// The pieces are base64, so they are safe to cut at a fixed byte count. Slicing the UTF-8
    /// bytes directly would split a multi-byte character across two entries.
    /// </summary>
    [Fact]
    public void MultiByteCharactersSurviveSplitting()
    {
        string secret = string.Concat(Enumerable.Repeat("秘密é\U0001F510", 2000));
        byte[] bytes = Encoding.UTF8.GetBytes(secret);
        Assert.False(ChunkedSecret.Fits(bytes));

        Assert.Equal(secret, ChunkedSecret.Join(ChunkedSecret.Split(bytes)));
    }

    [Fact]
    public void HeaderCarriesThePieceCount()
    {
        string header = ChunkedSecret.Header(7);

        Assert.True(ChunkedSecret.IsHeader(header));
        Assert.Equal(7, ChunkedSecret.ReadCount(header));
    }

    [Theory]
    [InlineData("{\"accessToken\":\"abc\"}")]
    [InlineData("plain secret")]
    [InlineData("")]
    public void OrdinarySecretIsNotMistakenForAHeader(string secret)
    {
        Assert.False(ChunkedSecret.IsHeader(secret));
    }

    [Theory]
    [InlineData("\0SecureStore.Chunked.v1:0")]
    [InlineData("\0SecureStore.Chunked.v1:-2")]
    [InlineData("\0SecureStore.Chunked.v1:many")]
    [InlineData("\0SecureStore.Chunked.v1:")]
    public void UnreadableHeaderIsReported(string header)
    {
        Assert.Throws<SecureStoreException>(() => ChunkedSecret.ReadCount(header));
    }

    [Fact]
    public void PiecesThatAreNotBase64AreReported()
    {
        Assert.Throws<SecureStoreException>(() => ChunkedSecret.Join(["not base64 at all"]));
    }
}
