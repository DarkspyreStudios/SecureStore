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
    [InlineData(6144)]
    public void SplitAndJoinReturnTheOriginalSecret(int length)
    {
        string secret = new('x', length);
        byte[] bytes = Encoding.UTF8.GetBytes(secret);

        IReadOnlyList<string> pieces = ChunkedSecret.Split(bytes);

        Assert.All(pieces, piece => Assert.True(Encoding.UTF8.GetByteCount(piece) <= ChunkedSecret.MaximumBlobBytes));
        Assert.Equal(secret, ChunkedSecret.Join(pieces));
    }

}
