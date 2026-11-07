using System.Text;
using Darkspyre.Encryption;

namespace Encryption.Tests;

public sealed class KeyAndEnvelopeTests
{
    private static readonly byte[] KnownRoot = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    [Fact]
    public void FingerprintMatchesTheKnownVector()
    {
        using VaultKey key = VaultKey.FromBytes(KnownRoot);
        Assert.Equal("893cb0976b004c1e382884b06b6ca808a4dd1c07ece507f6b3b6d482785c9eac", key.Fingerprint);
        Assert.Equal(key.Fingerprint, VaultKey.ComputeFingerprint(KnownRoot));
    }

    [Fact]
    public void StoreKeyMatchesTheKnownHkdfVector()
    {
        using VaultKey key = VaultKey.FromBytes(KnownRoot);
        using StoreKey store = key.DeriveStoreKey("agent-ds", StoreKind.Database, "sessions");
        byte[] bytes = new byte[StoreKey.Length];
        store.CopyTo(bytes);
        Assert.Equal("e86f23d6a8a6e51bdbf0eab0900a7dec7e97e2a2fadcf5457e676cc49e8b80e7", Convert.ToHexStringLower(bytes));
    }

    [Fact]
    public void EnvelopeRoundTrips()
    {
        using StoreKey key = Derive("settings");
        byte[] plaintext = Encoding.UTF8.GetBytes("{\"theme\":\"night\"}");
        byte[] sealedData = Envelope.Seal(key, "settings.json", plaintext);
        Assert.True(Envelope.IsSealed(sealedData));
        Assert.Equal(-1, sealedData.AsSpan().IndexOf("night"u8));
        Assert.Equal(plaintext, Envelope.Open(key, "settings.json", sealedData));
        Assert.NotEqual(sealedData, Envelope.Seal(key, "settings.json", plaintext));
    }

    private static StoreKey Derive(string storeId)
    {
        using VaultKey key = VaultKey.FromBytes(KnownRoot);
        return key.DeriveStoreKey("agent-ds", StoreKind.Asset, storeId);
    }

}
