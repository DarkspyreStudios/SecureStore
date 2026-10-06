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
    public void StoreKeysDifferByStoreIdKindAndApplication()
    {
        using VaultKey key = VaultKey.FromBytes(KnownRoot);
        string[] keys =
        [
            Hex(key.DeriveStoreKey("agent-ds", StoreKind.Database, "sessions")),
            Hex(key.DeriveStoreKey("agent-ds", StoreKind.Database, "memory.catalog")),
            Hex(key.DeriveStoreKey("agent-ds", StoreKind.Asset, "sessions")),
            Hex(key.DeriveStoreKey("tickets", StoreKind.Database, "sessions")),
        ];
        Assert.Equal(keys.Length, keys.Distinct().Count());
    }

    [Fact]
    public void DisposedKeysRefuseUse()
    {
        VaultKey key = VaultKey.Generate();
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.DeriveStoreKey("agent-ds", StoreKind.Asset, "settings"));
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

    [Fact]
    public void AlteredEnvelopeFailsAuthentication()
    {
        using StoreKey key = Derive("settings");
        byte[] sealedData = Envelope.Seal(key, "settings.json", "secret settings"u8);
        sealedData[^20] ^= 0x01;
        Assert.Equal(EncryptionFailure.Tampered, Assert.Throws<EncryptionException>(() => Envelope.Open(key, "settings.json", sealedData)).Failure);
    }

    [Fact]
    public void EnvelopeMovedToAnotherNameFailsAuthentication()
    {
        using StoreKey key = Derive("settings");
        byte[] sealedData = Envelope.Seal(key, "projects/a.json", "project a"u8);
        Assert.Equal(EncryptionFailure.Tampered, Assert.Throws<EncryptionException>(() => Envelope.Open(key, "projects/b.json", sealedData)).Failure);
    }

    [Fact]
    public void EnvelopeFromAnotherStoreIsRefused()
    {
        using StoreKey settings = Derive("settings");
        using StoreKey assets = Derive("assets");
        byte[] sealedData = Envelope.Seal(settings, "settings.json", "value"u8);
        Assert.Equal(EncryptionFailure.Tampered, Assert.Throws<EncryptionException>(() => Envelope.Open(assets, "settings.json", sealedData)).Failure);
    }

    [Fact]
    public void EnvelopeUnderAnotherRootFailsAuthentication()
    {
        using StoreKey key = Derive("settings");
        using VaultKey other = VaultKey.Generate();
        using StoreKey otherKey = other.DeriveStoreKey("agent-ds", StoreKind.Asset, "settings");
        byte[] sealedData = Envelope.Seal(key, "settings.json", "value"u8);
        Assert.Equal(EncryptionFailure.Tampered, Assert.Throws<EncryptionException>(() => Envelope.Open(otherKey, "settings.json", sealedData)).Failure);
    }

    [Fact]
    public void EnvelopeUnderAnotherKeyVersionIsRejected()
    {
        using VaultKey version1 = VaultKey.FromBytes(KnownRoot, keyVersion: 1);
        using VaultKey version2 = VaultKey.FromBytes(KnownRoot, keyVersion: 2);
        using StoreKey key1 = version1.DeriveStoreKey("agent-ds", StoreKind.Asset, "settings");
        using StoreKey key2 = version2.DeriveStoreKey("agent-ds", StoreKind.Asset, "settings");
        byte[] sealedData = Envelope.Seal(key1, "settings.json", "value"u8);
        Assert.Equal(EncryptionFailure.KeyRejected, Assert.Throws<EncryptionException>(() => Envelope.Open(key2, "settings.json", sealedData)).Failure);
    }

    [Fact]
    public void PlainFileIsNotAnEnvelope()
    {
        using StoreKey key = Derive("settings");
        byte[] plain = "{\"theme\":\"night\"}"u8.ToArray();
        Assert.False(Envelope.IsSealed(plain));
        Assert.Equal(EncryptionFailure.UnsupportedFormat, Assert.Throws<EncryptionException>(() => Envelope.Open(key, "settings.json", plain)).Failure);
    }

    [Fact]
    public void FailureMessagesCarryNoKeyMaterial()
    {
        using VaultKey root = VaultKey.FromBytes(KnownRoot);
        using StoreKey key = root.DeriveStoreKey("agent-ds", StoreKind.Asset, "settings");
        byte[] bytes = new byte[StoreKey.Length];
        key.CopyTo(bytes);
        byte[] sealedData = Envelope.Seal(key, "settings.json", "value"u8);
        sealedData[^1] ^= 0x01;
        EncryptionException error = Assert.Throws<EncryptionException>(() => Envelope.Open(key, "settings.json", sealedData));
        Assert.DoesNotContain(Convert.ToHexString(bytes), error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Convert.ToBase64String(bytes), error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToHexString(KnownRoot), error.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static StoreKey Derive(string storeId)
    {
        using VaultKey key = VaultKey.FromBytes(KnownRoot);
        return key.DeriveStoreKey("agent-ds", StoreKind.Asset, storeId);
    }

    private static string Hex(StoreKey key)
    {
        using (key)
        {
            byte[] bytes = new byte[StoreKey.Length];
            key.CopyTo(bytes);
            return Convert.ToHexString(bytes);
        }
    }
}
