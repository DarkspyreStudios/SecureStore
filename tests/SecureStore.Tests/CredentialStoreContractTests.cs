using SecureStore;

namespace SecureStore.Tests;

/// <summary>
/// The behaviour every store must show, whatever it stores secrets in. Each implementation runs
/// the whole set.
/// </summary>
public abstract class CredentialStoreContractTests
{
    protected abstract ICredentialStore CreateStore();

    [Fact]
    public async Task ReadingAnAbsentSecretReturnsNull()
    {
        ICredentialStore store = CreateStore();

        Assert.Null(await store.GetAsync("missing"));
    }

    [Fact]
    public async Task SecretReadsBackAsWritten()
    {
        ICredentialStore store = CreateStore();

        await store.SetAsync("token", "s3cr3t");

        Assert.Equal("s3cr3t", await store.GetAsync("token"));
    }

    [Fact]
    public async Task WritingTwiceReplacesTheSecret()
    {
        ICredentialStore store = CreateStore();

        await store.SetAsync("token", "first");
        await store.SetAsync("token", "second");

        Assert.Equal("second", await store.GetAsync("token"));
    }

    [Fact]
    public async Task DeletedSecretIsGone()
    {
        ICredentialStore store = CreateStore();
        await store.SetAsync("token", "s3cr3t");

        await store.DeleteAsync("token");

        Assert.Null(await store.GetAsync("token"));
    }

    [Fact]
    public async Task DeletingAnAbsentSecretSucceeds()
    {
        ICredentialStore store = CreateStore();

        await store.DeleteAsync("missing");
    }

    [Fact]
    public async Task SecretsAreKeptApartByName()
    {
        ICredentialStore store = CreateStore();

        await store.SetAsync("one", "first");
        await store.SetAsync("two", "second");

        Assert.Equal("first", await store.GetAsync("one"));
        Assert.Equal("second", await store.GetAsync("two"));
    }

    [Fact]
    public async Task SurroundingWhitespaceInANameIsIgnored()
    {
        ICredentialStore store = CreateStore();

        await store.SetAsync("token", "s3cr3t");

        Assert.Equal("s3cr3t", await store.GetAsync("  token  "));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task EmptyNameIsRejected(string name)
    {
        ICredentialStore store = CreateStore();

        await Assert.ThrowsAsync<ArgumentException>(async () => await store.GetAsync(name));
        await Assert.ThrowsAsync<ArgumentException>(async () => await store.SetAsync(name, "s3cr3t"));
        await Assert.ThrowsAsync<ArgumentException>(async () => await store.DeleteAsync(name));
    }

    [Fact]
    public async Task EmptySecretIsRejected()
    {
        ICredentialStore store = CreateStore();

        await Assert.ThrowsAsync<ArgumentException>(async () => await store.SetAsync("token", "   "));
    }

    [Fact]
    public async Task LargeSecretReadsBackAsWritten()
    {
        ICredentialStore store = CreateStore();
        string secret = new('x', 16384);

        await store.SetAsync("bundle", secret);

        Assert.Equal(secret, await store.GetAsync("bundle"));
    }
}

public sealed class InMemoryCredentialStoreTests : CredentialStoreContractTests
{
    protected override ICredentialStore CreateStore() => new InMemoryCredentialStore();
}
