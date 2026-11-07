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

}

public sealed class InMemoryCredentialStoreTests : CredentialStoreContractTests
{
    protected override ICredentialStore CreateStore() => new InMemoryCredentialStore();
}
