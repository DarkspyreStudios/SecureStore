using System.Security.Cryptography;
using SecureStore;

namespace SecureStore.Tests;

public sealed class EncryptedFileCredentialStoreTests : CredentialStoreContractTests, IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securestore-tests-" + Guid.NewGuid().ToString("N"));

    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

    private string FilePath => Path.Combine(_directory, "credentials.json");

    protected override ICredentialStore CreateStore() =>
        new EncryptedFileCredentialStore(new AesGcmSecretProtector(_key), FilePath);

    [Fact]
    public async Task SecretSurvivesANewStoreOverTheSameFile()
    {
        await CreateStore().SetAsync("token", "s3cr3t");

        Assert.Equal("s3cr3t", await CreateStore().GetAsync("token"));
    }

    [Fact]
    public async Task SecretIsNotReadableInTheFile()
    {
        await CreateStore().SetAsync("token", "s3cr3t-in-the-clear");

        string contents = await File.ReadAllTextAsync(FilePath);

        Assert.DoesNotContain("s3cr3t-in-the-clear", contents, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SecretWrittenUnderAnotherKeyIsRejected()
    {
        await CreateStore().SetAsync("token", "s3cr3t");

        var wrongKey = new EncryptedFileCredentialStore(
            new AesGcmSecretProtector(RandomNumberGenerator.GetBytes(32)),
            FilePath);

        await Assert.ThrowsAsync<SecureStoreException>(async () => await wrongKey.GetAsync("token"));
    }

    [Fact]
    public async Task FileIsReadableOnlyByItsOwner()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await CreateStore().SetAsync("token", "s3cr3t");

        UnixFileMode mode = File.GetUnixFileMode(FilePath);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
    }

    [Fact]
    public void KeyOfTheWrongLengthIsRejected()
    {
        Assert.Throws<ArgumentException>(() => new AesGcmSecretProtector(new byte[20]));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
