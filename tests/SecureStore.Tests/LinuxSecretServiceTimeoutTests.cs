using System.Diagnostics;
using SecureStore;

namespace SecureStore.Tests;

/// <summary>
/// Puts a <c>secret-tool</c> that never answers first on <c>PATH</c> to exercise the timeout without a real vault.
/// </summary>
[Collection("secret-tool")]
public sealed class LinuxSecretServiceTimeoutTests
{
    [Fact]
    public async Task HangingSecretToolFailsWithAVaultFailureWithinTheLimit()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        string directory = Path.Combine(Path.GetTempPath(), "securestore-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string fake = Path.Combine(directory, "secret-tool");
        await File.WriteAllTextAsync(fake, "#!/bin/sh\nexec sleep 600\n");
        File.SetUnixFileMode(fake, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        string? path = Environment.GetEnvironmentVariable("PATH");
        Environment.SetEnvironmentVariable("PATH", directory + Path.PathSeparator + path);
        try
        {
            using var store = new LinuxSecretServiceCredentialStore(new SecureStoreOptions
            {
                ServiceName = "com.darkspyrestudios.securestore.tests",
                Label = "SecureStore tests"
            });
            Stopwatch elapsed = Stopwatch.StartNew();
            ValueTask<string?> read = store.GetAsync("timeout-" + Guid.NewGuid().ToString("N"));

            SecureStoreException exception = await Assert.ThrowsAsync<SecureStoreException>(async () => await read);

            elapsed.Stop();
            Assert.Contains("did not answer within 10 seconds", exception.Message, StringComparison.Ordinal);
            Assert.InRange(elapsed.Elapsed, TimeSpan.FromSeconds(9), TimeSpan.FromSeconds(15));
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", path);
            Directory.Delete(directory, recursive: true);
        }
    }
}
