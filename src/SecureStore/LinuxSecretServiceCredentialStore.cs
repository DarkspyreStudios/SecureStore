using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using SecureStore.Internal;

namespace SecureStore;

/// <summary>
/// Stores secrets through the Linux Secret Service API, reached with the <c>secret-tool</c> command
/// from libsecret.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxSecretServiceCredentialStore : ICredentialStore, IDisposable
{
    // A locked keyring makes secret-tool wait on an unlock prompt that may never be answered. Each call ends after
    // this limit and reports a vault failure, so an application that tolerates an unavailable vault keeps starting.
    // A healthy Secret Service answers in well under a second. Ten seconds stays well under the start-up deadlines
    // of the applications that read secrets while they start.
    private static readonly TimeSpan CallTimeout = TimeSpan.FromSeconds(10);

    private readonly string _serviceName;
    private readonly string _label;
    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <summary>Creates a store that saves secrets under the service name and label in <paramref name="options"/>.</summary>
    public LinuxSecretServiceCredentialStore(SecureStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _serviceName = options.ServiceName;
        _label = options.ResolvedLabel;
    }

    /// <inheritdoc />
    public async ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        string account = Prepare(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            SecretToolResult result = await RunAsync(
                ["lookup", "service", _serviceName, "account", account],
                null,
                cancellationToken).ConfigureAwait(false);
            if (result.ExitCode == 1 && string.IsNullOrWhiteSpace(result.StandardOutput))
            {
                return null;
            }

            ThrowIfFailed(result, "read");
            return result.StandardOutput.TrimEnd('\r', '\n');
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default)
    {
        string account = Prepare(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            SecretToolResult result = await RunAsync(
                ["store", $"--label={_label}", "service", _serviceName, "account", account],
                secret,
                cancellationToken).ConfigureAwait(false);
            ThrowIfFailed(result, "save");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        string account = Prepare(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            SecretToolResult result = await RunAsync(
                ["clear", "service", _serviceName, "account", account],
                null,
                cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 1)
            {
                ThrowIfFailed(result, "delete");
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Releases the lock that serializes calls to <c>secret-tool</c>.</summary>
    public void Dispose() => _gate.Dispose();

    private static string Prepare(string name)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "LinuxSecretServiceCredentialStore requires Linux.");
        }

        return CredentialName.Normalize(name);
    }

    private static async Task<SecretToolResult> RunAsync(
        IReadOnlyList<string> arguments,
        string? standardInput,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "secret-tool",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
        }
        catch (Win32Exception exception)
        {
            throw new PlatformNotSupportedException(
                "Linux secure storage requires secret-tool. On Debian or Ubuntu, install it with: sudo apt install libsecret-tools",
                exception);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(CallTimeout);
        Task<string> standardOutput = process.StandardOutput.ReadToEndAsync(timeout.Token);
        Task<string> standardError = process.StandardError.ReadToEndAsync(timeout.Token);
        try
        {
            if (standardInput is not null)
            {
                await process.StandardInput.WriteAsync(standardInput.AsMemory(), timeout.Token).ConfigureAwait(false);
                await process.StandardInput.FlushAsync(timeout.Token).ConfigureAwait(false);
            }

            process.StandardInput.Close();

            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            return new SecretToolResult(
                process.ExitCode,
                await standardOutput.ConfigureAwait(false),
                await standardError.ConfigureAwait(false));
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            Stop(process);
            throw new SecureStoreException(
                $"Linux Secret Service did not answer within {CallTimeout.TotalSeconds:0} seconds. The keyring may be locked.",
                exception);
        }
        catch
        {
            Stop(process);
            throw;
        }
    }

    // Waiting after the kill lets the runtime reap the child; a child killed and then disposed stays a zombie.
    private static void Stop(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }
    }

    private static void ThrowIfFailed(SecretToolResult result, string operation)
    {
        if (result.ExitCode == 0)
        {
            return;
        }

        string detail = string.IsNullOrWhiteSpace(result.StandardError)
            ? $"exit code {result.ExitCode}"
            : result.StandardError.Trim();
        throw new SecureStoreException($"Linux Secret Service could not {operation} the secret: {detail}");
    }

    private sealed record SecretToolResult(int ExitCode, string StandardOutput, string StandardError);
}
