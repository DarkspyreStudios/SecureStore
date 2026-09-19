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
    private readonly string _serviceName;
    private readonly string _label;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public LinuxSecretServiceCredentialStore(SecureStoreOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _serviceName = options.ServiceName;
        _label = options.ResolvedLabel;
    }

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

        Task<string> standardOutput = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> standardError = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            if (standardInput is not null)
            {
                await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken).ConfigureAwait(false);
                await process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            process.StandardInput.Close();

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            return new SecretToolResult(
                process.ExitCode,
                await standardOutput.ConfigureAwait(false),
                await standardError.ConfigureAwait(false));
        }
        catch
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }

            throw;
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
