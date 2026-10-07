using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureStore.Internal;

namespace SecureStore;

/// <summary>
/// Stores secrets in one encrypted file. It exists for a host with no credential vault, such as a
/// headless Linux box or a container, where the alternative is asking for credentials on every
/// start. It is weaker than a vault: the file is only as private as the key the host holds and the
/// permissions on the directory around it.
/// </summary>
public sealed class EncryptedFileCredentialStore : ICredentialStore, IDisposable
{
    private readonly ISecretProtector _protector;
    private readonly string _filePath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public EncryptedFileCredentialStore(ISecretProtector protector, string filePath)
    {
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        _protector = protector;
        _filePath = Path.GetFullPath(filePath);
    }

    public async ValueTask<string?> GetAsync(string name, CancellationToken cancellationToken = default)
    {
        string key = CredentialName.Normalize(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Dictionary<string, string> entries = await ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!entries.TryGetValue(key, out string? stored))
            {
                return null;
            }

            byte[] plaintext = _protector.Unprotect(Convert.FromBase64String(stored));
            try
            {
                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask SetAsync(string name, string secret, CancellationToken cancellationToken = default)
    {
        string key = CredentialName.Normalize(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Dictionary<string, string> entries = await ReadAsync(cancellationToken).ConfigureAwait(false);
            byte[] plaintext = Encoding.UTF8.GetBytes(secret);
            try
            {
                entries[key] = Convert.ToBase64String(_protector.Protect(plaintext));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }

            await WriteAsync(entries, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DeleteAsync(string name, CancellationToken cancellationToken = default)
    {
        string key = CredentialName.Normalize(name);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Dictionary<string, string> entries = await ReadAsync(cancellationToken).ConfigureAwait(false);
            if (entries.Remove(key))
            {
                await WriteAsync(entries, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();

    private async Task<Dictionary<string, string>> ReadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_filePath))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        await using FileStream stream = File.OpenRead(_filePath);
        Dictionary<string, string>? entries = await JsonSerializer
            .DeserializeAsync(stream, EncryptedFileCredentialJsonContext.Default.Entries, cancellationToken)
            .ConfigureAwait(false);
        return entries is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(entries, StringComparer.Ordinal);
    }

    /// <summary>
    /// Writes to a temporary file and moves it into place, so a process that stops mid-write leaves
    /// the previous file intact.
    /// </summary>
    private async Task WriteAsync(Dictionary<string, string> entries, CancellationToken cancellationToken)
    {
        string directory = Path.GetDirectoryName(_filePath)
            ?? throw new SecureStoreException($"The secret file path '{_filePath}' has no directory.");
        Directory.CreateDirectory(directory);
        RestrictToOwner(directory, isDirectory: true);

        string temporaryPath = _filePath + ".tmp";
        await using (FileStream stream = File.Create(temporaryPath))
        {
            RestrictToOwner(temporaryPath, isDirectory: false);
            await JsonSerializer.SerializeAsync(stream, entries, EncryptedFileCredentialJsonContext.Default.Entries, cancellationToken).ConfigureAwait(false);
        }

        File.Move(temporaryPath, _filePath, overwrite: true);
        RestrictToOwner(_filePath, isDirectory: false);
    }

    private static void RestrictToOwner(string path, bool isDirectory)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        UnixFileMode mode = isDirectory
            ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            : UnixFileMode.UserRead | UnixFileMode.UserWrite;
        File.SetUnixFileMode(path, mode);
    }
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web, GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(Dictionary<string, string>), TypeInfoPropertyName = "Entries")]
internal sealed partial class EncryptedFileCredentialJsonContext : JsonSerializerContext;
