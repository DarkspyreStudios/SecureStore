using System.Runtime.Versioning;

namespace SecureStore.Internal.MacOS;

/// <summary>
/// Releases every CoreFoundation reference created while building a Keychain query. A query holds
/// a dozen short-lived strings, and losing one of them leaks for the life of the process.
/// </summary>
[SupportedOSPlatform("macos")]
internal sealed class CoreFoundationScope : IDisposable
{
    private readonly List<IntPtr> _references = [];

    /// <summary>Records a reference this scope owns and returns it unchanged.</summary>
    internal IntPtr Track(IntPtr reference)
    {
        if (reference != IntPtr.Zero)
        {
            _references.Add(reference);
        }

        return reference;
    }

    internal IntPtr String(string value) => Track(CoreFoundation.CreateString(value));

    internal IntPtr Data(byte[] value) => Track(CoreFoundation.CreateData(value));

    internal IntPtr Dictionary(int capacity) => Track(CoreFoundation.CreateMutableDictionary(capacity));

    public void Dispose()
    {
        for (int index = _references.Count - 1; index >= 0; index--)
        {
            CoreFoundation.Release(_references[index]);
        }

        _references.Clear();
    }
}
