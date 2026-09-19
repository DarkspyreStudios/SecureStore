using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SecureStore.Internal.MacOS;

/// <summary>
/// The CoreFoundation types the Keychain query dictionaries are built from. Every Create call
/// returns a reference the caller owns and must release, which <see cref="CoreFoundationScope"/>
/// does.
/// </summary>
[SupportedOSPlatform("macos")]
internal static class CoreFoundation
{
    internal const string Library = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    private const uint Utf8Encoding = 0x08000100;

    private static readonly IntPtr Handle = NativeLibrary.Load(Library);

    /// <summary>The key callbacks that make a dictionary retain and release its CoreFoundation keys.</summary>
    internal static readonly IntPtr TypeDictionaryKeyCallBacks =
        NativeLibrary.GetExport(Handle, "kCFTypeDictionaryKeyCallBacks");

    /// <summary>The value callbacks that make a dictionary retain and release its CoreFoundation values.</summary>
    internal static readonly IntPtr TypeDictionaryValueCallBacks =
        NativeLibrary.GetExport(Handle, "kCFTypeDictionaryValueCallBacks");

    /// <summary>The shared true value. It is a constant, so the caller does not release it.</summary>
    internal static readonly IntPtr True =
        Marshal.ReadIntPtr(NativeLibrary.GetExport(Handle, "kCFBooleanTrue"));

    /// <summary>Creates a CFString from UTF-8 bytes.</summary>
    internal static IntPtr CreateString(string value)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);
        IntPtr reference = CFStringCreateWithBytes(IntPtr.Zero, bytes, bytes.Length, Utf8Encoding, false);
        return reference != IntPtr.Zero
            ? reference
            : throw new SecureStoreException("macOS Keychain could not encode a query value.");
    }

    /// <summary>Creates a CFData holding a copy of <paramref name="value"/>.</summary>
    internal static IntPtr CreateData(byte[] value)
    {
        IntPtr reference = CFDataCreate(IntPtr.Zero, value, value.Length);
        return reference != IntPtr.Zero
            ? reference
            : throw new SecureStoreException("macOS Keychain could not encode a secret value.");
    }

    /// <summary>Copies the bytes out of a CFData the Keychain returned.</summary>
    internal static byte[] ReadData(IntPtr data)
    {
        long length = CFDataGetLength(data);
        if (length <= 0)
        {
            return [];
        }

        byte[] bytes = new byte[length];
        Marshal.Copy(CFDataGetBytePtr(data), bytes, 0, checked((int)length));
        return bytes;
    }

    /// <summary>Creates an empty mutable dictionary that retains the keys and values added to it.</summary>
    internal static IntPtr CreateMutableDictionary(int capacity)
    {
        IntPtr reference = CFDictionaryCreateMutable(
            IntPtr.Zero,
            capacity,
            TypeDictionaryKeyCallBacks,
            TypeDictionaryValueCallBacks);
        return reference != IntPtr.Zero
            ? reference
            : throw new SecureStoreException("macOS Keychain could not build a query.");
    }

    internal static void Release(IntPtr reference)
    {
        if (reference != IntPtr.Zero)
        {
            CFRelease(reference);
        }
    }

    [DllImport(Library)]
    private static extern IntPtr CFStringCreateWithBytes(
        IntPtr allocator,
        byte[] bytes,
        long length,
        uint encoding,
        [MarshalAs(UnmanagedType.I1)] bool isExternalRepresentation);

    [DllImport(Library)]
    private static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, long length);

    [DllImport(Library)]
    private static extern IntPtr CFDataGetBytePtr(IntPtr data);

    [DllImport(Library)]
    private static extern long CFDataGetLength(IntPtr data);

    [DllImport(Library)]
    private static extern IntPtr CFDictionaryCreateMutable(
        IntPtr allocator,
        long capacity,
        IntPtr keyCallBacks,
        IntPtr valueCallBacks);

    [DllImport(Library)]
    internal static extern void CFDictionarySetValue(IntPtr dictionary, IntPtr key, IntPtr value);

    [DllImport(Library)]
    private static extern void CFRelease(IntPtr reference);
}
