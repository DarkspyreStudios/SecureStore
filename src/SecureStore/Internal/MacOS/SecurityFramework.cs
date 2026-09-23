using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SecureStore.Internal.MacOS;

/// <summary>
/// The SecItem family of the Security framework. The older SecKeychain calls are deprecated, and
/// these read and write the same generic password items in the file-based login keychain, so an
/// application that moves between the two keeps the secrets it already stored. A query that sets
/// <see cref="UseDataProtectionKeychain"/> reaches the data protection keychain instead, where
/// the application's keychain access group decides which applications can read an item.
/// </summary>
[SupportedOSPlatform("macos")]
internal static class SecurityFramework
{
    internal const string Library = "/System/Library/Frameworks/Security.framework/Security";

    internal const int Success = 0;
    internal const int ItemNotFound = -25300;
    internal const int DuplicateItem = -25299;
    internal const int MissingEntitlement = -34018;

    private static readonly IntPtr Handle = NativeLibrary.Load(Library);

    internal static readonly IntPtr ClassKey = Constant("kSecClass");
    internal static readonly IntPtr GenericPasswordClass = Constant("kSecClassGenericPassword");
    internal static readonly IntPtr ServiceAttribute = Constant("kSecAttrService");
    internal static readonly IntPtr AccountAttribute = Constant("kSecAttrAccount");
    internal static readonly IntPtr LabelAttribute = Constant("kSecAttrLabel");
    internal static readonly IntPtr ValueData = Constant("kSecValueData");
    internal static readonly IntPtr ReturnData = Constant("kSecReturnData");
    internal static readonly IntPtr MatchLimit = Constant("kSecMatchLimit");
    internal static readonly IntPtr MatchLimitOne = Constant("kSecMatchLimitOne");
    internal static readonly IntPtr UseDataProtectionKeychain = Constant("kSecUseDataProtectionKeychain");
    internal static readonly IntPtr AccessibleAttribute = Constant("kSecAttrAccessible");
    internal static readonly IntPtr AccessibleAfterFirstUnlockThisDeviceOnly = Constant("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly");

    /// <summary>
    /// Reads a CFStringRef constant the framework exports. The exported symbol is the variable
    /// holding the reference, so the value is one dereference away.
    /// </summary>
    private static IntPtr Constant(string name) =>
        Marshal.ReadIntPtr(NativeLibrary.GetExport(Handle, name));

    [DllImport(Library)]
    internal static extern int SecItemCopyMatching(IntPtr query, out IntPtr result);

    [DllImport(Library)]
    internal static extern int SecItemAdd(IntPtr attributes, IntPtr result);

    [DllImport(Library)]
    internal static extern int SecItemUpdate(IntPtr query, IntPtr attributesToUpdate);

    [DllImport(Library)]
    internal static extern int SecItemDelete(IntPtr query);
}
