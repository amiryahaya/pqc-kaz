using System;
using System.Runtime.InteropServices;

namespace Antrapol.Kaz.Kem.Native;

/// <summary>
/// Low-level P/Invoke bindings to the native KAZ-KEM library.
/// </summary>
internal static partial class NativeInterop
{
    private const string LibraryName = "kazkem";

    /// <summary>
    /// Initialize KEM with a specific security level.
    /// </summary>
    /// <param name="level">Security level: 128, 192, or 256</param>
    /// <returns>0 on success, negative on error</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_init")]
    internal static partial int KazKemInit(int level);

    /// <summary>
    /// Check if KEM is initialized.
    /// </summary>
    /// <returns>1 if initialized, 0 otherwise</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_is_initialized")]
    internal static partial int KazKemIsInitialized();

    /// <summary>
    /// Get current security level.
    /// </summary>
    /// <returns>Security level (128, 192, 256) or 0 if not initialized</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_get_level")]
    internal static partial int KazKemGetLevel();

    /// <summary>
    /// Get public key size in bytes.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_publickey_bytes")]
    internal static partial nuint KazKemPublicKeyBytes();

    /// <summary>
    /// Get private key size in bytes.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_privatekey_bytes")]
    internal static partial nuint KazKemPrivateKeyBytes();

    /// <summary>
    /// Get ciphertext size in bytes.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_ciphertext_bytes")]
    internal static partial nuint KazKemCiphertextBytes();

    /// <summary>
    /// Get shared secret size in bytes.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_shared_secret_bytes")]
    internal static partial nuint KazKemSharedSecretBytes();

    /// <summary>
    /// Generate a key pair.
    /// </summary>
    /// <param name="pk">Output public key buffer</param>
    /// <param name="sk">Output private key buffer</param>
    /// <returns>0 on success</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_keypair")]
    internal static partial int KazKemKeypair(
        [Out] byte[] pk,
        [Out] byte[] sk);

    /// <summary>
    /// Encapsulate a shared secret.
    /// </summary>
    /// <param name="ct">Output ciphertext buffer</param>
    /// <param name="ctlen">Output ciphertext length</param>
    /// <param name="ss">Input shared secret</param>
    /// <param name="sslen">Shared secret length</param>
    /// <param name="pk">Public key</param>
    /// <returns>0 on success</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_encapsulate")]
    internal static partial int KazKemEncapsulate(
        [Out] byte[] ct,
        out ulong ctlen,
        [In] byte[] ss,
        ulong sslen,
        [In] byte[] pk);

    /// <summary>
    /// Decapsulate a shared secret.
    /// </summary>
    /// <param name="ss">Output shared secret buffer</param>
    /// <param name="sslen">Output shared secret length</param>
    /// <param name="ct">Input ciphertext</param>
    /// <param name="ctlen">Ciphertext length</param>
    /// <param name="sk">Private key</param>
    /// <returns>0 on success</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_decapsulate")]
    internal static partial int KazKemDecapsulate(
        [Out] byte[] ss,
        out ulong sslen,
        [In] byte[] ct,
        ulong ctlen,
        [In] byte[] sk);

    /// <summary>
    /// Cleanup KEM state.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_cleanup")]
    internal static partial void KazKemCleanup();

    /// <summary>
    /// Full cleanup including OpenSSL state.
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_cleanup_full")]
    internal static partial void KazKemCleanupFull();

    /// <summary>
    /// Get version string (native pointer).
    /// </summary>
    [LibraryImport(LibraryName, EntryPoint = "kaz_kem_version")]
    private static partial IntPtr KazKemVersionNative();

    /// <summary>
    /// Get version string as managed string.
    /// </summary>
    internal static string KazKemVersion()
    {
        IntPtr ptr = KazKemVersionNative();
        return Marshal.PtrToStringUTF8(ptr) ?? "unknown";
    }
}
