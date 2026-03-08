using System.Runtime.InteropServices;

namespace Antrapol.IdP.Crypto.Infrastructure.Providers;

/// <summary>
/// P/Invoke declarations for the libkazsign native library.
/// KAZ-SIGN-256 is the Malaysian National Post-Quantum Signature Algorithm (Security Level 5).
/// </summary>
internal static partial class KazSignNative
{
    private const string LibraryName = "kazsign";

    // ============================================
    // Constants
    // ============================================

    /// <summary>Public key size for KAZ-SIGN-256 (comparable to ML-DSA-87)</summary>
    public const int PublicKeySize = 2592;

    /// <summary>Secret key size for KAZ-SIGN-256</summary>
    public const int SecretKeySize = 4896;

    /// <summary>Maximum signature size for KAZ-SIGN-256</summary>
    public const int SignatureSize = 4627;

    // ============================================
    // Error Codes
    // ============================================

    public const int KAZ_SUCCESS = 0;
    public const int KAZ_ERROR_NULL_POINTER = -1;
    public const int KAZ_ERROR_KEYGEN_FAILED = -2;
    public const int KAZ_ERROR_SIGN_FAILED = -3;
    public const int KAZ_ERROR_VERIFY_FAILED = -4;
    public const int KAZ_ERROR_INVALID_KEY = -5;
    public const int KAZ_ERROR_INVALID_SIGNATURE = -6;

    // ============================================
    // P/Invoke Declarations
    // ============================================

    /// <summary>
    /// Generate a KAZ-SIGN-256 keypair.
    /// </summary>
    /// <param name="publicKey">Output buffer for public key (2592 bytes)</param>
    /// <param name="secretKey">Output buffer for secret key (4896 bytes)</param>
    /// <returns>KAZ_SUCCESS on success, error code otherwise</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_sign_keygen")]
    public static partial int KeyGen(
        [Out] byte[] publicKey,
        [Out] byte[] secretKey);

    /// <summary>
    /// Sign a message with KAZ-SIGN-256.
    /// </summary>
    /// <param name="secretKey">Secret key (4896 bytes)</param>
    /// <param name="message">Message to sign</param>
    /// <param name="messageLen">Length of message</param>
    /// <param name="signature">Output buffer for signature (4627 bytes max)</param>
    /// <param name="signatureLen">Output: actual signature length</param>
    /// <returns>KAZ_SUCCESS on success, error code otherwise</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_sign_sign")]
    public static partial int Sign(
        [In] byte[] secretKey,
        [In] byte[] message,
        nuint messageLen,
        [Out] byte[] signature,
        out nuint signatureLen);

    /// <summary>
    /// Verify a KAZ-SIGN-256 signature.
    /// </summary>
    /// <param name="publicKey">Public key (2592 bytes)</param>
    /// <param name="message">Original message</param>
    /// <param name="messageLen">Length of message</param>
    /// <param name="signature">Signature to verify</param>
    /// <param name="signatureLen">Length of signature</param>
    /// <returns>KAZ_SUCCESS if valid, KAZ_ERROR_INVALID_SIGNATURE if invalid</returns>
    [LibraryImport(LibraryName, EntryPoint = "kaz_sign_verify")]
    public static partial int Verify(
        [In] byte[] publicKey,
        [In] byte[] message,
        nuint messageLen,
        [In] byte[] signature,
        nuint signatureLen);
}

/// <summary>
/// Managed wrapper for KAZ-SIGN-256 native operations.
/// </summary>
#pragma warning disable CA1822 // Mark members as static - Keep as instance for DI and future state
public sealed class KazSignProvider
{
    /// <summary>
    /// Generates a new KAZ-SIGN-256 keypair.
    /// </summary>
    public KazSignKeyPair GenerateKeyPair()
    {
        var publicKey = new byte[KazSignNative.PublicKeySize];
        var secretKey = new byte[KazSignNative.SecretKeySize];

        var result = KazSignNative.KeyGen(publicKey, secretKey);
        if (result != KazSignNative.KAZ_SUCCESS)
        {
            throw new CryptographicException($"KAZ-SIGN-256 key generation failed with error code: {result}");
        }

        return new KazSignKeyPair(publicKey, secretKey);
    }

    /// <summary>
    /// Signs a message with KAZ-SIGN-256.
    /// </summary>
    public byte[] Sign(byte[] secretKey, byte[] message)
    {
        ArgumentNullException.ThrowIfNull(secretKey);
        ArgumentNullException.ThrowIfNull(message);

        if (secretKey.Length != KazSignNative.SecretKeySize)
        {
            throw new ArgumentException($"Invalid secret key size. Expected {KazSignNative.SecretKeySize}, got {secretKey.Length}");
        }

        var signature = new byte[KazSignNative.SignatureSize];
        var result = KazSignNative.Sign(
            secretKey,
            message,
            (nuint)message.Length,
            signature,
            out var signatureLen);

        if (result != KazSignNative.KAZ_SUCCESS)
        {
            throw new CryptographicException($"KAZ-SIGN-256 signing failed with error code: {result}");
        }

        // Return only the actual signature bytes
        return signature[..(int)signatureLen];
    }

    /// <summary>
    /// Verifies a KAZ-SIGN-256 signature.
    /// </summary>
    public bool Verify(byte[] publicKey, byte[] message, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signature);

        if (publicKey.Length != KazSignNative.PublicKeySize)
        {
            throw new ArgumentException($"Invalid public key size. Expected {KazSignNative.PublicKeySize}, got {publicKey.Length}");
        }

        var result = KazSignNative.Verify(
            publicKey,
            message,
            (nuint)message.Length,
            signature,
            (nuint)signature.Length);

        return result == KazSignNative.KAZ_SUCCESS;
    }
}

#pragma warning restore CA1822

/// <summary>
/// KAZ-SIGN-256 keypair.
/// </summary>
public sealed record KazSignKeyPair(byte[] PublicKey, byte[] SecretKey);

/// <summary>
/// Exception thrown when cryptographic operations fail.
/// </summary>
public class CryptographicException : Exception
{
    public CryptographicException(string message) : base(message) { }
    public CryptographicException(string message, Exception inner) : base(message, inner) { }
}
