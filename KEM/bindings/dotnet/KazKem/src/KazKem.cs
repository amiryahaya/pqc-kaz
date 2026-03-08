using System;
using System.Security.Cryptography;
using Antrapol.Kaz.Kem.Native;

namespace Antrapol.Kaz.Kem;

/// <summary>
/// KAZ-KEM Post-Quantum Key Encapsulation Mechanism.
/// Thread-safe wrapper for the native KAZ-KEM library.
/// </summary>
public sealed class KazKemContext : IDisposable
{
    private static readonly object _initLock = new();
    private static KazKemContext? _current;
    private bool _disposed;

    static KazKemContext()
    {
        // Initialize native library resolver on first access
        NativeLibraryResolver.Initialize();
    }

    /// <summary>
    /// Current security level.
    /// </summary>
    public SecurityLevel SecurityLevel { get; }

    /// <summary>
    /// Public key size in bytes for current security level.
    /// </summary>
    public int PublicKeySize { get; }

    /// <summary>
    /// Private key size in bytes for current security level.
    /// </summary>
    public int PrivateKeySize { get; }

    /// <summary>
    /// Ciphertext size in bytes for current security level.
    /// </summary>
    public int CiphertextSize { get; }

    /// <summary>
    /// Shared secret size in bytes for current security level.
    /// </summary>
    public int SharedSecretSize { get; }

    /// <summary>
    /// Library version string.
    /// </summary>
    public static string Version => NativeInterop.KazKemVersion();

    private KazKemContext(SecurityLevel level)
    {
        SecurityLevel = level;
        PublicKeySize = (int)NativeInterop.KazKemPublicKeyBytes();
        PrivateKeySize = (int)NativeInterop.KazKemPrivateKeyBytes();
        CiphertextSize = (int)NativeInterop.KazKemCiphertextBytes();
        SharedSecretSize = (int)NativeInterop.KazKemSharedSecretBytes();
    }

    /// <summary>
    /// Initialize KAZ-KEM with the specified security level.
    /// </summary>
    /// <param name="level">Security level (128, 192, or 256 bits)</param>
    /// <returns>Initialized KAZ-KEM context</returns>
    /// <exception cref="InvalidSecurityLevelException">If level is invalid</exception>
    /// <exception cref="KazKemException">If initialization fails</exception>
    public static KazKemContext Initialize(SecurityLevel level = SecurityLevel.Level128)
    {
        lock (_initLock)
        {
            // If already initialized with same level, return existing
            if (_current != null && !_current._disposed && _current.SecurityLevel == level)
            {
                return _current;
            }

            // Cleanup previous instance
            _current?.Dispose();

            int result = NativeInterop.KazKemInit((int)level);
            if (result != 0)
            {
                throw KazKemException.FromErrorCode(result, "Initialize");
            }

            _current = new KazKemContext(level);
            return _current;
        }
    }

    /// <summary>
    /// Get the current initialized context.
    /// </summary>
    /// <exception cref="KazKemNotInitializedException">If not initialized</exception>
    public static KazKemContext Current
    {
        get
        {
            if (_current == null || _current._disposed)
            {
                throw new KazKemNotInitializedException();
            }
            return _current;
        }
    }

    /// <summary>
    /// Check if KAZ-KEM is currently initialized.
    /// </summary>
    public static bool IsInitialized => _current != null && !_current._disposed &&
                                        NativeInterop.KazKemIsInitialized() != 0;

    /// <summary>
    /// Generate a new key pair.
    /// </summary>
    /// <returns>A new key pair containing public and private keys</returns>
    /// <exception cref="KazKemException">If key generation fails</exception>
    public KazKemKeyPair GenerateKeyPair()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureInitialized();

        byte[] publicKey = new byte[PublicKeySize];
        byte[] privateKey = new byte[PrivateKeySize];

        int result = NativeInterop.KazKemKeypair(publicKey, privateKey);
        if (result != 0)
        {
            // Clear any partial data
            CryptographicOperations.ZeroMemory(privateKey);
            throw KazKemException.FromErrorCode(result, "GenerateKeyPair");
        }

        return new KazKemKeyPair(publicKey, privateKey, SecurityLevel);
    }

    /// <summary>
    /// Encapsulate a shared secret using the recipient's public key.
    /// </summary>
    /// <param name="publicKey">Recipient's public key</param>
    /// <returns>Encapsulation result containing ciphertext and shared secret</returns>
    /// <exception cref="ArgumentNullException">If publicKey is null</exception>
    /// <exception cref="ArgumentException">If publicKey has wrong size</exception>
    /// <exception cref="KazKemException">If encapsulation fails</exception>
    public KazKemEncapsulationResult Encapsulate(KazKemPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        return Encapsulate(publicKey.Bytes);
    }

    /// <summary>
    /// Encapsulate a shared secret using the recipient's public key bytes.
    /// </summary>
    /// <param name="publicKey">Recipient's public key bytes</param>
    /// <returns>Encapsulation result containing ciphertext and shared secret</returns>
    /// <exception cref="ArgumentException">If publicKey has wrong size</exception>
    /// <exception cref="KazKemException">If encapsulation fails</exception>
    public KazKemEncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureInitialized();

        if (publicKey.Length != PublicKeySize)
        {
            throw new ArgumentException(
                $"Public key must be {PublicKeySize} bytes, got {publicKey.Length}",
                nameof(publicKey));
        }

        // Generate random shared secret
        byte[] sharedSecret = new byte[SharedSecretSize];
        RandomNumberGenerator.Fill(sharedSecret);

        // Ensure message < N by clearing high bits
        // The modulus N has fewer bits than the byte array:
        // - Level 128: N=432 bits, array=54*8=432 bits, clear 1 bit (0x7F)
        // - Level 192: N=702 bits, array=88*8=704 bits, clear 3 bits (0x1F)
        // - Level 256: N=942 bits, array=118*8=944 bits, clear 3 bits (0x1F)
        byte mask = SecurityLevel switch
        {
            SecurityLevel.Level128 => 0x7F,  // Clear 1 bit
            SecurityLevel.Level192 => 0x1F,  // Clear 3 bits
            SecurityLevel.Level256 => 0x1F,  // Clear 3 bits
            _ => 0x7F
        };
        sharedSecret[0] &= mask;

        byte[] ciphertext = new byte[CiphertextSize];
        byte[] pkArray = publicKey.ToArray();

        int result = NativeInterop.KazKemEncapsulate(
            ciphertext, out ulong ctLen, sharedSecret, (ulong)sharedSecret.Length, pkArray);

        if (result != 0)
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            throw KazKemException.FromErrorCode(result, "Encapsulate");
        }

        // Trim ciphertext to actual length
        if ((int)ctLen < ciphertext.Length)
        {
            Array.Resize(ref ciphertext, (int)ctLen);
        }

        return new KazKemEncapsulationResult(ciphertext, sharedSecret);
    }

    /// <summary>
    /// Decapsulate a shared secret using the private key.
    /// </summary>
    /// <param name="ciphertext">Ciphertext from encapsulation</param>
    /// <param name="keyPair">Key pair containing the private key</param>
    /// <returns>The shared secret</returns>
    /// <exception cref="ArgumentNullException">If parameters are null</exception>
    /// <exception cref="KazKemException">If decapsulation fails</exception>
    public byte[] Decapsulate(ReadOnlySpan<byte> ciphertext, KazKemKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        return Decapsulate(ciphertext, keyPair.PrivateKey);
    }

    /// <summary>
    /// Decapsulate a shared secret using the private key bytes.
    /// </summary>
    /// <param name="ciphertext">Ciphertext from encapsulation</param>
    /// <param name="privateKey">Private key bytes</param>
    /// <returns>The shared secret</returns>
    /// <exception cref="ArgumentException">If parameters have wrong sizes</exception>
    /// <exception cref="KazKemException">If decapsulation fails</exception>
    public byte[] Decapsulate(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> privateKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureInitialized();

        if (privateKey.Length != PrivateKeySize)
        {
            throw new ArgumentException(
                $"Private key must be {PrivateKeySize} bytes, got {privateKey.Length}",
                nameof(privateKey));
        }

        byte[] sharedSecret = new byte[SharedSecretSize];
        byte[] ctArray = ciphertext.ToArray();
        byte[] skArray = privateKey.ToArray();

        try
        {
            int result = NativeInterop.KazKemDecapsulate(
                sharedSecret, out ulong ssLen, ctArray, (ulong)ctArray.Length, skArray);

            if (result != 0)
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
                throw KazKemException.FromErrorCode(result, "Decapsulate");
            }

            // Trim to actual length
            if ((int)ssLen < sharedSecret.Length)
            {
                byte[] trimmed = new byte[(int)ssLen];
                Array.Copy(sharedSecret, trimmed, (int)ssLen);
                CryptographicOperations.ZeroMemory(sharedSecret);
                return trimmed;
            }

            return sharedSecret;
        }
        finally
        {
            // Clear the private key copy
            CryptographicOperations.ZeroMemory(skArray);
        }
    }

    private void EnsureInitialized()
    {
        if (NativeInterop.KazKemIsInitialized() == 0)
        {
            throw new KazKemNotInitializedException();
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            lock (_initLock)
            {
                if (_current == this)
                {
                    NativeInterop.KazKemCleanup();
                    _current = null;
                }
            }
            _disposed = true;
        }
    }
}
