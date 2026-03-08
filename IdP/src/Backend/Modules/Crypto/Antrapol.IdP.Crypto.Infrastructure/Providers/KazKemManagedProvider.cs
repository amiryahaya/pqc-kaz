using System.Security.Cryptography;
using Antrapol.Kaz.Kem;
using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.Crypto.Domain.Interfaces;
using KemSecurityLevel = Antrapol.Kaz.Kem.SecurityLevel;

namespace Antrapol.IdP.Crypto.Infrastructure.Providers;

/// <summary>
/// Managed crypto provider using Antrapol.Kaz.Kem NuGet package.
/// Provides KAZ-KEM key encapsulation operations at all security levels (128, 192, 256).
/// </summary>
public sealed class KazKemManagedProvider : ICryptoProvider, IDisposable
{
    private readonly object _lock = new();
    private KazKemContext? _currentContext;
    private KemSecurityLevel _currentLevel;
    private bool _disposed;

    public IReadOnlyList<KeyAlgorithm> SupportedAlgorithms =>
    [
        KeyAlgorithm.KazKem128,
        KeyAlgorithm.KazKem192,
        KeyAlgorithm.KazKem256
    ];

    /// <summary>
    /// Gets or initializes the KAZ-KEM context for the specified algorithm.
    /// </summary>
    private KazKemContext GetContext(KeyAlgorithm algorithm)
    {
        var level = AlgorithmToSecurityLevel(algorithm);

        lock (_lock)
        {
            // Re-initialize if level changed or not initialized
            if (_currentContext == null || _currentLevel != level)
            {
                _currentContext?.Dispose();
                _currentContext = KazKemContext.Initialize(level);
                _currentLevel = level;
            }
            return _currentContext;
        }
    }

    public Task<KeyPairResult> GenerateKeyPairAsync(KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ValidateKemAlgorithm(algorithm);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var context = GetContext(algorithm);
        using var keyPair = context.GenerateKeyPair();

        var publicKey = keyPair.ExportPublicKey();
        var privateKey = keyPair.ExportPrivateKey();

        return Task.FromResult(new KeyPairResult(publicKey, privateKey));
    }

    public Task<byte[]> SignAsync(byte[] data, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        // KAZ-KEM is not a signing algorithm
        throw new NotSupportedException($"KAZ-KEM does not support signing. Use KAZ-SIGN instead.");
    }

    public Task<bool> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        // KAZ-KEM is not a signing algorithm
        throw new NotSupportedException($"KAZ-KEM does not support signature verification. Use KAZ-SIGN instead.");
    }

    public Task<EncapsulationResult> EncapsulateAsync(byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ValidateKemAlgorithm(algorithm);
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(publicKey);

        var context = GetContext(algorithm);

        // Validate key size
        if (publicKey.Length != context.PublicKeySize)
        {
            throw new ArgumentException(
                $"Invalid public key size for {algorithm}. Expected {context.PublicKeySize}, got {publicKey.Length}",
                nameof(publicKey));
        }

        // Create public key object and encapsulate
        var kemPublicKey = KazKemPublicKey.FromBytes(publicKey, _currentLevel);
        using var encResult = context.Encapsulate(kemPublicKey);

        var ciphertext = encResult.ExportCiphertext();
        var sharedSecret = encResult.ExportSharedSecret();

        return Task.FromResult(new EncapsulationResult(ciphertext, sharedSecret));
    }

    public Task<byte[]> DecapsulateAsync(byte[] ciphertext, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ValidateKemAlgorithm(algorithm);
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(privateKey);

        var context = GetContext(algorithm);

        // Validate key size
        if (privateKey.Length != context.PrivateKeySize)
        {
            throw new ArgumentException(
                $"Invalid private key size for {algorithm}. Expected {context.PrivateKeySize}, got {privateKey.Length}",
                nameof(privateKey));
        }

        var sharedSecret = context.Decapsulate(ciphertext, privateKey);
        return Task.FromResult(sharedSecret);
    }

    public string ComputeFingerprint(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        var hash = SHA256.HashData(publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Maps KeyAlgorithm to Antrapol.Kaz.Kem.SecurityLevel.
    /// </summary>
    private static KemSecurityLevel AlgorithmToSecurityLevel(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazKem128 => KemSecurityLevel.Level128,
        KeyAlgorithm.KazKem192 => KemSecurityLevel.Level192,
        KeyAlgorithm.KazKem256 => KemSecurityLevel.Level256,
        _ => throw new ArgumentException($"Algorithm {algorithm} is not a KAZ-KEM algorithm.", nameof(algorithm))
    };

    private static void ValidateKemAlgorithm(KeyAlgorithm algorithm)
    {
        if (algorithm is not (KeyAlgorithm.KazKem128 or KeyAlgorithm.KazKem192 or KeyAlgorithm.KazKem256))
        {
            throw new ArgumentException($"Algorithm {algorithm} is not a KAZ-KEM algorithm.", nameof(algorithm));
        }
    }

    /// <summary>
    /// Get the public key size for a given algorithm.
    /// </summary>
    public static int GetPublicKeySize(KeyAlgorithm algorithm)
    {
        var level = AlgorithmToSecurityLevel(algorithm);
        using var context = KazKemContext.Initialize(level);
        return context.PublicKeySize;
    }

    /// <summary>
    /// Get the private key size for a given algorithm.
    /// </summary>
    public static int GetPrivateKeySize(KeyAlgorithm algorithm)
    {
        var level = AlgorithmToSecurityLevel(algorithm);
        using var context = KazKemContext.Initialize(level);
        return context.PrivateKeySize;
    }

    /// <summary>
    /// Get the ciphertext size for a given algorithm.
    /// </summary>
    public static int GetCiphertextSize(KeyAlgorithm algorithm)
    {
        var level = AlgorithmToSecurityLevel(algorithm);
        using var context = KazKemContext.Initialize(level);
        return context.CiphertextSize;
    }

    /// <summary>
    /// Get the shared secret size for a given algorithm.
    /// </summary>
    public static int GetSharedSecretSize(KeyAlgorithm algorithm)
    {
        var level = AlgorithmToSecurityLevel(algorithm);
        using var context = KazKemContext.Initialize(level);
        return context.SharedSecretSize;
    }

    public void Dispose()
    {
        if (_disposed) return;

        lock (_lock)
        {
            _currentContext?.Dispose();
            _currentContext = null;
        }

        _disposed = true;
    }
}
