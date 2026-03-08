using System.Security.Cryptography;
using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.Crypto.Domain.Interfaces;

namespace Antrapol.IdP.Crypto.Infrastructure.Providers;

/// <summary>
/// Unified crypto provider that delegates to the appropriate specialized provider
/// based on the requested algorithm.
/// </summary>
/// <remarks>
/// Supported algorithms:
/// - KAZ-SIGN (128, 192, 256): Malaysian National PQC Digital Signature
/// - KAZ-KEM (128, 192, 256): Malaysian National PQC Key Encapsulation
/// - ML-DSA (65, 87): NIST FIPS 204 Digital Signature (placeholder)
/// - ML-KEM (768, 1024): NIST FIPS 203 Key Encapsulation (placeholder)
/// </remarks>
public sealed class UnifiedCryptoProvider : ICryptoProvider, IDisposable
{
    private readonly KazSignManagedProvider _kazSignProvider;
    private readonly KazKemManagedProvider _kazKemProvider;
    private readonly LibOqsCryptoProvider _libOqsProvider;
    private bool _disposed;

    public UnifiedCryptoProvider()
    {
        _kazSignProvider = new KazSignManagedProvider();
        _kazKemProvider = new KazKemManagedProvider();
        _libOqsProvider = new LibOqsCryptoProvider();
    }

    public IReadOnlyList<KeyAlgorithm> SupportedAlgorithms =>
    [
        // KAZ-SIGN (Malaysian National Standard)
        KeyAlgorithm.KazSign128,
        KeyAlgorithm.KazSign192,
        KeyAlgorithm.KazSign256,

        // KAZ-KEM (Malaysian National Standard)
        KeyAlgorithm.KazKem128,
        KeyAlgorithm.KazKem192,
        KeyAlgorithm.KazKem256,

        // NIST Standards (via liboqs - placeholder)
        KeyAlgorithm.MlDsa65,
        KeyAlgorithm.MlDsa87,
        KeyAlgorithm.MlKem768,
        KeyAlgorithm.MlKem1024
    ];

    public Task<KeyPairResult> GenerateKeyPairAsync(KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return GetProvider(algorithm).GenerateKeyPairAsync(algorithm, ct);
    }

    public Task<byte[]> SignAsync(byte[] data, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return GetSigningProvider(algorithm).SignAsync(data, privateKey, algorithm, ct);
    }

    public Task<bool> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return GetSigningProvider(algorithm).VerifyAsync(data, signature, publicKey, algorithm, ct);
    }

    public Task<EncapsulationResult> EncapsulateAsync(byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return GetKemProvider(algorithm).EncapsulateAsync(publicKey, algorithm, ct);
    }

    public Task<byte[]> DecapsulateAsync(byte[] ciphertext, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return GetKemProvider(algorithm).DecapsulateAsync(ciphertext, privateKey, algorithm, ct);
    }

    public string ComputeFingerprint(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        var hash = SHA256.HashData(publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Gets the appropriate provider for key generation based on algorithm.
    /// </summary>
    private ICryptoProvider GetProvider(KeyAlgorithm algorithm) => algorithm switch
    {
        // KAZ-SIGN algorithms
        KeyAlgorithm.KazSign128 or
        KeyAlgorithm.KazSign192 or
        KeyAlgorithm.KazSign256 => _kazSignProvider,

        // KAZ-KEM algorithms
        KeyAlgorithm.KazKem128 or
        KeyAlgorithm.KazKem192 or
        KeyAlgorithm.KazKem256 => _kazKemProvider,

        // NIST algorithms (placeholder)
        KeyAlgorithm.MlDsa65 or
        KeyAlgorithm.MlDsa87 or
        KeyAlgorithm.MlKem768 or
        KeyAlgorithm.MlKem1024 => _libOqsProvider,

        _ => throw new NotSupportedException($"Algorithm {algorithm} is not supported.")
    };

    /// <summary>
    /// Gets the appropriate signing provider based on algorithm.
    /// </summary>
    private ICryptoProvider GetSigningProvider(KeyAlgorithm algorithm) => algorithm switch
    {
        // KAZ-SIGN algorithms
        KeyAlgorithm.KazSign128 or
        KeyAlgorithm.KazSign192 or
        KeyAlgorithm.KazSign256 => _kazSignProvider,

        // NIST ML-DSA (placeholder)
        KeyAlgorithm.MlDsa65 or
        KeyAlgorithm.MlDsa87 => _libOqsProvider,

        _ => throw new NotSupportedException($"Algorithm {algorithm} is not a signing algorithm.")
    };

    /// <summary>
    /// Gets the appropriate KEM provider based on algorithm.
    /// </summary>
    private ICryptoProvider GetKemProvider(KeyAlgorithm algorithm) => algorithm switch
    {
        // KAZ-KEM algorithms
        KeyAlgorithm.KazKem128 or
        KeyAlgorithm.KazKem192 or
        KeyAlgorithm.KazKem256 => _kazKemProvider,

        // NIST ML-KEM (placeholder)
        KeyAlgorithm.MlKem768 or
        KeyAlgorithm.MlKem1024 => _libOqsProvider,

        _ => throw new NotSupportedException($"Algorithm {algorithm} is not a KEM algorithm.")
    };

    /// <summary>
    /// Checks if an algorithm is supported.
    /// </summary>
    public bool IsAlgorithmSupported(KeyAlgorithm algorithm) =>
        SupportedAlgorithms.Contains(algorithm);

    /// <summary>
    /// Checks if an algorithm is a signing algorithm.
    /// </summary>
    public static bool IsSigningAlgorithm(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazSign128 or
        KeyAlgorithm.KazSign192 or
        KeyAlgorithm.KazSign256 or
        KeyAlgorithm.MlDsa65 or
        KeyAlgorithm.MlDsa87 => true,
        _ => false
    };

    /// <summary>
    /// Checks if an algorithm is a KEM algorithm.
    /// </summary>
    public static bool IsKemAlgorithm(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazKem128 or
        KeyAlgorithm.KazKem192 or
        KeyAlgorithm.KazKem256 or
        KeyAlgorithm.MlKem768 or
        KeyAlgorithm.MlKem1024 => true,
        _ => false
    };

    public void Dispose()
    {
        if (_disposed) return;

        _kazSignProvider.Dispose();
        _kazKemProvider.Dispose();

        _disposed = true;
    }
}
