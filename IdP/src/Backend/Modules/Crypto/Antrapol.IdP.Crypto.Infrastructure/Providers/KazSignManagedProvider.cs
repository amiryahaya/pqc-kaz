using System.Security.Cryptography;
using Antrapol.Kaz.Sign;
using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.Crypto.Domain.Interfaces;

namespace Antrapol.IdP.Crypto.Infrastructure.Providers;

/// <summary>
/// Managed crypto provider using Antrapol.Kaz.Sign NuGet package.
/// Provides KAZ-SIGN digital signature operations at all security levels (128, 192, 256).
/// </summary>
public sealed class KazSignManagedProvider : ICryptoProvider, IDisposable
{
    private readonly Dictionary<SecurityLevel, KazSigner> _signers = new();
    private readonly object _lock = new();
    private bool _disposed;

    public IReadOnlyList<KeyAlgorithm> SupportedAlgorithms =>
    [
        KeyAlgorithm.KazSign128,
        KeyAlgorithm.KazSign192,
        KeyAlgorithm.KazSign256
    ];

    /// <summary>
    /// Gets or creates a KazSigner for the specified algorithm.
    /// </summary>
    private KazSigner GetSigner(KeyAlgorithm algorithm)
    {
        var level = AlgorithmToSecurityLevel(algorithm);

        lock (_lock)
        {
            if (!_signers.TryGetValue(level, out var signer))
            {
                signer = new KazSigner(level, autoInitialize: true);
                _signers[level] = signer;
            }
            return signer;
        }
    }

    public Task<KeyPairResult> GenerateKeyPairAsync(KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ValidateSigningAlgorithm(algorithm);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var signer = GetSigner(algorithm);
        signer.GenerateKeyPair(out byte[] publicKey, out byte[] secretKey);

        return Task.FromResult(new KeyPairResult(publicKey, secretKey));
    }

    public Task<byte[]> SignAsync(byte[] data, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ValidateSigningAlgorithm(algorithm);
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(privateKey);

        var signer = GetSigner(algorithm);

        // Validate key size
        if (privateKey.Length != signer.SecretKeyBytes)
        {
            throw new ArgumentException(
                $"Invalid secret key size for {algorithm}. Expected {signer.SecretKeyBytes}, got {privateKey.Length}",
                nameof(privateKey));
        }

        var signature = signer.Sign(data, privateKey);
        return Task.FromResult(signature);
    }

    public Task<bool> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        ValidateSigningAlgorithm(algorithm);
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(publicKey);

        var signer = GetSigner(algorithm);

        // Validate key size
        if (publicKey.Length != signer.PublicKeyBytes)
        {
            throw new ArgumentException(
                $"Invalid public key size for {algorithm}. Expected {signer.PublicKeyBytes}, got {publicKey.Length}",
                nameof(publicKey));
        }

        // KAZ-SIGN uses message recovery - verify extracts message
        bool valid = signer.Verify(signature, publicKey, out byte[] recoveredMessage);

        // For signature schemes with message recovery, we compare the recovered message
        if (valid && recoveredMessage.Length > 0)
        {
            valid = data.SequenceEqual(recoveredMessage);
        }

        return Task.FromResult(valid);
    }

    public Task<EncapsulationResult> EncapsulateAsync(byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        // KAZ-SIGN is not a KEM algorithm
        throw new NotSupportedException($"KAZ-SIGN does not support key encapsulation. Use KAZ-KEM instead.");
    }

    public Task<byte[]> DecapsulateAsync(byte[] ciphertext, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default)
    {
        // KAZ-SIGN is not a KEM algorithm
        throw new NotSupportedException($"KAZ-SIGN does not support key decapsulation. Use KAZ-KEM instead.");
    }

    public string ComputeFingerprint(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        var hash = SHA256.HashData(publicKey);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Maps KeyAlgorithm to Antrapol.Kaz.Sign.SecurityLevel.
    /// </summary>
    private static SecurityLevel AlgorithmToSecurityLevel(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazSign128 => SecurityLevel.Level128,
        KeyAlgorithm.KazSign192 => SecurityLevel.Level192,
        KeyAlgorithm.KazSign256 => SecurityLevel.Level256,
        _ => throw new ArgumentException($"Algorithm {algorithm} is not a KAZ-SIGN algorithm.", nameof(algorithm))
    };

    private static void ValidateSigningAlgorithm(KeyAlgorithm algorithm)
    {
        if (algorithm is not (KeyAlgorithm.KazSign128 or KeyAlgorithm.KazSign192 or KeyAlgorithm.KazSign256))
        {
            throw new ArgumentException($"Algorithm {algorithm} is not a KAZ-SIGN signing algorithm.", nameof(algorithm));
        }
    }

    /// <summary>
    /// Get the public key size for a given algorithm.
    /// </summary>
    public static int GetPublicKeySize(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazSign128 => KazSignParameters.GetPublicKeyBytes(SecurityLevel.Level128),
        KeyAlgorithm.KazSign192 => KazSignParameters.GetPublicKeyBytes(SecurityLevel.Level192),
        KeyAlgorithm.KazSign256 => KazSignParameters.GetPublicKeyBytes(SecurityLevel.Level256),
        _ => throw new ArgumentException($"Unknown KAZ-SIGN algorithm: {algorithm}")
    };

    /// <summary>
    /// Get the private key size for a given algorithm.
    /// </summary>
    public static int GetPrivateKeySize(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazSign128 => KazSignParameters.GetSecretKeyBytes(SecurityLevel.Level128),
        KeyAlgorithm.KazSign192 => KazSignParameters.GetSecretKeyBytes(SecurityLevel.Level192),
        KeyAlgorithm.KazSign256 => KazSignParameters.GetSecretKeyBytes(SecurityLevel.Level256),
        _ => throw new ArgumentException($"Unknown KAZ-SIGN algorithm: {algorithm}")
    };

    /// <summary>
    /// Get the signature overhead size for a given algorithm.
    /// </summary>
    public static int GetSignatureOverhead(KeyAlgorithm algorithm) => algorithm switch
    {
        KeyAlgorithm.KazSign128 => KazSignParameters.GetSignatureOverhead(SecurityLevel.Level128),
        KeyAlgorithm.KazSign192 => KazSignParameters.GetSignatureOverhead(SecurityLevel.Level192),
        KeyAlgorithm.KazSign256 => KazSignParameters.GetSignatureOverhead(SecurityLevel.Level256),
        _ => throw new ArgumentException($"Unknown KAZ-SIGN algorithm: {algorithm}")
    };

    public void Dispose()
    {
        if (_disposed) return;

        lock (_lock)
        {
            foreach (var signer in _signers.Values)
            {
                signer.Dispose();
            }
            _signers.Clear();
        }

        _disposed = true;
    }
}
