using Antrapol.IdP.Crypto.Domain.Enums;

namespace Antrapol.IdP.Crypto.Domain.Interfaces;

/// <summary>
/// Interface for cryptographic operations provider.
/// </summary>
public interface ICryptoProvider
{
    /// <summary>
    /// Generates a new key pair for the specified algorithm.
    /// </summary>
    Task<KeyPairResult> GenerateKeyPairAsync(KeyAlgorithm algorithm, CancellationToken ct = default);

    /// <summary>
    /// Signs data using the specified private key.
    /// </summary>
    Task<byte[]> SignAsync(byte[] data, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default);

    /// <summary>
    /// Verifies a signature using the specified public key.
    /// </summary>
    Task<bool> VerifyAsync(byte[] data, byte[] signature, byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default);

    /// <summary>
    /// Encapsulates a shared secret using the specified public key (KEM).
    /// </summary>
    Task<EncapsulationResult> EncapsulateAsync(byte[] publicKey, KeyAlgorithm algorithm, CancellationToken ct = default);

    /// <summary>
    /// Decapsulates a shared secret using the specified private key (KEM).
    /// </summary>
    Task<byte[]> DecapsulateAsync(byte[] ciphertext, byte[] privateKey, KeyAlgorithm algorithm, CancellationToken ct = default);

    /// <summary>
    /// Computes the fingerprint of a public key.
    /// </summary>
    string ComputeFingerprint(byte[] publicKey);

    /// <summary>
    /// Gets the supported algorithms.
    /// </summary>
    IReadOnlyList<KeyAlgorithm> SupportedAlgorithms { get; }
}

/// <summary>
/// Result of key pair generation.
/// </summary>
public sealed record KeyPairResult(byte[] PublicKey, byte[] PrivateKey);

/// <summary>
/// Result of key encapsulation.
/// </summary>
public sealed record EncapsulationResult(byte[] Ciphertext, byte[] SharedSecret);
