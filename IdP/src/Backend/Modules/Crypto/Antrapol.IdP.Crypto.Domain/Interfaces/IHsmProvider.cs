using Antrapol.IdP.Crypto.Domain.Enums;

namespace Antrapol.IdP.Crypto.Domain.Interfaces;

/// <summary>
/// Interface for HSM (Hardware Security Module) operations via PKCS#11.
/// </summary>
public interface IHsmProvider
{
    /// <summary>
    /// Generates a key pair in the HSM.
    /// </summary>
    Task<HsmKeyResult> GenerateKeyPairAsync(
        string label,
        KeyAlgorithm algorithm,
        CancellationToken ct = default);

    /// <summary>
    /// Signs data using a key stored in the HSM.
    /// </summary>
    Task<byte[]> SignAsync(
        string keyHandle,
        byte[] data,
        KeyAlgorithm algorithm,
        CancellationToken ct = default);

    /// <summary>
    /// Verifies a signature using a key stored in the HSM.
    /// </summary>
    Task<bool> VerifyAsync(
        string keyHandle,
        byte[] data,
        byte[] signature,
        KeyAlgorithm algorithm,
        CancellationToken ct = default);

    /// <summary>
    /// Performs key encapsulation using a key stored in the HSM.
    /// </summary>
    Task<EncapsulationResult> EncapsulateAsync(
        string keyHandle,
        KeyAlgorithm algorithm,
        CancellationToken ct = default);

    /// <summary>
    /// Performs key decapsulation using a key stored in the HSM.
    /// </summary>
    Task<byte[]> DecapsulateAsync(
        string keyHandle,
        byte[] ciphertext,
        KeyAlgorithm algorithm,
        CancellationToken ct = default);

    /// <summary>
    /// Destroys a key in the HSM.
    /// </summary>
    Task DestroyKeyAsync(string keyHandle, CancellationToken ct = default);

    /// <summary>
    /// Checks if a key exists in the HSM.
    /// </summary>
    Task<bool> KeyExistsAsync(string keyHandle, CancellationToken ct = default);

    /// <summary>
    /// Gets information about the HSM.
    /// </summary>
    Task<HsmInfo> GetInfoAsync(CancellationToken ct = default);
}

/// <summary>
/// Result of HSM key generation.
/// </summary>
public sealed record HsmKeyResult(string KeyHandle, byte[] PublicKey);

/// <summary>
/// Information about the HSM.
/// </summary>
public sealed record HsmInfo(
    string Manufacturer,
    string Model,
    string SerialNumber,
    string FirmwareVersion,
    bool IsInitialized);
