using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Interfaces;

/// <summary>
/// Service for parsing and validating Certificate Signing Requests (CSRs).
/// </summary>
public interface ICsrService
{
    /// <summary>
    /// Parses a CSR from DER format (Base64 encoded).
    /// </summary>
    Result<CsrInfo> ParseCsr(string csrBase64);

    /// <summary>
    /// Verifies the CSR signature using KAZ-SIGN-256.
    /// </summary>
    bool VerifyCsrSignature(string csrBase64);

    /// <summary>
    /// Computes the SHA-256 fingerprint of a public key.
    /// </summary>
    string ComputePublicKeyFingerprint(byte[] publicKey);

    /// <summary>
    /// Verifies a payload signature using KAZ-SIGN-256.
    /// </summary>
    bool VerifySignature(byte[] publicKey, byte[] data, byte[] signature);
}

/// <summary>
/// Information extracted from a CSR.
/// </summary>
public sealed record CsrInfo(
    string SubjectDn,
    byte[] PublicKey,
    string PublicKeyFingerprint,
    byte[] CsrData);
