using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Certificate.Application.Interfaces;

/// <summary>
/// Service for parsing and validating Certificate Signing Requests (CSRs).
/// Uses ASN.1/DER parsing for structure and native P/Invoke for KAZ-SIGN-256 verification.
/// </summary>
public interface ICsrParser
{
    /// <summary>
    /// Parses a CSR from DER format and extracts its contents.
    /// </summary>
    /// <param name="csrDer">CSR in DER format</param>
    /// <returns>Parsed CSR data</returns>
    Result<ParsedCsr> Parse(byte[] csrDer);

    /// <summary>
    /// Verifies the self-signature of a CSR using KAZ-SIGN-256.
    /// </summary>
    /// <param name="csrDer">CSR in DER format</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>True if signature is valid</returns>
    Task<bool> VerifySignatureAsync(byte[] csrDer, CancellationToken ct = default);

    /// <summary>
    /// Validates that the CSR meets all requirements.
    /// </summary>
    Task<Result<CsrValidationResult>> ValidateAsync(byte[] csrDer, CancellationToken ct = default);
}

/// <summary>
/// Parsed CSR data.
/// </summary>
/// <param name="Version">Version (should be 0 for v1)</param>
/// <param name="SubjectDn">Subject Distinguished Name</param>
/// <param name="PublicKey">Public key bytes</param>
/// <param name="PublicKeyFingerprint">SHA-256 fingerprint of public key</param>
/// <param name="SignatureAlgorithmOid">Signature algorithm OID</param>
/// <param name="SignatureAlgorithm">Signature algorithm enum</param>
/// <param name="Signature">The signature bytes</param>
/// <param name="TbsData">The To-Be-Signed (TBS) portion for verification</param>
/// <param name="Subject">Individual subject attributes</param>
public sealed record ParsedCsr(
    int Version,
    string SubjectDn,
    byte[] PublicKey,
    string PublicKeyFingerprint,
    string SignatureAlgorithmOid,
    SignatureAlgorithm SignatureAlgorithm,
    byte[] Signature,
    byte[] TbsData,
    ParsedSubject Subject);

/// <summary>
/// Parsed subject DN attributes.
/// </summary>
/// <param name="CommonName">Common Name (CN)</param>
/// <param name="SerialNumber">Serial Number (MyKad number)</param>
/// <param name="Country">Country code</param>
/// <param name="Organization">Organization name</param>
/// <param name="EmailAddress">Email address</param>
public sealed record ParsedSubject(
    string? CommonName,
    string? SerialNumber,
    string? Country,
    string? Organization,
    string? EmailAddress);
