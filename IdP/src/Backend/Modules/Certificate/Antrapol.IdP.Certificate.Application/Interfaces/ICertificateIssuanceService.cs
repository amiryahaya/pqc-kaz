using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Certificate.Application.Interfaces;

/// <summary>
/// Service for issuing X.509 certificates from CSRs using KAZ-SIGN-256.
/// </summary>
public interface ICertificateIssuanceService
{
    /// <summary>
    /// Issues a certificate from a CSR.
    /// </summary>
    /// <param name="request">Certificate issuance request</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Issued certificate result</returns>
    Task<Result<IssuedCertificateDto>> IssueCertificateAsync(
        CertificateIssuanceRequest request,
        CancellationToken ct = default);

    /// <summary>
    /// Validates a CSR and extracts its information.
    /// </summary>
    /// <param name="csrDer">CSR in DER format</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>CSR validation result with extracted info</returns>
    Task<Result<CsrValidationResult>> ValidateCsrAsync(
        byte[] csrDer,
        CancellationToken ct = default);

    /// <summary>
    /// Verifies a certificate chain.
    /// </summary>
    Task<Result<bool>> VerifyCertificateChainAsync(
        byte[] certificateDer,
        CancellationToken ct = default);
}

/// <summary>
/// Request to issue a certificate.
/// </summary>
public sealed record CertificateIssuanceRequest(
    byte[] CsrDer,
    CertificateType CertificateType,
    string SubjectDn,
    TimeSpan ValidityPeriod,
    Guid? UserId = null,
    Dictionary<string, string>? Extensions = null);

/// <summary>
/// Result of CSR validation.
/// </summary>
public sealed record CsrValidationResult(
    bool IsValid,
    string SubjectDn,
    byte[] PublicKey,
    string PublicKeyFingerprint,
    SignatureAlgorithm Algorithm,
    string? ValidationError = null);

/// <summary>
/// Result of certificate issuance.
/// </summary>
public sealed record IssuedCertificateDto(
    Guid CertificateId,
    string SerialNumber,
    byte[] CertificateDer,
    string CertificatePem,
    string SubjectDn,
    string IssuerDn,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string PublicKeyFingerprint);
