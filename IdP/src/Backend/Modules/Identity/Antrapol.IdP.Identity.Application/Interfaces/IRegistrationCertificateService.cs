using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Interfaces;

/// <summary>
/// Service for issuing certificates during registration flow.
/// Abstracts the Certificate module integration from Identity module.
/// </summary>
public interface IRegistrationCertificateService
{
    /// <summary>
    /// Issues certificates for a registration's CSRs (device and user certificates).
    /// </summary>
    /// <param name="registrationId">The registration ID</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Result containing issued certificate information</returns>
    Task<Result<IssuedRegistrationCertificatesDto>> IssueCertificatesAsync(
        Guid registrationId,
        CancellationToken ct = default);

    /// <summary>
    /// Gets issued certificates for a registration.
    /// </summary>
    /// <param name="registrationId">The registration ID</param>
    /// <param name="ct">Cancellation token</param>
    /// <returns>Certificates if issued, null otherwise</returns>
    Task<IssuedRegistrationCertificatesDto?> GetCertificatesAsync(
        Guid registrationId,
        CancellationToken ct = default);
}

/// <summary>
/// Result of certificate issuance during registration.
/// </summary>
public sealed record IssuedRegistrationCertificatesDto(
    Guid DeviceCertificateId,
    string DeviceCertificatePem,
    string DeviceSerialNumber,
    Guid UserCertificateId,
    string UserCertificatePem,
    string UserSerialNumber,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter);
