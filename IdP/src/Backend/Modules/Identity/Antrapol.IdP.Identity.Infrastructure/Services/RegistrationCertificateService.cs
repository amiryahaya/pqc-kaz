using Microsoft.Extensions.Logging;
using Antrapol.IdP.Certificate.Application.Interfaces;
using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.Certificate.Domain.Interfaces;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Infrastructure.Services;

/// <summary>
/// Implementation of IRegistrationCertificateService that integrates
/// with the Certificate module for certificate issuance.
/// </summary>
public sealed partial class RegistrationCertificateService : IRegistrationCertificateService
{
    private readonly ICsrRequestRepository _csrRepository;
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly ICertificateIssuanceService _certificateIssuanceService;
    private readonly ICertificateRepository _certificateRepository;
    private readonly ILogger<RegistrationCertificateService> _logger;

    // Default validity period for end-entity certificates (1 year)
    private static readonly TimeSpan DefaultCertificateValidity = TimeSpan.FromDays(365);

    [LoggerMessage(Level = LogLevel.Information, Message = "Issuing certificates for registration {RegistrationId}")]
    private partial void LogIssuingCertificates(Guid registrationId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Successfully issued device certificate {CertificateId} and user certificate {UserCertificateId} for registration {RegistrationId}")]
    private partial void LogCertificatesIssued(Guid certificateId, Guid userCertificateId, Guid registrationId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "CSR requests not found for registration {RegistrationId}")]
    private partial void LogCsrNotFound(Guid registrationId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to issue certificate for registration {RegistrationId}: {ErrorMessage}")]
    private partial void LogCertificateIssuanceFailed(Guid registrationId, string errorMessage);

    public RegistrationCertificateService(
        ICsrRequestRepository csrRepository,
        IPendingRegistrationRepository registrationRepository,
        ICertificateIssuanceService certificateIssuanceService,
        ICertificateRepository certificateRepository,
        ILogger<RegistrationCertificateService> logger)
    {
        _csrRepository = csrRepository;
        _registrationRepository = registrationRepository;
        _certificateIssuanceService = certificateIssuanceService;
        _certificateRepository = certificateRepository;
        _logger = logger;
    }

    public async Task<Result<IssuedRegistrationCertificatesDto>> IssueCertificatesAsync(
        Guid registrationId,
        CancellationToken ct = default)
    {
        LogIssuingCertificates(registrationId);

        // Get pending registration
        var registration = await _registrationRepository.GetByIdAsync(registrationId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        // Verify registration status
        if (registration.Status != RegistrationStatus.CsrSubmitted)
        {
            return Error.Validation("Registration.InvalidStatus",
                $"Cannot issue certificates. Expected status CsrSubmitted, got {registration.Status}.");
        }

        // Get CSR requests
        var csrRequests = await _csrRepository.GetByRegistrationIdAsync(registrationId, ct);
        var deviceCsr = csrRequests.FirstOrDefault(c => c.Type == CsrType.Device);
        var userCsr = csrRequests.FirstOrDefault(c => c.Type == CsrType.User);

        if (deviceCsr is null || userCsr is null)
        {
            LogCsrNotFound(registrationId);
            return Error.NotFound("CSR.NotFound", "Device or User CSR not found for this registration.");
        }

        // Issue device certificate
        var deviceCertResult = await IssueSingleCertificateAsync(
            deviceCsr, CertificateType.EndEntitySigning, ct);

        if (deviceCertResult.IsFailure)
        {
            LogCertificateIssuanceFailed(registrationId, deviceCertResult.Error.Message);
            return deviceCertResult.Error;
        }

        // Issue user certificate
        var userCertResult = await IssueSingleCertificateAsync(
            userCsr, CertificateType.EndEntitySigning, ct);

        if (userCertResult.IsFailure)
        {
            LogCertificateIssuanceFailed(registrationId, userCertResult.Error.Message);
            return userCertResult.Error;
        }

        // Update registration status
        registration.MarkCertificatesIssued();
        await _registrationRepository.UpdateAsync(registration, ct);

        var result = new IssuedRegistrationCertificatesDto(
            DeviceCertificateId: deviceCertResult.Value.CertificateId,
            DeviceCertificatePem: deviceCertResult.Value.CertificatePem,
            DeviceSerialNumber: deviceCertResult.Value.SerialNumber,
            UserCertificateId: userCertResult.Value.CertificateId,
            UserCertificatePem: userCertResult.Value.CertificatePem,
            UserSerialNumber: userCertResult.Value.SerialNumber,
            NotBefore: deviceCertResult.Value.NotBefore,
            NotAfter: deviceCertResult.Value.NotAfter);

        LogCertificatesIssued(
            deviceCertResult.Value.CertificateId,
            userCertResult.Value.CertificateId,
            registrationId);

        return result;
    }

    public async Task<IssuedRegistrationCertificatesDto?> GetCertificatesAsync(
        Guid registrationId,
        CancellationToken ct = default)
    {
        // Get CSR requests
        var csrRequests = await _csrRepository.GetByRegistrationIdAsync(registrationId, ct);
        var deviceCsr = csrRequests.FirstOrDefault(c => c.Type == CsrType.Device);
        var userCsr = csrRequests.FirstOrDefault(c => c.Type == CsrType.User);

        // Check if certificates are issued
        if (deviceCsr?.IssuedCertificateId is null || userCsr?.IssuedCertificateId is null)
        {
            return null;
        }

        // Get actual certificates from Certificate module
        var deviceCert = await _certificateRepository.GetByIdAsync(deviceCsr.IssuedCertificateId.Value, ct);
        var userCert = await _certificateRepository.GetByIdAsync(userCsr.IssuedCertificateId.Value, ct);

        if (deviceCert is null || userCert is null)
        {
            return null;
        }

        // Convert certificate data to PEM
        var devicePem = ConvertToPem(deviceCert.CertificateData);
        var userPem = ConvertToPem(userCert.CertificateData);

        return new IssuedRegistrationCertificatesDto(
            DeviceCertificateId: deviceCert.Id,
            DeviceCertificatePem: devicePem,
            DeviceSerialNumber: deviceCert.SerialNumber,
            UserCertificateId: userCert.Id,
            UserCertificatePem: userPem,
            UserSerialNumber: userCert.SerialNumber,
            NotBefore: deviceCert.NotBefore,
            NotAfter: deviceCert.NotAfter);
    }

    private async Task<Result<IssuedCertificateDto>> IssueSingleCertificateAsync(
        CsrRequest csr,
        CertificateType certificateType,
        CancellationToken ct)
    {
        // Approve CSR first
        csr.Approve();
        await _csrRepository.UpdateAsync(csr, ct);

        // Create issuance request
        var request = new CertificateIssuanceRequest(
            CsrDer: csr.CsrData,
            CertificateType: certificateType,
            SubjectDn: csr.SubjectDn,
            ValidityPeriod: DefaultCertificateValidity,
            UserId: null, // Will be linked after registration completion
            Extensions: null);

        // Issue certificate
        var result = await _certificateIssuanceService.IssueCertificateAsync(request, ct);

        if (result.IsSuccess)
        {
            // Mark CSR as issued
            csr.MarkCertificateIssued(result.Value.CertificateId);
            await _csrRepository.UpdateAsync(csr, ct);
        }

        return result;
    }

    private static string ConvertToPem(byte[] der)
    {
        var base64 = Convert.ToBase64String(der);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE-----");

        for (var i = 0; i < base64.Length; i += 64)
        {
            var length = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, length));
        }

        sb.AppendLine("-----END CERTIFICATE-----");
        return sb.ToString();
    }
}
