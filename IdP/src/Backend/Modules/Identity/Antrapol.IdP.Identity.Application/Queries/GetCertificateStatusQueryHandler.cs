using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Queries;

/// <summary>
/// Handler for querying certificate issuance status during registration.
/// Step 6 of the registration flow: Poll for certificate status.
/// </summary>
public sealed class GetCertificateStatusQueryHandler : IQueryHandler<GetCertificateStatusQuery, CertificateStatusDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;
    private readonly ICsrRequestRepository _csrRepository;
    private readonly IRegistrationCertificateService _certificateService;

    public GetCertificateStatusQueryHandler(
        IPendingRegistrationRepository registrationRepository,
        ICsrRequestRepository csrRepository,
        IRegistrationCertificateService certificateService)
    {
        _registrationRepository = registrationRepository;
        _csrRepository = csrRepository;
        _certificateService = certificateService;
    }

    public async Task<Result<CertificateStatusDto>> HandleAsync(
        GetCertificateStatusQuery query,
        CancellationToken ct = default)
    {
        var registration = await _registrationRepository.GetByTrackingIdAsync(query.TrackingId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        // Only allow polling if CSR has been submitted
        if (registration.Status < RegistrationStatus.CsrSubmitted)
        {
            return Error.Validation("Registration.InvalidStatus",
                "Cannot check certificate status. CSR has not been submitted yet.");
        }

        // Get CSR requests for this registration
        var csrRequests = await _csrRepository.GetByRegistrationIdAsync(registration.Id, ct);

        var deviceCsr = csrRequests.FirstOrDefault(c => c.Type == CsrType.Device);
        var userCsr = csrRequests.FirstOrDefault(c => c.Type == CsrType.User);

        // Check if both certificates are issued
        bool bothIssued = deviceCsr?.Status == CsrStatus.Issued && userCsr?.Status == CsrStatus.Issued;

        string? deviceCertPem = null;
        string? userCertPem = null;
        string? recoveryToken = null;
        string? signature = null;

        // If certificates are issued, fetch the actual certificate data
        if (bothIssued && registration.Status == RegistrationStatus.CertificatesIssued)
        {
            var certificates = await _certificateService.GetCertificatesAsync(registration.Id, ct);
            if (certificates is not null)
            {
                deviceCertPem = certificates.DeviceCertificatePem;
                userCertPem = certificates.UserCertificatePem;
                // Recovery token would be generated and stored separately
                // Signature would be created by signing the response with CA key
            }
        }

        return new CertificateStatusDto(
            TrackingId: query.TrackingId,
            Status: registration.Status,
            DeviceCertificate: deviceCertPem,
            UserCertificate: userCertPem,
            RecoveryToken: recoveryToken,
            Signature: signature);
    }
}
