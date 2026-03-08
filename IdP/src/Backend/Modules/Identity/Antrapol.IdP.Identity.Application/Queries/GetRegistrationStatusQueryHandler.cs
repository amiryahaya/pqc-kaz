using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.SharedKernel.Handlers;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Application.Queries;

public sealed class GetRegistrationStatusQueryHandler : IQueryHandler<GetRegistrationStatusQuery, RegistrationStatusDto>
{
    private readonly IPendingRegistrationRepository _registrationRepository;

    public GetRegistrationStatusQueryHandler(IPendingRegistrationRepository registrationRepository)
    {
        _registrationRepository = registrationRepository;
    }

    public async Task<Result<RegistrationStatusDto>> HandleAsync(
        GetRegistrationStatusQuery query,
        CancellationToken ct = default)
    {
        var registration = await _registrationRepository.GetByTrackingIdAsync(query.TrackingId, ct);
        if (registration is null)
        {
            return Error.NotFound("Registration.NotFound", "Registration not found.");
        }

        return new RegistrationStatusDto(
            registration.TrackingId,
            registration.Email.Value,
            registration.FullName,
            registration.PhoneNumber?.Value,
            registration.Status,
            registration.CreatedAt,
            registration.EmailOtpExpiresAt);
    }
}
