using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.ValueObjects;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for PendingRegistration aggregate.
/// </summary>
public interface IPendingRegistrationRepository
{
    Task<PendingRegistration?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<PendingRegistration?> GetByTrackingIdAsync(Guid trackingId, CancellationToken ct = default);
    Task<PendingRegistration?> GetByEmailAsync(Email email, CancellationToken ct = default);
    Task<PendingRegistration?> GetByMyKadAsync(string myKadNumber, CancellationToken ct = default);
    Task<Guid> CreateAsync(PendingRegistration registration, CancellationToken ct = default);
    Task UpdateAsync(PendingRegistration registration, CancellationToken ct = default);
    Task DeleteAsync(Guid id, CancellationToken ct = default);
}
