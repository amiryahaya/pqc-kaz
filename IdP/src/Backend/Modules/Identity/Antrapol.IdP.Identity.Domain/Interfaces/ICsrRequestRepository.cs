using Antrapol.IdP.Identity.Domain.Entities;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for CsrRequest aggregate.
/// </summary>
public interface ICsrRequestRepository
{
    Task<CsrRequest?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<CsrRequest>> GetByRegistrationIdAsync(Guid registrationId, CancellationToken ct = default);
    Task<CsrRequest?> GetByPublicKeyFingerprintAsync(string fingerprint, CancellationToken ct = default);
    Task<Guid> CreateAsync(CsrRequest csr, CancellationToken ct = default);
    Task UpdateAsync(CsrRequest csr, CancellationToken ct = default);
}
