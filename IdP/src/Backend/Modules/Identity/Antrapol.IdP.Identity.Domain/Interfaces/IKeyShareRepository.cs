using Antrapol.IdP.Identity.Domain.Entities;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for KeyShare aggregate.
/// </summary>
public interface IKeyShareRepository
{
    Task<KeyShare?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<KeyShare>> GetByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task<IReadOnlyList<KeyShare>> GetByRegistrationIdAsync(Guid registrationId, CancellationToken ct = default);
    Task<KeyShare?> GetActiveControlShareAsync(Guid userId, CancellationToken ct = default);
    Task<KeyShare?> GetActiveRecoveryShareAsync(Guid userId, CancellationToken ct = default);
    Task<Guid> CreateAsync(KeyShare keyShare, CancellationToken ct = default);
    Task UpdateAsync(KeyShare keyShare, CancellationToken ct = default);
}
