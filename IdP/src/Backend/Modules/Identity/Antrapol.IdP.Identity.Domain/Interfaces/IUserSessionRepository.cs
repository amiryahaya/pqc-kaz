using Antrapol.IdP.Identity.Domain.Entities;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for UserSession entity.
/// </summary>
public interface IUserSessionRepository
{
    Task<UserSession?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<UserSession?> GetByRefreshTokenHashAsync(string refreshTokenHash, CancellationToken ct = default);
    Task<IReadOnlyList<UserSession>> GetActiveByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task<Guid> CreateAsync(UserSession session, CancellationToken ct = default);
    Task UpdateAsync(UserSession session, CancellationToken ct = default);
    Task DeleteAsync(Guid id, CancellationToken ct = default);
    Task RevokeAllByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task DeleteExpiredAsync(CancellationToken ct = default);
}
