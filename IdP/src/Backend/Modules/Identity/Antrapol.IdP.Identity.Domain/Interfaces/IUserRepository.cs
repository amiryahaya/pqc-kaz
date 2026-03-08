using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.ValueObjects;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for User aggregate.
/// </summary>
public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<User?> GetByEmailAsync(Email email, CancellationToken ct = default);
    Task<User?> GetByPhoneAsync(PhoneNumber phone, CancellationToken ct = default);
    Task<User?> GetByMyKadAsync(string myKadNumber, CancellationToken ct = default);
    Task<bool> ExistsAsync(Email email, CancellationToken ct = default);
    Task<bool> ExistsByMyKadAsync(string myKadNumber, CancellationToken ct = default);
    Task<Guid> CreateAsync(User user, CancellationToken ct = default);
    Task UpdateAsync(User user, CancellationToken ct = default);
    Task DeleteAsync(Guid id, CancellationToken ct = default);
}
