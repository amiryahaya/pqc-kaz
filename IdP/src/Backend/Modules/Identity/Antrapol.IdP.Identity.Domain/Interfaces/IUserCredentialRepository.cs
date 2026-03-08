using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for UserCredential entity.
/// </summary>
public interface IUserCredentialRepository
{
    Task<UserCredential?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyList<UserCredential>> GetByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task<IReadOnlyList<UserCredential>> GetByUserIdAndTypeAsync(Guid userId, CredentialType type, CancellationToken ct = default);
    Task<UserCredential?> GetByCredentialDataAsync(byte[] credentialData, CancellationToken ct = default);
    Task<Guid> CreateAsync(UserCredential credential, CancellationToken ct = default);
    Task UpdateAsync(UserCredential credential, CancellationToken ct = default);
    Task DeleteAsync(Guid id, CancellationToken ct = default);
}
