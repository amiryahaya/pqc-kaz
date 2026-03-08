using Antrapol.IdP.Identity.Domain.Entities;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository for managing recovery tokens.
/// </summary>
public interface IRecoveryTokenRepository
{
    /// <summary>
    /// Creates a new recovery token.
    /// </summary>
    Task<Guid> CreateAsync(RecoveryToken token, CancellationToken ct = default);

    /// <summary>
    /// Gets a recovery token by ID.
    /// </summary>
    Task<RecoveryToken?> GetByIdAsync(Guid id, CancellationToken ct = default);

    /// <summary>
    /// Gets the active recovery token for a user.
    /// </summary>
    Task<RecoveryToken?> GetActiveByUserIdAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Gets a recovery token by user ID and token hash.
    /// </summary>
    Task<RecoveryToken?> GetByUserIdAndHashAsync(Guid userId, string tokenHash, CancellationToken ct = default);

    /// <summary>
    /// Updates a recovery token.
    /// </summary>
    Task UpdateAsync(RecoveryToken token, CancellationToken ct = default);

    /// <summary>
    /// Deactivates all recovery tokens for a user.
    /// </summary>
    /// <returns>Number of tokens deactivated</returns>
    Task<int> DeactivateAllByUserIdAsync(Guid userId, CancellationToken ct = default);
}
