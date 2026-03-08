using Antrapol.IdP.SharedKernel.Entities;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents a recovery token for account recovery.
/// The recovery token contains the encrypted part_recovery share and metadata.
/// User must save this token offline for emergency recovery.
/// </summary>
public sealed class RecoveryToken : AuditableEntity
{
    /// <summary>
    /// Reference to the user who owns this recovery token.
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// Token version (incremented when recovery password changes).
    /// </summary>
    public int TokenVersion { get; private set; }

    /// <summary>
    /// Hash of the token for verification (SHA-256).
    /// The actual token is never stored, only its hash.
    /// </summary>
    public string TokenHash { get; private set; } = null!;

    /// <summary>
    /// Reference to the associated recovery key share.
    /// </summary>
    public Guid KeyShareId { get; private set; }

    /// <summary>
    /// Whether this token is still active.
    /// </summary>
    public bool IsActive { get; private set; }

    /// <summary>
    /// Timestamp when this token was last used for recovery.
    /// </summary>
    public DateTimeOffset? LastUsedAt { get; private set; }

    /// <summary>
    /// Number of times this token has been used for recovery.
    /// </summary>
    public int UseCount { get; private set; }

    /// <summary>
    /// IP address when recovery was initiated.
    /// </summary>
    public string? LastRecoveryIp { get; private set; }

    private RecoveryToken() { }

    public static RecoveryToken Create(
        Guid userId,
        string tokenHash,
        Guid keyShareId,
        int tokenVersion = 1,
        Guid? createdBy = null)
    {
        var token = new RecoveryToken
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            TokenVersion = tokenVersion,
            TokenHash = tokenHash,
            KeyShareId = keyShareId,
            IsActive = true,
            UseCount = 0
        };

        token.SetCreated(createdBy);
        return token;
    }

    /// <summary>
    /// Records that this token was used for a recovery operation.
    /// </summary>
    public void RecordUsage(string? ipAddress = null)
    {
        LastUsedAt = DateTimeOffset.UtcNow;
        UseCount++;
        LastRecoveryIp = ipAddress;
        SetUpdated(null);
    }

    /// <summary>
    /// Deactivates this recovery token (e.g., when generating a new one).
    /// </summary>
    public void Deactivate(Guid? deactivatedBy = null)
    {
        IsActive = false;
        SetUpdated(deactivatedBy);
    }

    /// <summary>
    /// Verifies if the provided token hash matches this token.
    /// </summary>
    public bool VerifyTokenHash(string hash)
    {
        return string.Equals(TokenHash, hash, StringComparison.OrdinalIgnoreCase);
    }
}
