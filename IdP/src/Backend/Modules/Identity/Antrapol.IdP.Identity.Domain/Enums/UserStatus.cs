namespace Antrapol.IdP.Identity.Domain.Enums;

/// <summary>
/// Represents the status of a user account.
/// </summary>
public enum UserStatus
{
    /// <summary>
    /// User is pending email/phone verification.
    /// </summary>
    PendingVerification = 0,

    /// <summary>
    /// User account is active and can authenticate.
    /// </summary>
    Active = 1,

    /// <summary>
    /// User account is suspended (temporary).
    /// </summary>
    Suspended = 2,

    /// <summary>
    /// User account is locked due to failed login attempts.
    /// </summary>
    Locked = 3,

    /// <summary>
    /// User account is deactivated (soft delete).
    /// </summary>
    Deactivated = 4
}
