namespace Antrapol.IdP.Identity.Domain.Enums;

/// <summary>
/// Represents the type of authentication credential.
/// </summary>
public enum CredentialType
{
    /// <summary>
    /// FIDO2/WebAuthn passkey credential.
    /// </summary>
    Passkey = 0,

    /// <summary>
    /// Time-based One-Time Password (TOTP).
    /// </summary>
    Totp = 1,

    /// <summary>
    /// Recovery code for account recovery.
    /// </summary>
    RecoveryCode = 2,

    /// <summary>
    /// Hardware security key (e.g., YubiKey).
    /// </summary>
    SecurityKey = 3
}
