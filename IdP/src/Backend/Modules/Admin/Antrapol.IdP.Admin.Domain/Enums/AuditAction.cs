namespace Antrapol.IdP.Admin.Domain.Enums;

/// <summary>
/// Represents the type of audit action.
/// </summary>
public enum AuditAction
{
    // User actions
    UserCreated = 100,
    UserUpdated = 101,
    UserDeleted = 102,
    UserLoggedIn = 103,
    UserLoggedOut = 104,
    UserLockedOut = 105,
    UserUnlocked = 106,
    UserSuspended = 107,
    UserActivated = 108,

    // Credential actions
    CredentialAdded = 200,
    CredentialRemoved = 201,
    CredentialUsed = 202,

    // Session actions
    SessionCreated = 300,
    SessionRevoked = 301,
    SessionExpired = 302,

    // Certificate actions
    CertificateIssued = 400,
    CertificateRevoked = 401,
    CertificateSuspended = 402,
    CertificateReinstated = 403,

    // Key actions
    KeyGenerated = 500,
    KeyDisabled = 501,
    KeyEnabled = 502,
    KeyCompromised = 503,
    KeyDestroyed = 504,
    KeyUsedForSigning = 505,
    KeyUsedForEncapsulation = 506,

    // Admin actions
    AdminConfigChanged = 600,
    AdminRoleAssigned = 601,
    AdminRoleRevoked = 602
}

/// <summary>
/// Represents the severity level of an audit event.
/// </summary>
public enum AuditSeverity
{
    Info = 0,
    Warning = 1,
    Critical = 2
}
