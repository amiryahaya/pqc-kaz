namespace Antrapol.IdP.Identity.Domain.Enums;

/// <summary>
/// Represents the status of a pending registration.
/// Follows the registration flow: Profile → Email OTP → Phone OTP → CSR → Certificate → Complete
/// </summary>
public enum RegistrationStatus
{
    /// <summary>
    /// Registration initiated, awaiting email verification.
    /// </summary>
    Pending = 0,

    /// <summary>
    /// Email verified via OTP, awaiting phone verification.
    /// </summary>
    EmailVerified = 1,

    /// <summary>
    /// Phone verified via OTP, awaiting CSR submission.
    /// </summary>
    PhoneVerified = 2,

    /// <summary>
    /// CSR submitted, awaiting certificate issuance.
    /// </summary>
    CsrSubmitted = 3,

    /// <summary>
    /// Certificates issued, awaiting device activation.
    /// </summary>
    CertificatesIssued = 4,

    /// <summary>
    /// Registration completed, user account fully activated.
    /// </summary>
    Completed = 10,

    /// <summary>
    /// Registration expired, OTP no longer valid.
    /// </summary>
    Expired = 98,

    /// <summary>
    /// Registration rejected (e.g., invalid CSR, duplicate MyKad).
    /// </summary>
    Rejected = 99
}
