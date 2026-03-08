using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.ValueObjects;
using Antrapol.IdP.SharedKernel.Entities;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents a pending user registration following the full registration flow:
/// Profile Setup → Email OTP → Phone OTP → CSR Submission → Certificate Issuance → Complete
/// </summary>
public sealed class PendingRegistration : AuditableEntity
{
    // === User Profile ===
    public string FullName { get; private set; } = null!;
    public string MyKadNumber { get; private set; } = null!;
    public Email Email { get; private set; } = null!;
    public PhoneNumber? PhoneNumber { get; private set; }

    // === Email OTP ===
    public string EmailOtpHash { get; private set; } = null!;
    public DateTimeOffset EmailOtpExpiresAt { get; private set; }
    public int EmailOtpAttempts { get; private set; }

    // === Phone OTP ===
    public string? PhoneOtpHash { get; private set; }
    public DateTimeOffset? PhoneOtpExpiresAt { get; private set; }
    public int PhoneOtpAttempts { get; private set; }

    // === Registration State ===
    public RegistrationStatus Status { get; private set; }
    public Guid TrackingId { get; private set; }

    // === Device Info (collected during registration) ===
    public string? DeviceId { get; private set; }
    public string? DeviceName { get; private set; }
    public DevicePlatform? DevicePlatform { get; private set; }
    public string? DeviceOsVersion { get; private set; }
    public string? AppVersion { get; private set; }

    private PendingRegistration() { }

    public static PendingRegistration Create(
        string fullName,
        string myKadNumber,
        Email email,
        string emailOtpHash,
        TimeSpan otpValidityDuration,
        string? deviceId = null,
        string? deviceName = null,
        DevicePlatform? devicePlatform = null,
        string? deviceOsVersion = null,
        string? appVersion = null)
    {
        var registration = new PendingRegistration
        {
            Id = Guid.CreateVersion7(),
            FullName = fullName,
            MyKadNumber = myKadNumber,
            Email = email,
            EmailOtpHash = emailOtpHash,
            EmailOtpExpiresAt = DateTimeOffset.UtcNow.Add(otpValidityDuration),
            Status = RegistrationStatus.Pending,
            TrackingId = Guid.CreateVersion7(),
            EmailOtpAttempts = 0,
            PhoneOtpAttempts = 0,
            DeviceId = deviceId,
            DeviceName = deviceName,
            DevicePlatform = devicePlatform,
            DeviceOsVersion = deviceOsVersion,
            AppVersion = appVersion
        };

        registration.SetCreated(null);
        return registration;
    }

    // Legacy factory for backward compatibility
    public static PendingRegistration Create(Email email, string otpHash, TimeSpan otpValidityDuration)
    {
        return Create(
            fullName: "Pending",
            myKadNumber: "000000000000",
            email: email,
            emailOtpHash: otpHash,
            otpValidityDuration: otpValidityDuration);
    }

    // === Backward compatibility properties ===
    [Obsolete("Use EmailOtpHash instead")]
    public string OtpHash => EmailOtpHash;

    [Obsolete("Use EmailOtpExpiresAt instead")]
    public DateTimeOffset OtpExpiresAt => EmailOtpExpiresAt;

    [Obsolete("Use EmailOtpAttempts instead")]
    public int OtpAttempts => EmailOtpAttempts;

    // === Email OTP Methods ===

    public bool IsEmailOtpExpired()
    {
        return DateTimeOffset.UtcNow > EmailOtpExpiresAt;
    }

    public bool CanVerifyEmailOtp(int maxAttempts = 5)
    {
        if (Status != RegistrationStatus.Pending)
            return false;

        if (IsEmailOtpExpired())
        {
            Status = RegistrationStatus.Expired;
            return false;
        }

        if (EmailOtpAttempts >= maxAttempts)
        {
            Status = RegistrationStatus.Expired;
            return false;
        }

        return true;
    }

    public void IncrementEmailOtpAttempts()
    {
        EmailOtpAttempts++;
    }

    public void MarkEmailVerified()
    {
        if (Status != RegistrationStatus.Pending)
            throw new InvalidOperationException("Can only verify email for pending registrations.");

        if (IsEmailOtpExpired())
            throw new InvalidOperationException("Cannot verify expired OTP.");

        Status = RegistrationStatus.EmailVerified;
        SetUpdated(null);
    }

    // === Phone OTP Methods ===

    public void SetPhoneOtp(PhoneNumber phoneNumber, string phoneOtpHash, TimeSpan otpValidityDuration)
    {
        if (Status != RegistrationStatus.EmailVerified)
            throw new InvalidOperationException("Email must be verified before setting phone OTP.");

        PhoneNumber = phoneNumber;
        PhoneOtpHash = phoneOtpHash;
        PhoneOtpExpiresAt = DateTimeOffset.UtcNow.Add(otpValidityDuration);
        PhoneOtpAttempts = 0;
        SetUpdated(null);
    }

    public bool IsPhoneOtpExpired()
    {
        return PhoneOtpExpiresAt.HasValue && DateTimeOffset.UtcNow > PhoneOtpExpiresAt.Value;
    }

    public bool CanVerifyPhoneOtp(int maxAttempts = 5)
    {
        if (Status != RegistrationStatus.EmailVerified)
            return false;

        if (PhoneOtpHash is null || PhoneOtpExpiresAt is null)
            return false;

        if (IsPhoneOtpExpired())
        {
            return false;
        }

        if (PhoneOtpAttempts >= maxAttempts)
        {
            return false;
        }

        return true;
    }

    public void IncrementPhoneOtpAttempts()
    {
        PhoneOtpAttempts++;
    }

    public void MarkPhoneVerified()
    {
        if (Status != RegistrationStatus.EmailVerified)
            throw new InvalidOperationException("Can only verify phone after email is verified.");

        if (PhoneOtpHash is null)
            throw new InvalidOperationException("Phone OTP was never set.");

        if (IsPhoneOtpExpired())
            throw new InvalidOperationException("Cannot verify expired phone OTP.");

        Status = RegistrationStatus.PhoneVerified;
        SetUpdated(null);
    }

    // === CSR and Certificate Methods ===

    public void MarkCsrSubmitted()
    {
        if (Status != RegistrationStatus.PhoneVerified)
            throw new InvalidOperationException("Phone must be verified before submitting CSR.");

        Status = RegistrationStatus.CsrSubmitted;
        SetUpdated(null);
    }

    public void MarkCertificatesIssued()
    {
        if (Status != RegistrationStatus.CsrSubmitted)
            throw new InvalidOperationException("CSR must be submitted before certificates are issued.");

        Status = RegistrationStatus.CertificatesIssued;
        SetUpdated(null);
    }

    public void MarkCompleted()
    {
        if (Status != RegistrationStatus.CertificatesIssued)
            throw new InvalidOperationException("Certificates must be issued before completing registration.");

        Status = RegistrationStatus.Completed;
        SetUpdated(null);
    }

    public void MarkRejected(string? reason = null)
    {
        Status = RegistrationStatus.Rejected;
        SetUpdated(null);
    }

    // === Backward Compatibility ===

    [Obsolete("Use IsEmailOtpExpired instead")]
    public bool IsOtpExpired() => IsEmailOtpExpired();

    [Obsolete("Use CanVerifyEmailOtp instead")]
    public bool CanVerifyOtp(int maxAttempts = 5) => CanVerifyEmailOtp(maxAttempts);

    [Obsolete("Use IncrementEmailOtpAttempts instead")]
    public void IncrementOtpAttempts() => IncrementEmailOtpAttempts();

    // === Reconstitution ===

    public static PendingRegistration Reconstitute(
        Guid id,
        string fullName,
        string myKadNumber,
        Email email,
        PhoneNumber? phoneNumber,
        string emailOtpHash,
        DateTimeOffset emailOtpExpiresAt,
        int emailOtpAttempts,
        string? phoneOtpHash,
        DateTimeOffset? phoneOtpExpiresAt,
        int phoneOtpAttempts,
        RegistrationStatus status,
        Guid trackingId,
        string? deviceId,
        string? deviceName,
        DevicePlatform? devicePlatform,
        string? deviceOsVersion,
        string? appVersion,
        DateTimeOffset createdAt,
        Guid? createdBy,
        DateTimeOffset? updatedAt,
        Guid? updatedBy,
        int version)
    {
        return new PendingRegistration
        {
            Id = id,
            FullName = fullName,
            MyKadNumber = myKadNumber,
            Email = email,
            PhoneNumber = phoneNumber,
            EmailOtpHash = emailOtpHash,
            EmailOtpExpiresAt = emailOtpExpiresAt,
            EmailOtpAttempts = emailOtpAttempts,
            PhoneOtpHash = phoneOtpHash,
            PhoneOtpExpiresAt = phoneOtpExpiresAt,
            PhoneOtpAttempts = phoneOtpAttempts,
            Status = status,
            TrackingId = trackingId,
            DeviceId = deviceId,
            DeviceName = deviceName,
            DevicePlatform = devicePlatform,
            DeviceOsVersion = deviceOsVersion,
            AppVersion = appVersion,
            CreatedAt = createdAt,
            CreatedBy = createdBy,
            UpdatedAt = updatedAt,
            UpdatedBy = updatedBy,
            Version = version
        };
    }

    // Legacy reconstitute for backward compatibility
    public static PendingRegistration Reconstitute(
        Guid id,
        Email email,
        string otpHash,
        DateTimeOffset otpExpiresAt,
        RegistrationStatus status,
        Guid trackingId,
        int otpAttempts,
        DateTimeOffset createdAt,
        Guid? createdBy,
        DateTimeOffset? updatedAt,
        Guid? updatedBy,
        int version)
    {
        return Reconstitute(
            id: id,
            fullName: "Legacy",
            myKadNumber: "000000000000",
            email: email,
            phoneNumber: null,
            emailOtpHash: otpHash,
            emailOtpExpiresAt: otpExpiresAt,
            emailOtpAttempts: otpAttempts,
            phoneOtpHash: null,
            phoneOtpExpiresAt: null,
            phoneOtpAttempts: 0,
            status: status,
            trackingId: trackingId,
            deviceId: null,
            deviceName: null,
            devicePlatform: null,
            deviceOsVersion: null,
            appVersion: null,
            createdAt: createdAt,
            createdBy: createdBy,
            updatedAt: updatedAt,
            updatedBy: updatedBy,
            version: version);
    }
}
