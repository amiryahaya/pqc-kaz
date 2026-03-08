using Antrapol.IdP.Identity.Domain.Enums;

namespace Antrapol.IdP.Identity.Application.DTOs;

public sealed record InitiateRegistrationDto(
    Guid TrackingId,
    string Email,
    DateTimeOffset ExpiresAt);

public sealed record VerifyEmailOtpDto(
    Guid RegistrationId,
    RegistrationStatus Status,
    string Message);

public sealed record SendPhoneOtpDto(
    Guid RegistrationId,
    string PhoneNumber,
    DateTimeOffset ExpiresAt);

public sealed record VerifyPhoneOtpDto(
    Guid RegistrationId,
    RegistrationStatus Status,
    string Message);

public sealed record SubmitCsrDto(
    Guid TrackingId,
    Guid DeviceCsrId,
    Guid UserCsrId,
    RegistrationStatus Status,
    string Message);

public sealed record CertificateStatusDto(
    Guid TrackingId,
    RegistrationStatus Status,
    string? DeviceCertificate,      // PEM encoded (null if not yet issued)
    string? UserCertificate,        // PEM encoded (null if not yet issued)
    string? RecoveryToken,          // Base64 encoded recovery token
    string? Signature);             // Backend signature over response

public sealed record CompleteRegistrationDto(
    Guid UserId,
    string Email,
    string FullName,
    string? DisplayName,
    string Message);

public sealed record RegistrationStatusDto(
    Guid TrackingId,
    string Email,
    string FullName,
    string? PhoneNumber,
    RegistrationStatus Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt);
