using Antrapol.IdP.Identity.Domain.Enums;

namespace Antrapol.IdP.Identity.Application.DTOs;

public sealed record UserDto(
    Guid Id,
    string Email,
    string? PhoneNumber,
    string? DisplayName,
    UserStatus Status,
    bool EmailVerified,
    bool PhoneVerified,
    DateTimeOffset? LastLoginAt,
    DateTimeOffset CreatedAt);

public sealed record UserCredentialDto(
    Guid Id,
    CredentialType Type,
    string Name,
    string? DeviceInfo,
    DateTimeOffset? LastUsedAt,
    int UseCount,
    bool IsEnabled,
    DateTimeOffset CreatedAt);

public sealed record UserSessionDto(
    Guid Id,
    string? IpAddress,
    string? UserAgent,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    bool IsCurrent);
