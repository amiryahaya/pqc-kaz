using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Identity.Domain.Events;

// ============================================
// User Events
// ============================================

public sealed record UserCreatedEvent(Guid UserId, string Email) : DomainEvent;

public sealed record UserEmailVerifiedEvent(Guid UserId) : DomainEvent;

public sealed record UserPhoneVerifiedEvent(Guid UserId) : DomainEvent;

public sealed record UserLoggedInEvent(Guid UserId) : DomainEvent;

public sealed record UserLockedOutEvent(Guid UserId, DateTimeOffset LockoutEndAt) : DomainEvent;

public sealed record UserSuspendedEvent(Guid UserId) : DomainEvent;

public sealed record UserDeactivatedEvent(Guid UserId) : DomainEvent;

public sealed record UserCredentialAddedEvent(Guid UserId, Guid CredentialId, string CredentialType) : DomainEvent;

public sealed record UserCredentialRemovedEvent(Guid UserId, Guid CredentialId) : DomainEvent;

public sealed record UserSessionCreatedEvent(Guid UserId, Guid SessionId) : DomainEvent;

public sealed record UserSessionRevokedEvent(Guid UserId, Guid SessionId) : DomainEvent;

// ============================================
// Device Events (Single Device Policy)
// ============================================

/// <summary>
/// Raised when a new device is registered for a user.
/// Note: Due to single device policy, this replaces any previous device.
/// </summary>
public sealed record DeviceRegisteredEvent(
    Guid DeviceId,
    Guid UserId,
    string DeviceName,
    DevicePlatform Platform) : DomainEvent;

/// <summary>
/// Raised when a device transfer is initiated from the source device.
/// </summary>
public sealed record DeviceTransferInitiatedEvent(
    Guid DeviceId,
    Guid UserId) : DomainEvent;

/// <summary>
/// Raised when a device transfer is cancelled.
/// </summary>
public sealed record DeviceTransferCancelledEvent(
    Guid DeviceId,
    Guid UserId) : DomainEvent;

/// <summary>
/// Raised when a device is deactivated (after successful transfer or manual deactivation).
/// </summary>
public sealed record DeviceDeactivatedEvent(
    Guid DeviceId,
    Guid UserId) : DomainEvent;

// ============================================
// Device Transfer Session Events
// ============================================

/// <summary>
/// Raised when a new device transfer session is created (QR code generated).
/// </summary>
public sealed record DeviceTransferSessionCreatedEvent(
    Guid SessionId,
    Guid UserId,
    Guid SourceDeviceId) : DomainEvent;

/// <summary>
/// Raised when a new device scans the QR and KAZ-KEM session is established.
/// </summary>
public sealed record DeviceTransferSessionEstablishedEvent(
    Guid SessionId,
    Guid UserId,
    Guid SourceDeviceId,
    Guid TargetDeviceId,
    string TargetDeviceName) : DomainEvent;

/// <summary>
/// Raised when a device transfer completes successfully.
/// </summary>
public sealed record DeviceTransferCompletedEvent(
    Guid SessionId,
    Guid UserId,
    Guid SourceDeviceId,
    Guid TargetDeviceId) : DomainEvent;

/// <summary>
/// Raised when a device transfer fails.
/// </summary>
public sealed record DeviceTransferFailedEvent(
    Guid SessionId,
    Guid UserId,
    string ErrorMessage) : DomainEvent;
