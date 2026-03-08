using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Events;
using Antrapol.IdP.SharedKernel.Entities;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents a user's registered device.
/// IMPORTANT: Single device policy - each user can only have ONE device at a time.
/// To change devices, a secure device transfer must be performed.
/// </summary>
public sealed class UserDevice : AuditableEntity, IHasDomainEvents
{
    private readonly List<IDomainEvent> _domainEvents = [];

    /// <summary>
    /// The user who owns this device.
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// Unique device identifier (fingerprint/attestation).
    /// </summary>
    public string DeviceId { get; private set; } = null!;

    /// <summary>
    /// Human-readable device name (e.g., "Samsung Galaxy S24").
    /// </summary>
    public string DeviceName { get; private set; } = null!;

    /// <summary>
    /// Device platform/OS.
    /// </summary>
    public DevicePlatform Platform { get; private set; }

    /// <summary>
    /// OS version string.
    /// </summary>
    public string? OsVersion { get; private set; }

    /// <summary>
    /// App version installed on the device.
    /// </summary>
    public string? AppVersion { get; private set; }

    /// <summary>
    /// Device push notification token for alerts.
    /// </summary>
    public string? PushToken { get; private set; }

    /// <summary>
    /// Public key fingerprint for device attestation.
    /// </summary>
    public string PublicKeyFingerprint { get; private set; } = null!;

    /// <summary>
    /// Current status of the device.
    /// </summary>
    public DeviceStatus Status { get; private set; }

    /// <summary>
    /// Timestamp of the last successful authentication from this device.
    /// </summary>
    public DateTimeOffset? LastAuthenticatedAt { get; private set; }

    /// <summary>
    /// IP address of the last authentication.
    /// </summary>
    public string? LastIpAddress { get; private set; }

    /// <summary>
    /// Geographic location of the last authentication (if available).
    /// </summary>
    public string? LastLocation { get; private set; }

    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    private UserDevice() { }

    /// <summary>
    /// Creates a new device registration for a user.
    /// This should only be called when no existing device exists (new registration)
    /// or after a successful device transfer (old device deactivated).
    /// </summary>
    public static UserDevice Create(
        Guid userId,
        string deviceId,
        string deviceName,
        DevicePlatform platform,
        string publicKeyFingerprint,
        string? osVersion = null,
        string? appVersion = null,
        string? pushToken = null,
        Guid? createdBy = null)
    {
        var device = new UserDevice
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            DeviceId = deviceId,
            DeviceName = deviceName,
            Platform = platform,
            PublicKeyFingerprint = publicKeyFingerprint,
            OsVersion = osVersion,
            AppVersion = appVersion,
            PushToken = pushToken,
            Status = DeviceStatus.Active
        };

        device.SetCreated(createdBy ?? userId);
        device._domainEvents.Add(new DeviceRegisteredEvent(device.Id, userId, deviceName, platform));

        return device;
    }

    /// <summary>
    /// Records a successful authentication from this device.
    /// </summary>
    public void RecordAuthentication(string? ipAddress = null, string? location = null)
    {
        if (Status != DeviceStatus.Active)
            throw new InvalidOperationException("Cannot authenticate from an inactive device.");

        LastAuthenticatedAt = DateTimeOffset.UtcNow;
        LastIpAddress = ipAddress;
        LastLocation = location;
    }

    /// <summary>
    /// Updates device information (app version, push token, etc.).
    /// </summary>
    public void UpdateInfo(string? appVersion = null, string? pushToken = null)
    {
        if (appVersion is not null)
            AppVersion = appVersion;

        if (pushToken is not null)
            PushToken = pushToken;

        SetUpdated(UserId);
    }

    /// <summary>
    /// Initiates a device transfer - locks the device until transfer completes.
    /// </summary>
    public void InitiateTransfer()
    {
        if (Status != DeviceStatus.Active)
            throw new InvalidOperationException("Can only initiate transfer from an active device.");

        Status = DeviceStatus.TransferPending;
        SetUpdated(UserId);
        _domainEvents.Add(new DeviceTransferInitiatedEvent(Id, UserId));
    }

    /// <summary>
    /// Cancels a pending transfer and restores the device to active status.
    /// </summary>
    public void CancelTransfer()
    {
        if (Status != DeviceStatus.TransferPending)
            throw new InvalidOperationException("No transfer in progress to cancel.");

        Status = DeviceStatus.Active;
        SetUpdated(UserId);
        _domainEvents.Add(new DeviceTransferCancelledEvent(Id, UserId));
    }

    /// <summary>
    /// Deactivates this device after successful transfer to a new device.
    /// Keys should be securely erased from this device after this call.
    /// </summary>
    public void Deactivate()
    {
        if (Status == DeviceStatus.Deactivated)
            return;

        Status = DeviceStatus.Deactivated;
        SetDeleted(UserId);
        _domainEvents.Add(new DeviceDeactivatedEvent(Id, UserId));
    }

    public void ClearDomainEvents() => _domainEvents.Clear();
}
