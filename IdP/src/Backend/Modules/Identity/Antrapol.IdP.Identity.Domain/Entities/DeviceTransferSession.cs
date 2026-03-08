using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Events;
using Antrapol.IdP.SharedKernel.Entities;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents a device transfer session for securely moving identity from one device to another.
/// Uses KAZ-KEM for encrypted key transfer between devices.
/// </summary>
public sealed class DeviceTransferSession : Entity, IHasDomainEvents
{
    private readonly List<IDomainEvent> _domainEvents = [];

    /// <summary>
    /// The user performing the transfer.
    /// </summary>
    public Guid UserId { get; private set; }

    /// <summary>
    /// The source device (current device initiating transfer).
    /// </summary>
    public Guid SourceDeviceId { get; private set; }

    /// <summary>
    /// The target device (new device receiving identity). Null until scanned.
    /// </summary>
    public Guid? TargetDeviceId { get; private set; }

    /// <summary>
    /// QR code data for the transfer (contains session info + KAZ-KEM public key).
    /// </summary>
    public string QrCodeData { get; private set; } = null!;

    /// <summary>
    /// KAZ-KEM encapsulated key for secure channel (set when new device scans QR).
    /// </summary>
    public byte[]? EncapsulatedKey { get; private set; }

    /// <summary>
    /// Current status of the transfer.
    /// </summary>
    public TransferStatus Status { get; private set; }

    /// <summary>
    /// When the transfer session was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// When the transfer session expires.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; private set; }

    /// <summary>
    /// When the transfer was completed (if successful).
    /// </summary>
    public DateTimeOffset? CompletedAt { get; private set; }

    /// <summary>
    /// Error message if transfer failed.
    /// </summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>
    /// Information about the new device (set when scanned).
    /// </summary>
    public string? TargetDeviceName { get; private set; }

    /// <summary>
    /// Platform of the new device.
    /// </summary>
    public DevicePlatform? TargetPlatform { get; private set; }

    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    private DeviceTransferSession() { }

    /// <summary>
    /// Creates a new device transfer session.
    /// </summary>
    /// <param name="userId">The user initiating the transfer.</param>
    /// <param name="sourceDeviceId">The current device ID.</param>
    /// <param name="qrCodeData">QR code data containing session info and KAZ-KEM public key.</param>
    /// <param name="validityMinutes">How long the transfer session is valid (default 5 minutes).</param>
    public static DeviceTransferSession Create(
        Guid userId,
        Guid sourceDeviceId,
        string qrCodeData,
        int validityMinutes = 5)
    {
        var now = DateTimeOffset.UtcNow;

        var session = new DeviceTransferSession
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            SourceDeviceId = sourceDeviceId,
            QrCodeData = qrCodeData,
            Status = TransferStatus.Initiated,
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(validityMinutes)
        };

        session._domainEvents.Add(new DeviceTransferSessionCreatedEvent(
            session.Id, userId, sourceDeviceId));

        return session;
    }

    /// <summary>
    /// Records when the new device scans the QR code and establishes KAZ-KEM session.
    /// </summary>
    public void EstablishSession(
        Guid targetDeviceId,
        string targetDeviceName,
        DevicePlatform targetPlatform,
        byte[] encapsulatedKey)
    {
        ValidateNotExpired();
        ValidateStatus(TransferStatus.Initiated);

        TargetDeviceId = targetDeviceId;
        TargetDeviceName = targetDeviceName;
        TargetPlatform = targetPlatform;
        EncapsulatedKey = encapsulatedKey;
        Status = TransferStatus.SessionEstablished;

        _domainEvents.Add(new DeviceTransferSessionEstablishedEvent(
            Id, UserId, SourceDeviceId, targetDeviceId, targetDeviceName));
    }

    /// <summary>
    /// Marks that key transfer is in progress.
    /// </summary>
    public void StartKeyTransfer()
    {
        ValidateNotExpired();
        ValidateStatus(TransferStatus.SessionEstablished);

        Status = TransferStatus.KeysTransferring;
    }

    /// <summary>
    /// Completes the transfer successfully.
    /// </summary>
    public void Complete()
    {
        ValidateStatus(TransferStatus.KeysTransferring);

        Status = TransferStatus.Completed;
        CompletedAt = DateTimeOffset.UtcNow;

        _domainEvents.Add(new DeviceTransferCompletedEvent(
            Id, UserId, SourceDeviceId, TargetDeviceId!.Value));
    }

    /// <summary>
    /// Cancels the transfer.
    /// </summary>
    public void Cancel()
    {
        if (Status is TransferStatus.Completed or TransferStatus.Failed)
            throw new InvalidOperationException("Cannot cancel a completed or failed transfer.");

        Status = TransferStatus.Cancelled;
        CompletedAt = DateTimeOffset.UtcNow;

        _domainEvents.Add(new DeviceTransferCancelledEvent(SourceDeviceId, UserId));
    }

    /// <summary>
    /// Marks the transfer as failed with an error message.
    /// </summary>
    public void Fail(string errorMessage)
    {
        Status = TransferStatus.Failed;
        ErrorMessage = errorMessage;
        CompletedAt = DateTimeOffset.UtcNow;

        _domainEvents.Add(new DeviceTransferFailedEvent(Id, UserId, errorMessage));
    }

    /// <summary>
    /// Checks if the session has expired.
    /// </summary>
    public bool IsExpired() => DateTimeOffset.UtcNow > ExpiresAt;

    /// <summary>
    /// Marks the session as expired.
    /// </summary>
    public void MarkExpired()
    {
        if (Status is TransferStatus.Completed or TransferStatus.Failed or TransferStatus.Cancelled)
            return;

        Status = TransferStatus.Expired;
        CompletedAt = DateTimeOffset.UtcNow;
    }

    private void ValidateNotExpired()
    {
        if (IsExpired())
            throw new InvalidOperationException("Transfer session has expired.");
    }

    private void ValidateStatus(TransferStatus expected)
    {
        if (Status != expected)
            throw new InvalidOperationException(
                $"Invalid transfer status. Expected: {expected}, Actual: {Status}");
    }

    public void ClearDomainEvents() => _domainEvents.Clear();
}
