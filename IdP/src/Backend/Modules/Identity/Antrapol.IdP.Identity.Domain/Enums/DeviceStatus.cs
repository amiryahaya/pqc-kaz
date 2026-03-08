namespace Antrapol.IdP.Identity.Domain.Enums;

/// <summary>
/// Represents the status of a user's device.
/// Note: Single device policy - each user can only have ONE device at a time.
/// </summary>
public enum DeviceStatus
{
    /// <summary>
    /// Device is active and can be used for authentication.
    /// </summary>
    Active = 0,

    /// <summary>
    /// Device transfer is pending - device is locked until transfer completes or is cancelled.
    /// </summary>
    TransferPending = 1,

    /// <summary>
    /// Device has been deactivated after transfer to a new device.
    /// </summary>
    Deactivated = 2
}

/// <summary>
/// Represents the status of a device transfer session.
/// </summary>
public enum TransferStatus
{
    /// <summary>
    /// Transfer initiated, waiting for new device to scan QR code.
    /// </summary>
    Initiated = 0,

    /// <summary>
    /// New device has scanned QR, KAZ-KEM session established.
    /// </summary>
    SessionEstablished = 1,

    /// <summary>
    /// Keys are being transferred (encrypted with KAZ-KEM).
    /// </summary>
    KeysTransferring = 2,

    /// <summary>
    /// Transfer completed successfully.
    /// </summary>
    Completed = 3,

    /// <summary>
    /// Transfer was cancelled by user.
    /// </summary>
    Cancelled = 4,

    /// <summary>
    /// Transfer expired (timeout).
    /// </summary>
    Expired = 5,

    /// <summary>
    /// Transfer failed due to an error.
    /// </summary>
    Failed = 6
}

/// <summary>
/// Represents the platform/OS of a device.
/// </summary>
public enum DevicePlatform
{
    /// <summary>
    /// Android device.
    /// </summary>
    Android = 0,

    /// <summary>
    /// iOS device.
    /// </summary>
    iOS = 1,

    /// <summary>
    /// Windows device.
    /// </summary>
    Windows = 2,

    /// <summary>
    /// macOS device.
    /// </summary>
    MacOS = 3,

    /// <summary>
    /// Unknown platform.
    /// </summary>
    Unknown = 99
}
