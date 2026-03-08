using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for device transfer session operations.
/// </summary>
public interface IDeviceTransferSessionRepository
{
    /// <summary>
    /// Gets a transfer session by its ID.
    /// </summary>
    Task<DeviceTransferSession?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an active (non-completed) transfer session for a user.
    /// </summary>
    Task<DeviceTransferSession?> GetActiveSessionByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a transfer session by its QR code data (for scanning).
    /// </summary>
    Task<DeviceTransferSession?> GetByQrCodeDataAsync(
        string qrCodeData,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a user has an active transfer session.
    /// </summary>
    Task<bool> HasActiveSessionAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new transfer session.
    /// </summary>
    Task<DeviceTransferSession> CreateAsync(
        DeviceTransferSession session,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing transfer session.
    /// </summary>
    Task UpdateAsync(DeviceTransferSession session, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets transfer history for a user.
    /// </summary>
    Task<IReadOnlyList<DeviceTransferSession>> GetTransferHistoryByUserIdAsync(
        Guid userId,
        int limit = 10,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all expired sessions that need to be marked as expired.
    /// </summary>
    Task<IReadOnlyList<DeviceTransferSession>> GetExpiredSessionsAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks expired sessions as expired status.
    /// </summary>
    Task MarkExpiredSessionsAsync(CancellationToken cancellationToken = default);
}
