using Antrapol.IdP.Identity.Domain.Entities;

namespace Antrapol.IdP.Identity.Domain.Interfaces;

/// <summary>
/// Repository interface for user device operations.
/// Note: Single device policy - each user can only have ONE active device.
/// </summary>
public interface IUserDeviceRepository
{
    /// <summary>
    /// Gets a device by its ID.
    /// </summary>
    Task<UserDevice?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the active device for a user.
    /// Due to single device policy, this returns at most one device.
    /// </summary>
    Task<UserDevice?> GetActiveDeviceByUserIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a device by its device fingerprint/ID.
    /// </summary>
    Task<UserDevice?> GetByDeviceIdAsync(string deviceId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a user has an active device registered.
    /// </summary>
    Task<bool> HasActiveDeviceAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new device registration.
    /// </summary>
    Task<UserDevice> CreateAsync(UserDevice device, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing device.
    /// </summary>
    Task UpdateAsync(UserDevice device, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets device history for a user (including deactivated devices).
    /// </summary>
    Task<IReadOnlyList<UserDevice>> GetDeviceHistoryByUserIdAsync(
        Guid userId,
        int limit = 10,
        CancellationToken cancellationToken = default);
}
