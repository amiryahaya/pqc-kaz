using Antrapol.IdP.SharedKernel.Entities;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents an active user session.
/// </summary>
public sealed class UserSession : Entity
{
    public Guid UserId { get; private set; }
    public string RefreshTokenHash { get; private set; } = null!;
    public string? IpAddress { get; private set; }
    public string? UserAgent { get; private set; }
    public string? DeviceFingerprint { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public bool IsRevoked => RevokedAt.HasValue;

    private UserSession() { }

    public static UserSession Create(
        Guid userId,
        string refreshTokenHash,
        TimeSpan duration,
        string? ipAddress = null,
        string? userAgent = null,
        string? deviceFingerprint = null)
    {
        var now = DateTimeOffset.UtcNow;

        return new UserSession
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            RefreshTokenHash = refreshTokenHash,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            DeviceFingerprint = deviceFingerprint,
            CreatedAt = now,
            ExpiresAt = now.Add(duration)
        };
    }

    public bool IsValid()
    {
        return !IsRevoked && ExpiresAt > DateTimeOffset.UtcNow;
    }

    public void Revoke()
    {
        if (!IsRevoked)
        {
            RevokedAt = DateTimeOffset.UtcNow;
        }
    }

    public void Extend(TimeSpan duration)
    {
        if (IsRevoked)
            throw new InvalidOperationException("Cannot extend a revoked session.");

        ExpiresAt = DateTimeOffset.UtcNow.Add(duration);
    }
}
