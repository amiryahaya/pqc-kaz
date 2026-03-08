using Antrapol.IdP.Admin.Domain.Enums;
using Antrapol.IdP.SharedKernel.Entities;

namespace Antrapol.IdP.Admin.Domain.Entities;

/// <summary>
/// Represents an audit log entry.
/// </summary>
public sealed class AuditLog : Entity
{
    public AuditAction Action { get; private set; }
    public AuditSeverity Severity { get; private set; }
    public Guid? ActorId { get; private set; }
    public string? ActorEmail { get; private set; }
    public Guid? TargetId { get; private set; }
    public string? TargetType { get; private set; }
    public string Description { get; private set; } = null!;
    public string? IpAddress { get; private set; }
    public string? UserAgent { get; private set; }
    public string? AdditionalData { get; private set; }
    public DateTimeOffset Timestamp { get; private set; }

    private AuditLog() { }

    public static AuditLog Create(
        AuditAction action,
        string description,
        Guid? actorId = null,
        string? actorEmail = null,
        Guid? targetId = null,
        string? targetType = null,
        string? ipAddress = null,
        string? userAgent = null,
        string? additionalData = null,
        AuditSeverity severity = AuditSeverity.Info)
    {
        return new AuditLog
        {
            Id = Guid.CreateVersion7(),
            Action = action,
            Severity = severity,
            ActorId = actorId,
            ActorEmail = actorEmail,
            TargetId = targetId,
            TargetType = targetType,
            Description = description,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            AdditionalData = additionalData,
            Timestamp = DateTimeOffset.UtcNow
        };
    }
}
