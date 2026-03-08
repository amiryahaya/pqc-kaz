using Antrapol.IdP.Admin.Domain.Enums;

namespace Antrapol.IdP.Admin.Application.DTOs;

public sealed record AuditLogDto(
    Guid Id,
    AuditAction Action,
    AuditSeverity Severity,
    Guid? ActorId,
    string? ActorEmail,
    Guid? TargetId,
    string? TargetType,
    string Description,
    string? IpAddress,
    string? UserAgent,
    DateTimeOffset Timestamp);

public sealed record AuditLogSearchRequest(
    string? Query,
    AuditAction? Action,
    AuditSeverity? Severity,
    DateTimeOffset? From,
    DateTimeOffset? To,
    int Limit = 100,
    int Offset = 0);

public sealed record AuditLogSummaryDto(
    long TotalCount,
    long InfoCount,
    long WarningCount,
    long CriticalCount,
    DateTimeOffset? LastEventAt);
