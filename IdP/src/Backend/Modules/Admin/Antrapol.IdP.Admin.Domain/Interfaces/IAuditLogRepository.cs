using Antrapol.IdP.Admin.Domain.Entities;
using Antrapol.IdP.Admin.Domain.Enums;

namespace Antrapol.IdP.Admin.Domain.Interfaces;

/// <summary>
/// Repository interface for AuditLog entity.
/// </summary>
public interface IAuditLogRepository
{
    Task<AuditLog?> GetByIdAsync(Guid id, CancellationToken ct = default);

    Task<IReadOnlyList<AuditLog>> GetByActorIdAsync(
        Guid actorId,
        int limit = 100,
        int offset = 0,
        CancellationToken ct = default);

    Task<IReadOnlyList<AuditLog>> GetByTargetAsync(
        Guid targetId,
        string targetType,
        int limit = 100,
        int offset = 0,
        CancellationToken ct = default);

    Task<IReadOnlyList<AuditLog>> GetByActionAsync(
        AuditAction action,
        DateTimeOffset? fromDate = null,
        DateTimeOffset? toDate = null,
        int limit = 100,
        int offset = 0,
        CancellationToken ct = default);

    Task<IReadOnlyList<AuditLog>> GetBySeverityAsync(
        AuditSeverity severity,
        DateTimeOffset? fromDate = null,
        DateTimeOffset? toDate = null,
        int limit = 100,
        int offset = 0,
        CancellationToken ct = default);

    Task<IReadOnlyList<AuditLog>> SearchAsync(
        string? query = null,
        AuditAction? action = null,
        AuditSeverity? severity = null,
        DateTimeOffset? fromDate = null,
        DateTimeOffset? toDate = null,
        int limit = 100,
        int offset = 0,
        CancellationToken ct = default);

    Task<Guid> CreateAsync(AuditLog auditLog, CancellationToken ct = default);

    Task<long> CountAsync(
        AuditAction? action = null,
        AuditSeverity? severity = null,
        DateTimeOffset? fromDate = null,
        DateTimeOffset? toDate = null,
        CancellationToken ct = default);
}
