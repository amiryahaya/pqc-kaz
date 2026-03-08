using Antrapol.IdP.Certificate.Domain.Enums;

namespace Antrapol.IdP.Certificate.Application.DTOs;

public sealed record CertificateDto(
    Guid Id,
    Guid? UserId,
    string SerialNumber,
    string SubjectDn,
    string IssuerDn,
    CertificateType Type,
    CertificateStatus Status,
    SignatureAlgorithm Algorithm,
    string Thumbprint,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    DateTimeOffset? RevokedAt,
    RevocationReason? RevocationReason,
    DateTimeOffset CreatedAt);

public sealed record CertificateSummaryDto(
    Guid Id,
    string SerialNumber,
    string SubjectDn,
    CertificateStatus Status,
    SignatureAlgorithm Algorithm,
    DateTimeOffset NotAfter);
