using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Certificate.Domain.Events;

public sealed record CertificateIssuedEvent(Guid CertificateId, string SerialNumber, string SubjectDn) : DomainEvent;

public sealed record CertificateRevokedEvent(Guid CertificateId, string SerialNumber, RevocationReason Reason) : DomainEvent;

public sealed record CertificateSuspendedEvent(Guid CertificateId, string SerialNumber) : DomainEvent;

public sealed record CertificateReinstatedEvent(Guid CertificateId, string SerialNumber) : DomainEvent;

public sealed record CertificateExpiredEvent(Guid CertificateId, string SerialNumber) : DomainEvent;
