using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.Certificate.Domain.Events;
using Antrapol.IdP.SharedKernel.Entities;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Certificate.Domain.Entities;

/// <summary>
/// Represents an X.509 certificate with PQC algorithms.
/// </summary>
public sealed class Certificate : AuditableEntity, IHasDomainEvents
{
    private readonly List<IDomainEvent> _domainEvents = [];

    public Guid? UserId { get; private set; }
    public string SerialNumber { get; private set; } = null!;
    public string SubjectDn { get; private set; } = null!;
    public string IssuerDn { get; private set; } = null!;
    public Guid? IssuerId { get; private set; }
    public CertificateType Type { get; private set; }
    public CertificateStatus Status { get; private set; }
    public SignatureAlgorithm Algorithm { get; private set; }
    public byte[] PublicKey { get; private set; } = [];
    public byte[] CertificateData { get; private set; } = [];
    public string Thumbprint { get; private set; } = null!;
    public DateTimeOffset NotBefore { get; private set; }
    public DateTimeOffset NotAfter { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public RevocationReason? RevocationReason { get; private set; }
    public Guid? KeyId { get; private set; }

    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    private Certificate() { }

    public static Certificate Create(
        string serialNumber,
        string subjectDn,
        string issuerDn,
        Guid? issuerId,
        CertificateType type,
        SignatureAlgorithm algorithm,
        byte[] publicKey,
        byte[] certificateData,
        string thumbprint,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        Guid? userId = null,
        Guid? keyId = null,
        Guid? createdBy = null)
    {
        var cert = new Certificate
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            SerialNumber = serialNumber,
            SubjectDn = subjectDn,
            IssuerDn = issuerDn,
            IssuerId = issuerId,
            Type = type,
            Status = CertificateStatus.Active,
            Algorithm = algorithm,
            PublicKey = publicKey,
            CertificateData = certificateData,
            Thumbprint = thumbprint,
            NotBefore = notBefore,
            NotAfter = notAfter,
            KeyId = keyId
        };

        cert.SetCreated(createdBy);
        cert._domainEvents.Add(new CertificateIssuedEvent(cert.Id, cert.SerialNumber, cert.SubjectDn));

        return cert;
    }

    public bool IsValid()
    {
        var now = DateTimeOffset.UtcNow;
        return Status == CertificateStatus.Active &&
               now >= NotBefore &&
               now <= NotAfter;
    }

    public bool IsExpired()
    {
        return DateTimeOffset.UtcNow > NotAfter;
    }

    public void Revoke(RevocationReason reason, Guid? revokedBy = null)
    {
        if (Status == CertificateStatus.Revoked)
            return;

        Status = CertificateStatus.Revoked;
        RevokedAt = DateTimeOffset.UtcNow;
        RevocationReason = reason;
        SetUpdated(revokedBy);

        _domainEvents.Add(new CertificateRevokedEvent(Id, SerialNumber, reason));
    }

    public void Suspend(Guid? suspendedBy = null)
    {
        if (Status != CertificateStatus.Active)
            throw new InvalidOperationException("Only active certificates can be suspended.");

        Status = CertificateStatus.Suspended;
        SetUpdated(suspendedBy);

        _domainEvents.Add(new CertificateSuspendedEvent(Id, SerialNumber));
    }

    public void Reinstate(Guid? reinstatedBy = null)
    {
        if (Status != CertificateStatus.Suspended)
            throw new InvalidOperationException("Only suspended certificates can be reinstated.");

        if (IsExpired())
        {
            Status = CertificateStatus.Expired;
            throw new InvalidOperationException("Cannot reinstate an expired certificate.");
        }

        Status = CertificateStatus.Active;
        SetUpdated(reinstatedBy);

        _domainEvents.Add(new CertificateReinstatedEvent(Id, SerialNumber));
    }

    public void MarkExpired()
    {
        if (Status == CertificateStatus.Revoked)
            return;

        Status = CertificateStatus.Expired;
        _domainEvents.Add(new CertificateExpiredEvent(Id, SerialNumber));
    }

    public void ClearDomainEvents() => _domainEvents.Clear();

    /// <summary>
    /// Reconstitutes a Certificate entity from persistence.
    /// </summary>
    public static Certificate Reconstitute(
        Guid id,
        Guid? userId,
        string serialNumber,
        string subjectDn,
        string issuerDn,
        Guid? issuerId,
        CertificateType type,
        CertificateStatus status,
        SignatureAlgorithm algorithm,
        byte[] publicKey,
        byte[] certificateData,
        string thumbprint,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        DateTimeOffset? revokedAt,
        RevocationReason? revocationReason,
        Guid? keyId,
        DateTimeOffset createdAt,
        Guid? createdBy,
        DateTimeOffset? updatedAt,
        Guid? updatedBy,
        int version)
    {
        return new Certificate
        {
            Id = id,
            UserId = userId,
            SerialNumber = serialNumber,
            SubjectDn = subjectDn,
            IssuerDn = issuerDn,
            IssuerId = issuerId,
            Type = type,
            Status = status,
            Algorithm = algorithm,
            PublicKey = publicKey,
            CertificateData = certificateData,
            Thumbprint = thumbprint,
            NotBefore = notBefore,
            NotAfter = notAfter,
            RevokedAt = revokedAt,
            RevocationReason = revocationReason,
            KeyId = keyId,
            CreatedAt = createdAt,
            CreatedBy = createdBy,
            UpdatedAt = updatedAt,
            UpdatedBy = updatedBy,
            Version = version
        };
    }
}
