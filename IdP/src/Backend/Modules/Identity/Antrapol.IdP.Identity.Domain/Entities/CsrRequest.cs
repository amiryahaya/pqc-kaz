using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.SharedKernel.Entities;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents a Certificate Signing Request (CSR) submitted during registration.
/// Each registration generates two CSRs: one for device certificate and one for user certificate.
/// </summary>
public sealed class CsrRequest : AuditableEntity
{
    /// <summary>
    /// Reference to the pending registration.
    /// </summary>
    public Guid RegistrationId { get; private set; }

    /// <summary>
    /// Type of CSR (Device or User).
    /// </summary>
    public CsrType Type { get; private set; }

    /// <summary>
    /// The CSR data in DER format (Base64 encoded for storage).
    /// </summary>
    public byte[] CsrData { get; private set; } = [];

    /// <summary>
    /// Subject DN extracted from the CSR.
    /// </summary>
    public string SubjectDn { get; private set; } = null!;

    /// <summary>
    /// Public key extracted from the CSR (for fingerprint/verification).
    /// </summary>
    public byte[] PublicKey { get; private set; } = [];

    /// <summary>
    /// SHA-256 hash of the public key for quick lookup.
    /// </summary>
    public string PublicKeyFingerprint { get; private set; } = null!;

    /// <summary>
    /// Status of the CSR processing.
    /// </summary>
    public CsrStatus Status { get; private set; }

    /// <summary>
    /// Reference to the issued certificate (once approved and issued).
    /// </summary>
    public Guid? IssuedCertificateId { get; private set; }

    /// <summary>
    /// Rejection reason if CSR was rejected.
    /// </summary>
    public string? RejectionReason { get; private set; }

    private CsrRequest() { }

    public static CsrRequest Create(
        Guid registrationId,
        CsrType type,
        byte[] csrData,
        string subjectDn,
        byte[] publicKey,
        string publicKeyFingerprint,
        Guid? createdBy = null)
    {
        var csr = new CsrRequest
        {
            Id = Guid.CreateVersion7(),
            RegistrationId = registrationId,
            Type = type,
            CsrData = csrData,
            SubjectDn = subjectDn,
            PublicKey = publicKey,
            PublicKeyFingerprint = publicKeyFingerprint,
            Status = CsrStatus.Pending
        };

        csr.SetCreated(createdBy);
        return csr;
    }

    public void Approve()
    {
        if (Status != CsrStatus.Pending)
            throw new InvalidOperationException("Only pending CSRs can be approved.");

        Status = CsrStatus.Approved;
        SetUpdated(null);
    }

    public void MarkCertificateIssued(Guid certificateId)
    {
        if (Status != CsrStatus.Approved)
            throw new InvalidOperationException("CSR must be approved before marking certificate as issued.");

        Status = CsrStatus.Issued;
        IssuedCertificateId = certificateId;
        SetUpdated(null);
    }

    public void Reject(string reason)
    {
        if (Status != CsrStatus.Pending)
            throw new InvalidOperationException("Only pending CSRs can be rejected.");

        Status = CsrStatus.Rejected;
        RejectionReason = reason;
        SetUpdated(null);
    }

    /// <summary>
    /// Reconstitutes a CsrRequest entity from persistence.
    /// </summary>
    public static CsrRequest Reconstitute(
        Guid id,
        Guid registrationId,
        CsrType type,
        byte[] csrData,
        string subjectDn,
        byte[] publicKey,
        string publicKeyFingerprint,
        CsrStatus status,
        Guid? issuedCertificateId,
        string? rejectionReason,
        DateTimeOffset createdAt,
        Guid? createdBy,
        DateTimeOffset? updatedAt,
        Guid? updatedBy,
        int version)
    {
        return new CsrRequest
        {
            Id = id,
            RegistrationId = registrationId,
            Type = type,
            CsrData = csrData,
            SubjectDn = subjectDn,
            PublicKey = publicKey,
            PublicKeyFingerprint = publicKeyFingerprint,
            Status = status,
            IssuedCertificateId = issuedCertificateId,
            RejectionReason = rejectionReason,
            CreatedAt = createdAt,
            CreatedBy = createdBy,
            UpdatedAt = updatedAt,
            UpdatedBy = updatedBy,
            Version = version
        };
    }
}

/// <summary>
/// Type of Certificate Signing Request.
/// </summary>
public enum CsrType
{
    /// <summary>
    /// CSR for device certificate (device identity).
    /// </summary>
    Device = 0,

    /// <summary>
    /// CSR for user certificate (user identity/signing).
    /// </summary>
    User = 1
}

/// <summary>
/// Status of CSR processing.
/// </summary>
public enum CsrStatus
{
    /// <summary>
    /// CSR submitted, awaiting processing.
    /// </summary>
    Pending = 0,

    /// <summary>
    /// CSR validated and approved, ready for certificate issuance.
    /// </summary>
    Approved = 1,

    /// <summary>
    /// Certificate has been issued for this CSR.
    /// </summary>
    Issued = 2,

    /// <summary>
    /// CSR was rejected (invalid format, verification failed, etc.).
    /// </summary>
    Rejected = 3
}
