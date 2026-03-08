using Dapper;
using Antrapol.IdP.Common.Data;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Interfaces;

namespace Antrapol.IdP.Identity.Infrastructure.Persistence.Repositories;

public sealed class CsrRequestRepository : ICsrRequestRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public CsrRequestRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<CsrRequest?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, registration_id, type, csr_data, subject_dn, public_key,
                   public_key_fingerprint, status, issued_certificate_id, rejection_reason,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.csr_requests
            WHERE id = @Id
            """;

        var row = await connection.QueryFirstOrDefaultAsync<CsrRequestRow>(sql, new { Id = id });
        return row?.ToEntity();
    }

    public async Task<IReadOnlyList<CsrRequest>> GetByRegistrationIdAsync(Guid registrationId, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, registration_id, type, csr_data, subject_dn, public_key,
                   public_key_fingerprint, status, issued_certificate_id, rejection_reason,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.csr_requests
            WHERE registration_id = @RegistrationId
            ORDER BY type ASC
            """;

        var rows = await connection.QueryAsync<CsrRequestRow>(sql, new { RegistrationId = registrationId });
        return rows.Select(r => r.ToEntity()).ToList();
    }

    public async Task<CsrRequest?> GetByPublicKeyFingerprintAsync(string fingerprint, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, registration_id, type, csr_data, subject_dn, public_key,
                   public_key_fingerprint, status, issued_certificate_id, rejection_reason,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.csr_requests
            WHERE public_key_fingerprint = @Fingerprint
            """;

        var row = await connection.QueryFirstOrDefaultAsync<CsrRequestRow>(sql, new { Fingerprint = fingerprint });
        return row?.ToEntity();
    }

    public async Task<Guid> CreateAsync(CsrRequest csr, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            INSERT INTO identity.csr_requests (
                id, registration_id, type, csr_data, subject_dn, public_key,
                public_key_fingerprint, status, issued_certificate_id, rejection_reason,
                created_at, created_by, version
            ) VALUES (
                @Id, @RegistrationId, @Type, @CsrData, @SubjectDn, @PublicKey,
                @PublicKeyFingerprint, @Status, @IssuedCertificateId, @RejectionReason,
                @CreatedAt, @CreatedBy, @Version
            )
            """;

        await connection.ExecuteAsync(sql, new
        {
            csr.Id,
            csr.RegistrationId,
            Type = (int)csr.Type,
            csr.CsrData,
            csr.SubjectDn,
            csr.PublicKey,
            csr.PublicKeyFingerprint,
            Status = (int)csr.Status,
            csr.IssuedCertificateId,
            csr.RejectionReason,
            csr.CreatedAt,
            csr.CreatedBy,
            csr.Version
        });

        return csr.Id;
    }

    public async Task UpdateAsync(CsrRequest csr, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            UPDATE identity.csr_requests SET
                status = @Status,
                issued_certificate_id = @IssuedCertificateId,
                rejection_reason = @RejectionReason,
                updated_at = @UpdatedAt,
                updated_by = @UpdatedBy,
                version = @Version
            WHERE id = @Id AND version = @ExpectedVersion
            """;

        var affected = await connection.ExecuteAsync(sql, new
        {
            csr.Id,
            Status = (int)csr.Status,
            csr.IssuedCertificateId,
            csr.RejectionReason,
            csr.UpdatedAt,
            csr.UpdatedBy,
            csr.Version,
            ExpectedVersion = csr.Version - 1
        });

        if (affected == 0)
        {
            throw new InvalidOperationException("Concurrency conflict: CSR request was modified by another process.");
        }
    }

    private sealed class CsrRequestRow
    {
        public Guid Id { get; set; }
        public Guid RegistrationId { get; set; }
        public int Type { get; set; }
        public byte[] CsrData { get; set; } = [];
        public string SubjectDn { get; set; } = null!;
        public byte[] PublicKey { get; set; } = [];
        public string PublicKeyFingerprint { get; set; } = null!;
        public int Status { get; set; }
        public Guid? IssuedCertificateId { get; set; }
        public string? RejectionReason { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public Guid? CreatedBy { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public Guid? UpdatedBy { get; set; }
        public int Version { get; set; }

        public CsrRequest ToEntity()
        {
            return CsrRequest.Reconstitute(
                id: Id,
                registrationId: RegistrationId,
                type: (CsrType)Type,
                csrData: CsrData,
                subjectDn: SubjectDn,
                publicKey: PublicKey,
                publicKeyFingerprint: PublicKeyFingerprint,
                status: (CsrStatus)Status,
                issuedCertificateId: IssuedCertificateId,
                rejectionReason: RejectionReason,
                createdAt: CreatedAt,
                createdBy: CreatedBy,
                updatedAt: UpdatedAt,
                updatedBy: UpdatedBy,
                version: Version);
        }
    }
}
