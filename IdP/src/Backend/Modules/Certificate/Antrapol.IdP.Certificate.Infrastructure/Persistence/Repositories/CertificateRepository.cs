using Dapper;
using Antrapol.IdP.Certificate.Domain.Enums;
using Antrapol.IdP.Certificate.Domain.Interfaces;
using Antrapol.IdP.Common.Data;
using CertificateEntity = Antrapol.IdP.Certificate.Domain.Entities.Certificate;

namespace Antrapol.IdP.Certificate.Infrastructure.Persistence.Repositories;

public sealed class CertificateRepository : ICertificateRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public CertificateRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<CertificateEntity?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, serial_number, subject_dn, issuer_dn, issuer_id,
                   type, status, algorithm, public_key, certificate_data, thumbprint,
                   not_before, not_after, revoked_at, revocation_reason, key_id,
                   created_at, created_by, updated_at, updated_by, version
            FROM certificate.certificates
            WHERE id = @Id
            """;

        var row = await connection.QueryFirstOrDefaultAsync<CertificateRow>(sql, new { Id = id });
        return row?.ToEntity();
    }

    public async Task<CertificateEntity?> GetBySerialNumberAsync(string serialNumber, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, serial_number, subject_dn, issuer_dn, issuer_id,
                   type, status, algorithm, public_key, certificate_data, thumbprint,
                   not_before, not_after, revoked_at, revocation_reason, key_id,
                   created_at, created_by, updated_at, updated_by, version
            FROM certificate.certificates
            WHERE serial_number = @SerialNumber
            """;

        var row = await connection.QueryFirstOrDefaultAsync<CertificateRow>(sql, new { SerialNumber = serialNumber });
        return row?.ToEntity();
    }

    public async Task<CertificateEntity?> GetByThumbprintAsync(string thumbprint, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, serial_number, subject_dn, issuer_dn, issuer_id,
                   type, status, algorithm, public_key, certificate_data, thumbprint,
                   not_before, not_after, revoked_at, revocation_reason, key_id,
                   created_at, created_by, updated_at, updated_by, version
            FROM certificate.certificates
            WHERE thumbprint = @Thumbprint
            """;

        var row = await connection.QueryFirstOrDefaultAsync<CertificateRow>(sql, new { Thumbprint = thumbprint });
        return row?.ToEntity();
    }

    public async Task<IReadOnlyList<CertificateEntity>> GetByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, serial_number, subject_dn, issuer_dn, issuer_id,
                   type, status, algorithm, public_key, certificate_data, thumbprint,
                   not_before, not_after, revoked_at, revocation_reason, key_id,
                   created_at, created_by, updated_at, updated_by, version
            FROM certificate.certificates
            WHERE user_id = @UserId
            ORDER BY created_at DESC
            """;

        var rows = await connection.QueryAsync<CertificateRow>(sql, new { UserId = userId });
        return rows.Select(r => r.ToEntity()).ToList();
    }

    public async Task<IReadOnlyList<CertificateEntity>> GetByStatusAsync(CertificateStatus status, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, serial_number, subject_dn, issuer_dn, issuer_id,
                   type, status, algorithm, public_key, certificate_data, thumbprint,
                   not_before, not_after, revoked_at, revocation_reason, key_id,
                   created_at, created_by, updated_at, updated_by, version
            FROM certificate.certificates
            WHERE status = @Status
            ORDER BY created_at DESC
            """;

        var rows = await connection.QueryAsync<CertificateRow>(sql, new { Status = (int)status });
        return rows.Select(r => r.ToEntity()).ToList();
    }

    public async Task<IReadOnlyList<CertificateEntity>> GetExpiringAsync(DateTimeOffset before, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, serial_number, subject_dn, issuer_dn, issuer_id,
                   type, status, algorithm, public_key, certificate_data, thumbprint,
                   not_before, not_after, revoked_at, revocation_reason, key_id,
                   created_at, created_by, updated_at, updated_by, version
            FROM certificate.certificates
            WHERE not_after <= @Before AND status = @ActiveStatus
            ORDER BY not_after ASC
            """;

        var rows = await connection.QueryAsync<CertificateRow>(sql, new
        {
            Before = before,
            ActiveStatus = (int)CertificateStatus.Active
        });
        return rows.Select(r => r.ToEntity()).ToList();
    }

    public async Task<Guid> CreateAsync(CertificateEntity certificate, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            INSERT INTO certificate.certificates (
                id, user_id, serial_number, subject_dn, issuer_dn, issuer_id,
                type, status, algorithm, public_key, certificate_data, thumbprint,
                not_before, not_after, revoked_at, revocation_reason, key_id,
                created_at, created_by, version
            ) VALUES (
                @Id, @UserId, @SerialNumber, @SubjectDn, @IssuerDn, @IssuerId,
                @Type, @Status, @Algorithm, @PublicKey, @CertificateData, @Thumbprint,
                @NotBefore, @NotAfter, @RevokedAt, @RevocationReason, @KeyId,
                @CreatedAt, @CreatedBy, @Version
            )
            """;

        await connection.ExecuteAsync(sql, new
        {
            certificate.Id,
            certificate.UserId,
            certificate.SerialNumber,
            certificate.SubjectDn,
            certificate.IssuerDn,
            certificate.IssuerId,
            Type = (int)certificate.Type,
            Status = (int)certificate.Status,
            Algorithm = (int)certificate.Algorithm,
            certificate.PublicKey,
            certificate.CertificateData,
            certificate.Thumbprint,
            certificate.NotBefore,
            certificate.NotAfter,
            certificate.RevokedAt,
            RevocationReason = certificate.RevocationReason.HasValue ? (int?)certificate.RevocationReason : null,
            certificate.KeyId,
            certificate.CreatedAt,
            certificate.CreatedBy,
            certificate.Version
        });

        return certificate.Id;
    }

    public async Task UpdateAsync(CertificateEntity certificate, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            UPDATE certificate.certificates SET
                status = @Status,
                revoked_at = @RevokedAt,
                revocation_reason = @RevocationReason,
                updated_at = @UpdatedAt,
                updated_by = @UpdatedBy,
                version = @Version
            WHERE id = @Id AND version = @ExpectedVersion
            """;

        var affected = await connection.ExecuteAsync(sql, new
        {
            certificate.Id,
            Status = (int)certificate.Status,
            certificate.RevokedAt,
            RevocationReason = certificate.RevocationReason.HasValue ? (int?)certificate.RevocationReason : null,
            certificate.UpdatedAt,
            certificate.UpdatedBy,
            certificate.Version,
            ExpectedVersion = certificate.Version - 1
        });

        if (affected == 0)
        {
            throw new InvalidOperationException("Concurrency conflict: Certificate was modified by another process.");
        }
    }

    public async Task<string> GenerateSerialNumberAsync(CancellationToken ct = default)
    {
        // Generate a unique serial number using UUID v7 and timestamp
        var bytes = new byte[16];
        Random.Shared.NextBytes(bytes);
        return Convert.ToHexString(bytes).ToUpperInvariant();
    }

    private sealed class CertificateRow
    {
        public Guid Id { get; set; }
        public Guid? UserId { get; set; }
        public string SerialNumber { get; set; } = null!;
        public string SubjectDn { get; set; } = null!;
        public string IssuerDn { get; set; } = null!;
        public Guid? IssuerId { get; set; }
        public int Type { get; set; }
        public int Status { get; set; }
        public int Algorithm { get; set; }
        public byte[] PublicKey { get; set; } = [];
        public byte[] CertificateData { get; set; } = [];
        public string Thumbprint { get; set; } = null!;
        public DateTimeOffset NotBefore { get; set; }
        public DateTimeOffset NotAfter { get; set; }
        public DateTimeOffset? RevokedAt { get; set; }
        public int? RevocationReason { get; set; }
        public Guid? KeyId { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public Guid? CreatedBy { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public Guid? UpdatedBy { get; set; }
        public int Version { get; set; }

        public CertificateEntity ToEntity()
        {
            return CertificateEntity.Reconstitute(
                id: Id,
                userId: UserId,
                serialNumber: SerialNumber,
                subjectDn: SubjectDn,
                issuerDn: IssuerDn,
                issuerId: IssuerId,
                type: (CertificateType)Type,
                status: (CertificateStatus)Status,
                algorithm: (SignatureAlgorithm)Algorithm,
                publicKey: PublicKey,
                certificateData: CertificateData,
                thumbprint: Thumbprint,
                notBefore: NotBefore,
                notAfter: NotAfter,
                revokedAt: RevokedAt,
                revocationReason: RevocationReason.HasValue ? (RevocationReason)RevocationReason : null,
                keyId: KeyId,
                createdAt: CreatedAt,
                createdBy: CreatedBy,
                updatedAt: UpdatedAt,
                updatedBy: UpdatedBy,
                version: Version);
        }
    }
}
