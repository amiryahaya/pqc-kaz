using Dapper;
using Antrapol.IdP.Common.Data;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Interfaces;

namespace Antrapol.IdP.Identity.Infrastructure.Persistence.Repositories;

public sealed class KeyShareRepository : IKeyShareRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public KeyShareRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<KeyShare?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, registration_id, type, encrypted_data, encapsulated_key,
                   nonce, auth_tag, salt, share_index, is_active,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.key_shares
            WHERE id = @Id
            """;

        var row = await connection.QueryFirstOrDefaultAsync<KeyShareRow>(sql, new { Id = id });
        return row?.ToEntity();
    }

    public async Task<IReadOnlyList<KeyShare>> GetByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, registration_id, type, encrypted_data, encapsulated_key,
                   nonce, auth_tag, salt, share_index, is_active,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.key_shares
            WHERE user_id = @UserId
            ORDER BY type ASC, share_index ASC
            """;

        var rows = await connection.QueryAsync<KeyShareRow>(sql, new { UserId = userId });
        return rows.Select(r => r.ToEntity()).ToList();
    }

    public async Task<IReadOnlyList<KeyShare>> GetByRegistrationIdAsync(Guid registrationId, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, registration_id, type, encrypted_data, encapsulated_key,
                   nonce, auth_tag, salt, share_index, is_active,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.key_shares
            WHERE registration_id = @RegistrationId
            ORDER BY type ASC, share_index ASC
            """;

        var rows = await connection.QueryAsync<KeyShareRow>(sql, new { RegistrationId = registrationId });
        return rows.Select(r => r.ToEntity()).ToList();
    }

    public async Task<KeyShare?> GetActiveControlShareAsync(Guid userId, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, registration_id, type, encrypted_data, encapsulated_key,
                   nonce, auth_tag, salt, share_index, is_active,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.key_shares
            WHERE user_id = @UserId AND type = @Type AND is_active = true
            LIMIT 1
            """;

        var row = await connection.QueryFirstOrDefaultAsync<KeyShareRow>(
            sql, new { UserId = userId, Type = (int)KeyShareType.Control });
        return row?.ToEntity();
    }

    public async Task<KeyShare?> GetActiveRecoveryShareAsync(Guid userId, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, user_id, registration_id, type, encrypted_data, encapsulated_key,
                   nonce, auth_tag, salt, share_index, is_active,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.key_shares
            WHERE user_id = @UserId AND type = @Type AND is_active = true
            LIMIT 1
            """;

        var row = await connection.QueryFirstOrDefaultAsync<KeyShareRow>(
            sql, new { UserId = userId, Type = (int)KeyShareType.Recovery });
        return row?.ToEntity();
    }

    public async Task<Guid> CreateAsync(KeyShare keyShare, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            INSERT INTO identity.key_shares (
                id, user_id, registration_id, type, encrypted_data, encapsulated_key,
                nonce, auth_tag, salt, share_index, is_active,
                created_at, created_by, version
            ) VALUES (
                @Id, @UserId, @RegistrationId, @Type, @EncryptedData, @EncapsulatedKey,
                @Nonce, @AuthTag, @Salt, @ShareIndex, @IsActive,
                @CreatedAt, @CreatedBy, @Version
            )
            """;

        await connection.ExecuteAsync(sql, new
        {
            keyShare.Id,
            keyShare.UserId,
            keyShare.RegistrationId,
            Type = (int)keyShare.Type,
            keyShare.EncryptedData,
            keyShare.EncapsulatedKey,
            keyShare.Nonce,
            keyShare.AuthTag,
            keyShare.Salt,
            keyShare.ShareIndex,
            keyShare.IsActive,
            keyShare.CreatedAt,
            keyShare.CreatedBy,
            keyShare.Version
        });

        return keyShare.Id;
    }

    public async Task UpdateAsync(KeyShare keyShare, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            UPDATE identity.key_shares SET
                user_id = @UserId,
                encrypted_data = @EncryptedData,
                encapsulated_key = @EncapsulatedKey,
                nonce = @Nonce,
                auth_tag = @AuthTag,
                salt = @Salt,
                is_active = @IsActive,
                updated_at = @UpdatedAt,
                updated_by = @UpdatedBy,
                version = @Version
            WHERE id = @Id AND version = @ExpectedVersion
            """;

        var affected = await connection.ExecuteAsync(sql, new
        {
            keyShare.Id,
            keyShare.UserId,
            keyShare.EncryptedData,
            keyShare.EncapsulatedKey,
            keyShare.Nonce,
            keyShare.AuthTag,
            keyShare.Salt,
            keyShare.IsActive,
            keyShare.UpdatedAt,
            keyShare.UpdatedBy,
            keyShare.Version,
            ExpectedVersion = keyShare.Version - 1
        });

        if (affected == 0)
        {
            throw new InvalidOperationException("Concurrency conflict: KeyShare was modified by another process.");
        }
    }

    private sealed class KeyShareRow
    {
        public Guid Id { get; set; }
        public Guid? UserId { get; set; }
        public Guid? RegistrationId { get; set; }
        public int Type { get; set; }
        public byte[] EncryptedData { get; set; } = [];
        public byte[]? EncapsulatedKey { get; set; }
        public byte[]? Nonce { get; set; }
        public byte[]? AuthTag { get; set; }
        public byte[]? Salt { get; set; }
        public int ShareIndex { get; set; }
        public bool IsActive { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public Guid? CreatedBy { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public Guid? UpdatedBy { get; set; }
        public int Version { get; set; }

        public KeyShare ToEntity()
        {
            return KeyShare.Reconstitute(
                id: Id,
                userId: UserId,
                registrationId: RegistrationId,
                type: (KeyShareType)Type,
                encryptedData: EncryptedData,
                encapsulatedKey: EncapsulatedKey,
                nonce: Nonce,
                authTag: AuthTag,
                salt: Salt,
                shareIndex: ShareIndex,
                isActive: IsActive,
                createdAt: CreatedAt,
                createdBy: CreatedBy,
                updatedAt: UpdatedAt,
                updatedBy: UpdatedBy,
                version: Version);
        }
    }
}
