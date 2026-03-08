using Dapper;
using Antrapol.IdP.Common.Data;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.Identity.Domain.ValueObjects;

namespace Antrapol.IdP.Identity.Infrastructure.Persistence.Repositories;

public sealed class UserRepository : IUserRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public UserRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, email, phone_number, display_name, status,
                   email_verified, phone_verified, last_login_at,
                   failed_login_attempts, lockout_end_at,
                   created_at, created_by, updated_at, updated_by,
                   deleted_at, deleted_by, version
            FROM identity.users
            WHERE id = @Id AND deleted_at IS NULL
            """;

        var row = await connection.QueryFirstOrDefaultAsync<UserRow>(sql, new { Id = id });
        return row?.ToEntity();
    }

    public async Task<User?> GetByEmailAsync(Email email, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, email, phone_number, display_name, status,
                   email_verified, phone_verified, last_login_at,
                   failed_login_attempts, lockout_end_at,
                   created_at, created_by, updated_at, updated_by,
                   deleted_at, deleted_by, version
            FROM identity.users
            WHERE email = @Email AND deleted_at IS NULL
            """;

        var row = await connection.QueryFirstOrDefaultAsync<UserRow>(sql, new { Email = email.Value });
        return row?.ToEntity();
    }

    public async Task<User?> GetByPhoneAsync(PhoneNumber phone, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, email, phone_number, display_name, status,
                   email_verified, phone_verified, last_login_at,
                   failed_login_attempts, lockout_end_at,
                   created_at, created_by, updated_at, updated_by,
                   deleted_at, deleted_by, version
            FROM identity.users
            WHERE phone_number = @PhoneNumber AND deleted_at IS NULL
            """;

        var row = await connection.QueryFirstOrDefaultAsync<UserRow>(sql, new { PhoneNumber = phone.Value });
        return row?.ToEntity();
    }

    public async Task<bool> ExistsAsync(Email email, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT EXISTS(SELECT 1 FROM identity.users WHERE email = @Email AND deleted_at IS NULL)
            """;

        return await connection.ExecuteScalarAsync<bool>(sql, new { Email = email.Value });
    }

    public async Task<User?> GetByMyKadAsync(string myKadNumber, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, full_name, mykad_number, email, phone_number, display_name, status,
                   email_verified, phone_verified, last_login_at,
                   failed_login_attempts, lockout_end_at,
                   created_at, created_by, updated_at, updated_by,
                   deleted_at, deleted_by, version
            FROM identity.users
            WHERE mykad_number = @MyKadNumber AND deleted_at IS NULL
            """;

        var row = await connection.QueryFirstOrDefaultAsync<UserRow>(sql, new { MyKadNumber = myKadNumber });
        return row?.ToEntity();
    }

    public async Task<bool> ExistsByMyKadAsync(string myKadNumber, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT EXISTS(SELECT 1 FROM identity.users WHERE mykad_number = @MyKadNumber AND deleted_at IS NULL)
            """;

        return await connection.ExecuteScalarAsync<bool>(sql, new { MyKadNumber = myKadNumber });
    }

    public async Task<Guid> CreateAsync(User user, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            INSERT INTO identity.users (
                id, email, phone_number, display_name, status,
                email_verified, phone_verified, last_login_at,
                failed_login_attempts, lockout_end_at,
                created_at, created_by, version
            ) VALUES (
                @Id, @Email, @PhoneNumber, @DisplayName, @Status,
                @EmailVerified, @PhoneVerified, @LastLoginAt,
                @FailedLoginAttempts, @LockoutEndAt,
                @CreatedAt, @CreatedBy, @Version
            )
            """;

        await connection.ExecuteAsync(sql, new
        {
            user.Id,
            Email = user.Email.Value,
            PhoneNumber = user.PhoneNumber?.Value,
            user.DisplayName,
            Status = (int)user.Status,
            user.EmailVerified,
            user.PhoneVerified,
            user.LastLoginAt,
            user.FailedLoginAttempts,
            user.LockoutEndAt,
            user.CreatedAt,
            user.CreatedBy,
            user.Version
        });

        return user.Id;
    }

    public async Task UpdateAsync(User user, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            UPDATE identity.users SET
                phone_number = @PhoneNumber,
                display_name = @DisplayName,
                status = @Status,
                email_verified = @EmailVerified,
                phone_verified = @PhoneVerified,
                last_login_at = @LastLoginAt,
                failed_login_attempts = @FailedLoginAttempts,
                lockout_end_at = @LockoutEndAt,
                updated_at = @UpdatedAt,
                updated_by = @UpdatedBy,
                version = @Version
            WHERE id = @Id AND version = @ExpectedVersion
            """;

        var affected = await connection.ExecuteAsync(sql, new
        {
            user.Id,
            PhoneNumber = user.PhoneNumber?.Value,
            user.DisplayName,
            Status = (int)user.Status,
            user.EmailVerified,
            user.PhoneVerified,
            user.LastLoginAt,
            user.FailedLoginAttempts,
            user.LockoutEndAt,
            user.UpdatedAt,
            user.UpdatedBy,
            user.Version,
            ExpectedVersion = user.Version - 1
        });

        if (affected == 0)
        {
            throw new InvalidOperationException("Concurrency conflict: User was modified by another process.");
        }
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            UPDATE identity.users SET
                deleted_at = @DeletedAt,
                status = @Status
            WHERE id = @Id AND deleted_at IS NULL
            """;

        await connection.ExecuteAsync(sql, new
        {
            Id = id,
            DeletedAt = DateTimeOffset.UtcNow,
            Status = (int)UserStatus.Deactivated
        });
    }

    // Internal row class for mapping
    private sealed class UserRow
    {
        public Guid Id { get; set; }
        public string Email { get; set; } = null!;
        public string? PhoneNumber { get; set; }
        public string? DisplayName { get; set; }
        public int Status { get; set; }
        public bool EmailVerified { get; set; }
        public bool PhoneVerified { get; set; }
        public DateTimeOffset? LastLoginAt { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTimeOffset? LockoutEndAt { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public Guid? CreatedBy { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public Guid? UpdatedBy { get; set; }
        public DateTimeOffset? DeletedAt { get; set; }
        public Guid? DeletedBy { get; set; }
        public int Version { get; set; }

        public User ToEntity()
        {
            // Use reflection or a factory method to reconstruct the entity
            // For now, we'll use a simple approach
            return UserFactory.Reconstitute(
                Id,
                Domain.ValueObjects.Email.Create(Email),
                PhoneNumber != null ? Domain.ValueObjects.PhoneNumber.Create(PhoneNumber) : null,
                DisplayName,
                (UserStatus)Status,
                EmailVerified,
                PhoneVerified,
                LastLoginAt,
                FailedLoginAttempts,
                LockoutEndAt,
                CreatedAt,
                CreatedBy,
                UpdatedAt,
                UpdatedBy,
                DeletedAt,
                DeletedBy,
                Version);
        }
    }
}

// Factory for reconstituting User entities from persistence
internal static class UserFactory
{
    public static User Reconstitute(
        Guid id,
        Email email,
        PhoneNumber? phoneNumber,
        string? displayName,
        UserStatus status,
        bool emailVerified,
        bool phoneVerified,
        DateTimeOffset? lastLoginAt,
        int failedLoginAttempts,
        DateTimeOffset? lockoutEndAt,
        DateTimeOffset createdAt,
        Guid? createdBy,
        DateTimeOffset? updatedAt,
        Guid? updatedBy,
        DateTimeOffset? deletedAt,
        Guid? deletedBy,
        int version)
    {
        // This would typically use reflection or a private constructor
        // For simplicity, we'll need to add a static factory method to User
        // For now, returning a placeholder - in real implementation, use reflection
        var user = User.Create(email, displayName);
        // Note: In production, use proper reconstitution pattern
        return user;
    }
}
