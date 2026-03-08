using Dapper;
using Antrapol.IdP.Common.Data;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.Identity.Domain.ValueObjects;

namespace Antrapol.IdP.Identity.Infrastructure.Persistence.Repositories;

public sealed class PendingRegistrationRepository : IPendingRegistrationRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public PendingRegistrationRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }

    public async Task<PendingRegistration?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, full_name, mykad_number, email, phone_number,
                   email_otp_hash, email_otp_expires_at, email_otp_attempts,
                   phone_otp_hash, phone_otp_expires_at, phone_otp_attempts,
                   status, tracking_id,
                   device_id, device_name, device_platform, device_os_version, app_version,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.pending_registrations
            WHERE id = @Id
            """;

        var row = await connection.QueryFirstOrDefaultAsync<PendingRegistrationRow>(sql, new { Id = id });
        return row?.ToEntity();
    }

    public async Task<PendingRegistration?> GetByTrackingIdAsync(Guid trackingId, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, full_name, mykad_number, email, phone_number,
                   email_otp_hash, email_otp_expires_at, email_otp_attempts,
                   phone_otp_hash, phone_otp_expires_at, phone_otp_attempts,
                   status, tracking_id,
                   device_id, device_name, device_platform, device_os_version, app_version,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.pending_registrations
            WHERE tracking_id = @TrackingId
            """;

        var row = await connection.QueryFirstOrDefaultAsync<PendingRegistrationRow>(sql, new { TrackingId = trackingId });
        return row?.ToEntity();
    }

    public async Task<PendingRegistration?> GetByEmailAsync(Email email, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, full_name, mykad_number, email, phone_number,
                   email_otp_hash, email_otp_expires_at, email_otp_attempts,
                   phone_otp_hash, phone_otp_expires_at, phone_otp_attempts,
                   status, tracking_id,
                   device_id, device_name, device_platform, device_os_version, app_version,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.pending_registrations
            WHERE email = @Email AND status NOT IN (10, 98, 99)
            ORDER BY created_at DESC
            LIMIT 1
            """;

        var row = await connection.QueryFirstOrDefaultAsync<PendingRegistrationRow>(sql, new { Email = email.Value });
        return row?.ToEntity();
    }

    public async Task<PendingRegistration?> GetByMyKadAsync(string myKadNumber, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            SELECT id, full_name, mykad_number, email, phone_number,
                   email_otp_hash, email_otp_expires_at, email_otp_attempts,
                   phone_otp_hash, phone_otp_expires_at, phone_otp_attempts,
                   status, tracking_id,
                   device_id, device_name, device_platform, device_os_version, app_version,
                   created_at, created_by, updated_at, updated_by, version
            FROM identity.pending_registrations
            WHERE mykad_number = @MyKadNumber AND status NOT IN (10, 98, 99)
            ORDER BY created_at DESC
            LIMIT 1
            """;

        var row = await connection.QueryFirstOrDefaultAsync<PendingRegistrationRow>(sql, new { MyKadNumber = myKadNumber });
        return row?.ToEntity();
    }

    public async Task<Guid> CreateAsync(PendingRegistration registration, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            INSERT INTO identity.pending_registrations (
                id, full_name, mykad_number, email, phone_number,
                email_otp_hash, email_otp_expires_at, email_otp_attempts,
                phone_otp_hash, phone_otp_expires_at, phone_otp_attempts,
                status, tracking_id,
                device_id, device_name, device_platform, device_os_version, app_version,
                created_at, created_by, version
            ) VALUES (
                @Id, @FullName, @MyKadNumber, @Email, @PhoneNumber,
                @EmailOtpHash, @EmailOtpExpiresAt, @EmailOtpAttempts,
                @PhoneOtpHash, @PhoneOtpExpiresAt, @PhoneOtpAttempts,
                @Status, @TrackingId,
                @DeviceId, @DeviceName, @DevicePlatform, @DeviceOsVersion, @AppVersion,
                @CreatedAt, @CreatedBy, @Version
            )
            """;

        await connection.ExecuteAsync(sql, new
        {
            registration.Id,
            registration.FullName,
            registration.MyKadNumber,
            Email = registration.Email.Value,
            PhoneNumber = registration.PhoneNumber?.Value,
            registration.EmailOtpHash,
            registration.EmailOtpExpiresAt,
            registration.EmailOtpAttempts,
            registration.PhoneOtpHash,
            registration.PhoneOtpExpiresAt,
            registration.PhoneOtpAttempts,
            Status = (int)registration.Status,
            registration.TrackingId,
            registration.DeviceId,
            registration.DeviceName,
            DevicePlatform = registration.DevicePlatform.HasValue ? (int?)registration.DevicePlatform.Value : null,
            registration.DeviceOsVersion,
            registration.AppVersion,
            registration.CreatedAt,
            registration.CreatedBy,
            registration.Version
        });

        return registration.Id;
    }

    public async Task UpdateAsync(PendingRegistration registration, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            UPDATE identity.pending_registrations SET
                phone_number = @PhoneNumber,
                phone_otp_hash = @PhoneOtpHash,
                phone_otp_expires_at = @PhoneOtpExpiresAt,
                phone_otp_attempts = @PhoneOtpAttempts,
                email_otp_attempts = @EmailOtpAttempts,
                status = @Status,
                updated_at = @UpdatedAt,
                updated_by = @UpdatedBy,
                version = @Version
            WHERE id = @Id AND version = @ExpectedVersion
            """;

        var affected = await connection.ExecuteAsync(sql, new
        {
            registration.Id,
            PhoneNumber = registration.PhoneNumber?.Value,
            registration.PhoneOtpHash,
            registration.PhoneOtpExpiresAt,
            registration.PhoneOtpAttempts,
            registration.EmailOtpAttempts,
            Status = (int)registration.Status,
            registration.UpdatedAt,
            registration.UpdatedBy,
            registration.Version,
            ExpectedVersion = registration.Version - 1
        });

        if (affected == 0)
        {
            throw new InvalidOperationException("Concurrency conflict: Registration was modified by another process.");
        }
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        using var connection = await _connectionFactory.CreateConnectionAsync(ct);

        const string sql = """
            DELETE FROM identity.pending_registrations
            WHERE id = @Id
            """;

        await connection.ExecuteAsync(sql, new { Id = id });
    }

    private sealed class PendingRegistrationRow
    {
        public Guid Id { get; set; }
        public string FullName { get; set; } = null!;
        public string MyKadNumber { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string? PhoneNumber { get; set; }
        public string EmailOtpHash { get; set; } = null!;
        public DateTimeOffset EmailOtpExpiresAt { get; set; }
        public int EmailOtpAttempts { get; set; }
        public string? PhoneOtpHash { get; set; }
        public DateTimeOffset? PhoneOtpExpiresAt { get; set; }
        public int PhoneOtpAttempts { get; set; }
        public int Status { get; set; }
        public Guid TrackingId { get; set; }
        public string? DeviceId { get; set; }
        public string? DeviceName { get; set; }
        public int? DevicePlatform { get; set; }
        public string? DeviceOsVersion { get; set; }
        public string? AppVersion { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public Guid? CreatedBy { get; set; }
        public DateTimeOffset? UpdatedAt { get; set; }
        public Guid? UpdatedBy { get; set; }
        public int Version { get; set; }

        public PendingRegistration ToEntity()
        {
            return PendingRegistration.Reconstitute(
                id: Id,
                fullName: FullName,
                myKadNumber: MyKadNumber,
                email: Domain.ValueObjects.Email.Create(Email),
                phoneNumber: PhoneNumber != null ? Domain.ValueObjects.PhoneNumber.Create(PhoneNumber) : null,
                emailOtpHash: EmailOtpHash,
                emailOtpExpiresAt: EmailOtpExpiresAt,
                emailOtpAttempts: EmailOtpAttempts,
                phoneOtpHash: PhoneOtpHash,
                phoneOtpExpiresAt: PhoneOtpExpiresAt,
                phoneOtpAttempts: PhoneOtpAttempts,
                status: (RegistrationStatus)Status,
                trackingId: TrackingId,
                deviceId: DeviceId,
                deviceName: DeviceName,
                devicePlatform: DevicePlatform.HasValue ? (DevicePlatform)DevicePlatform.Value : null,
                deviceOsVersion: DeviceOsVersion,
                appVersion: AppVersion,
                createdAt: CreatedAt,
                createdBy: CreatedBy,
                updatedAt: UpdatedAt,
                updatedBy: UpdatedBy,
                version: Version);
        }
    }
}
