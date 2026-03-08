using Antrapol.IdP.Certificate.Domain.Enums;
using CertificateEntity = Antrapol.IdP.Certificate.Domain.Entities.Certificate;

namespace Antrapol.IdP.Certificate.Domain.Interfaces;

/// <summary>
/// Repository interface for Certificate aggregate.
/// </summary>
public interface ICertificateRepository
{
    Task<CertificateEntity?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<CertificateEntity?> GetBySerialNumberAsync(string serialNumber, CancellationToken ct = default);
    Task<CertificateEntity?> GetByThumbprintAsync(string thumbprint, CancellationToken ct = default);
    Task<IReadOnlyList<CertificateEntity>> GetByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task<IReadOnlyList<CertificateEntity>> GetByStatusAsync(CertificateStatus status, CancellationToken ct = default);
    Task<IReadOnlyList<CertificateEntity>> GetExpiringAsync(DateTimeOffset before, CancellationToken ct = default);
    Task<Guid> CreateAsync(CertificateEntity certificate, CancellationToken ct = default);
    Task UpdateAsync(CertificateEntity certificate, CancellationToken ct = default);
    Task<string> GenerateSerialNumberAsync(CancellationToken ct = default);
}
