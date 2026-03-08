using Antrapol.IdP.Crypto.Domain.Entities;
using Antrapol.IdP.Crypto.Domain.Enums;

namespace Antrapol.IdP.Crypto.Domain.Interfaces;

/// <summary>
/// Repository interface for CryptoKey aggregate.
/// </summary>
public interface ICryptoKeyRepository
{
    Task<CryptoKey?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<CryptoKey?> GetByFingerprintAsync(string fingerprint, CancellationToken ct = default);
    Task<CryptoKey?> GetByHsmHandleAsync(string hsmHandle, CancellationToken ct = default);
    Task<IReadOnlyList<CryptoKey>> GetByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task<IReadOnlyList<CryptoKey>> GetByAlgorithmAsync(KeyAlgorithm algorithm, CancellationToken ct = default);
    Task<IReadOnlyList<CryptoKey>> GetActiveByPurposeAsync(KeyPurpose purpose, CancellationToken ct = default);
    Task<Guid> CreateAsync(CryptoKey key, CancellationToken ct = default);
    Task UpdateAsync(CryptoKey key, CancellationToken ct = default);
}
