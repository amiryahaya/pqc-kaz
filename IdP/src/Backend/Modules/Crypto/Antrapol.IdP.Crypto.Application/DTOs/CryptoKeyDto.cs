using Antrapol.IdP.Crypto.Domain.Enums;

namespace Antrapol.IdP.Crypto.Application.DTOs;

public sealed record CryptoKeyDto(
    Guid Id,
    Guid? UserId,
    string Label,
    KeyAlgorithm Algorithm,
    KeyPurpose Purpose,
    KeyStatus Status,
    KeyStorageType StorageType,
    string KeyFingerprint,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? LastUsedAt,
    long UseCount,
    DateTimeOffset CreatedAt);

public sealed record KeyPairGenerationRequest(
    string Label,
    KeyAlgorithm Algorithm,
    KeyPurpose Purpose,
    KeyStorageType StorageType,
    DateTimeOffset? ExpiresAt);

public sealed record SignatureRequest(
    Guid KeyId,
    byte[] Data);

public sealed record SignatureResponse(
    byte[] Signature,
    KeyAlgorithm Algorithm,
    string KeyFingerprint);

public sealed record VerifyRequest(
    byte[] Data,
    byte[] Signature,
    byte[] PublicKey,
    KeyAlgorithm Algorithm);

public sealed record EncapsulateRequest(
    Guid KeyId);

public sealed record EncapsulateResponse(
    byte[] Ciphertext,
    byte[] SharedSecret);

public sealed record DecapsulateRequest(
    Guid KeyId,
    byte[] Ciphertext);
