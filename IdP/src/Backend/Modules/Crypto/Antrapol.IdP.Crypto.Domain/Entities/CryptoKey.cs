using Antrapol.IdP.Crypto.Domain.Enums;
using Antrapol.IdP.Crypto.Domain.Events;
using Antrapol.IdP.SharedKernel.Entities;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Crypto.Domain.Entities;

/// <summary>
/// Represents a cryptographic key pair.
/// </summary>
public sealed class CryptoKey : AuditableEntity, IHasDomainEvents
{
    private readonly List<IDomainEvent> _domainEvents = [];

    public Guid? UserId { get; private set; }
    public string Label { get; private set; } = null!;
    public KeyAlgorithm Algorithm { get; private set; }
    public KeyPurpose Purpose { get; private set; }
    public KeyStatus Status { get; private set; }
    public KeyStorageType StorageType { get; private set; }
    public byte[] PublicKey { get; private set; } = [];
    public byte[]? EncryptedPrivateKey { get; private set; }
    public string? HsmKeyHandle { get; private set; }
    public string? CloudKmsKeyId { get; private set; }
    public string KeyFingerprint { get; private set; } = null!;
    public DateTimeOffset? ExpiresAt { get; private set; }
    public DateTimeOffset? LastUsedAt { get; private set; }
    public long UseCount { get; private set; }

    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    private CryptoKey() { }

    public static CryptoKey CreateSoftwareKey(
        string label,
        KeyAlgorithm algorithm,
        KeyPurpose purpose,
        byte[] publicKey,
        byte[] encryptedPrivateKey,
        string keyFingerprint,
        DateTimeOffset? expiresAt = null,
        Guid? userId = null,
        Guid? createdBy = null)
    {
        var key = new CryptoKey
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            Label = label,
            Algorithm = algorithm,
            Purpose = purpose,
            Status = KeyStatus.Active,
            StorageType = KeyStorageType.Software,
            PublicKey = publicKey,
            EncryptedPrivateKey = encryptedPrivateKey,
            KeyFingerprint = keyFingerprint,
            ExpiresAt = expiresAt,
            UseCount = 0
        };

        key.SetCreated(createdBy);
        key._domainEvents.Add(new KeyGeneratedEvent(key.Id, key.Label, key.Algorithm, key.StorageType));

        return key;
    }

    public static CryptoKey CreateHsmKey(
        string label,
        KeyAlgorithm algorithm,
        KeyPurpose purpose,
        byte[] publicKey,
        string hsmKeyHandle,
        string keyFingerprint,
        DateTimeOffset? expiresAt = null,
        Guid? userId = null,
        Guid? createdBy = null)
    {
        var key = new CryptoKey
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            Label = label,
            Algorithm = algorithm,
            Purpose = purpose,
            Status = KeyStatus.Active,
            StorageType = KeyStorageType.Hsm,
            PublicKey = publicKey,
            HsmKeyHandle = hsmKeyHandle,
            KeyFingerprint = keyFingerprint,
            ExpiresAt = expiresAt,
            UseCount = 0
        };

        key.SetCreated(createdBy);
        key._domainEvents.Add(new KeyGeneratedEvent(key.Id, key.Label, key.Algorithm, key.StorageType));

        return key;
    }

    public bool IsUsable()
    {
        if (Status != KeyStatus.Active)
            return false;

        if (ExpiresAt.HasValue && ExpiresAt.Value <= DateTimeOffset.UtcNow)
            return false;

        return true;
    }

    public void RecordUsage()
    {
        LastUsedAt = DateTimeOffset.UtcNow;
        UseCount++;
    }

    public void Disable(Guid? disabledBy = null)
    {
        if (Status == KeyStatus.Destroyed)
            throw new InvalidOperationException("Cannot disable a destroyed key.");

        Status = KeyStatus.Disabled;
        SetUpdated(disabledBy);
        _domainEvents.Add(new KeyDisabledEvent(Id, Label));
    }

    public void Enable(Guid? enabledBy = null)
    {
        if (Status != KeyStatus.Disabled)
            throw new InvalidOperationException("Only disabled keys can be enabled.");

        Status = KeyStatus.Active;
        SetUpdated(enabledBy);
        _domainEvents.Add(new KeyEnabledEvent(Id, Label));
    }

    public void MarkCompromised(Guid? markedBy = null)
    {
        if (Status == KeyStatus.Destroyed)
            return;

        Status = KeyStatus.Compromised;
        SetUpdated(markedBy);
        _domainEvents.Add(new KeyCompromisedEvent(Id, Label));
    }

    public void Destroy(Guid? destroyedBy = null)
    {
        if (Status == KeyStatus.Destroyed)
            return;

        Status = KeyStatus.Destroyed;
        EncryptedPrivateKey = null; // Clear sensitive data
        SetDeleted(destroyedBy);
        _domainEvents.Add(new KeyDestroyedEvent(Id, Label));
    }

    public void UpdateLabel(string label, Guid? updatedBy = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        Label = label;
        SetUpdated(updatedBy);
    }

    public void ClearDomainEvents() => _domainEvents.Clear();
}
