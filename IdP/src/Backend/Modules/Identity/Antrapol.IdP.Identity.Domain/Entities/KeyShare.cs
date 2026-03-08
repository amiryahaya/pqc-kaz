using Antrapol.IdP.SharedKernel.Entities;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents an encrypted key share stored on the backend.
/// Used for Shamir's Secret Sharing (2-of-3) of the user's private key.
///
/// Key shares:
/// - part_user: Stored on user's device (not in this entity)
/// - part_control: Stored by backend (encrypted with system KEM pubkey)
/// - part_recovery: Encrypted with user's recovery password
/// </summary>
public sealed class KeyShare : AuditableEntity
{
    /// <summary>
    /// Reference to the user who owns this key share.
    /// Set after registration completion.
    /// </summary>
    public Guid? UserId { get; private set; }

    /// <summary>
    /// Reference to the pending registration (before user creation).
    /// </summary>
    public Guid? RegistrationId { get; private set; }

    /// <summary>
    /// Type of key share.
    /// </summary>
    public KeyShareType Type { get; private set; }

    /// <summary>
    /// Encrypted share data.
    /// For part_control: KEM encapsulated with system public key.
    /// For part_recovery: AES-GCM encrypted with recovery password derived key.
    /// </summary>
    public byte[] EncryptedData { get; private set; } = [];

    /// <summary>
    /// For KEM-encrypted shares: the encapsulated key ciphertext.
    /// For AES-GCM encrypted shares: null.
    /// </summary>
    public byte[]? EncapsulatedKey { get; private set; }

    /// <summary>
    /// For AES-GCM encrypted shares: the nonce/IV.
    /// </summary>
    public byte[]? Nonce { get; private set; }

    /// <summary>
    /// For AES-GCM encrypted shares: the authentication tag.
    /// </summary>
    public byte[]? AuthTag { get; private set; }

    /// <summary>
    /// Salt used for key derivation (for recovery password shares).
    /// </summary>
    public byte[]? Salt { get; private set; }

    /// <summary>
    /// Index of this share in the Shamir scheme (1, 2, or 3).
    /// </summary>
    public int ShareIndex { get; private set; }

    /// <summary>
    /// Whether this share is still active (not revoked/replaced).
    /// </summary>
    public bool IsActive { get; private set; }

    private KeyShare() { }

    /// <summary>
    /// Creates a control share (part_control) encrypted with system KEM public key.
    /// </summary>
    public static KeyShare CreateControlShare(
        Guid registrationId,
        byte[] encryptedData,
        byte[] encapsulatedKey,
        int shareIndex,
        Guid? createdBy = null)
    {
        var share = new KeyShare
        {
            Id = Guid.CreateVersion7(),
            UserId = null, // Set after registration completion
            RegistrationId = registrationId,
            Type = KeyShareType.Control,
            EncryptedData = encryptedData,
            EncapsulatedKey = encapsulatedKey,
            ShareIndex = shareIndex,
            IsActive = true
        };

        share.SetCreated(createdBy);
        return share;
    }

    /// <summary>
    /// Creates a recovery share (part_recovery) encrypted with user's recovery password.
    /// </summary>
    public static KeyShare CreateRecoveryShare(
        Guid registrationId,
        byte[] encryptedData,
        byte[] nonce,
        byte[] authTag,
        byte[] salt,
        int shareIndex,
        Guid? createdBy = null)
    {
        var share = new KeyShare
        {
            Id = Guid.CreateVersion7(),
            UserId = null, // Set after registration completion
            RegistrationId = registrationId,
            Type = KeyShareType.Recovery,
            EncryptedData = encryptedData,
            Nonce = nonce,
            AuthTag = authTag,
            Salt = salt,
            ShareIndex = shareIndex,
            IsActive = true
        };

        share.SetCreated(createdBy);
        return share;
    }

    /// <summary>
    /// Links this key share to a user after registration completion.
    /// </summary>
    public void LinkToUser(Guid userId, Guid? linkedBy = null)
    {
        if (UserId.HasValue)
            throw new InvalidOperationException("Key share is already linked to a user.");

        UserId = userId;
        SetUpdated(linkedBy);
    }

    /// <summary>
    /// Deactivates this key share (e.g., when user changes recovery password).
    /// </summary>
    public void Deactivate(Guid? deactivatedBy = null)
    {
        IsActive = false;
        SetUpdated(deactivatedBy);
    }

    /// <summary>
    /// Replaces this share's encrypted data (e.g., when recovery password changes).
    /// </summary>
    public void UpdateEncryptedData(
        byte[] newEncryptedData,
        byte[]? nonce = null,
        byte[]? authTag = null,
        byte[]? salt = null,
        Guid? updatedBy = null)
    {
        EncryptedData = newEncryptedData;
        if (nonce is not null) Nonce = nonce;
        if (authTag is not null) AuthTag = authTag;
        if (salt is not null) Salt = salt;
        SetUpdated(updatedBy);
    }

    /// <summary>
    /// Reconstitutes a KeyShare entity from persistence.
    /// </summary>
    public static KeyShare Reconstitute(
        Guid id,
        Guid? userId,
        Guid? registrationId,
        KeyShareType type,
        byte[] encryptedData,
        byte[]? encapsulatedKey,
        byte[]? nonce,
        byte[]? authTag,
        byte[]? salt,
        int shareIndex,
        bool isActive,
        DateTimeOffset createdAt,
        Guid? createdBy,
        DateTimeOffset? updatedAt,
        Guid? updatedBy,
        int version)
    {
        return new KeyShare
        {
            Id = id,
            UserId = userId,
            RegistrationId = registrationId,
            Type = type,
            EncryptedData = encryptedData,
            EncapsulatedKey = encapsulatedKey,
            Nonce = nonce,
            AuthTag = authTag,
            Salt = salt,
            ShareIndex = shareIndex,
            IsActive = isActive,
            CreatedAt = createdAt,
            CreatedBy = createdBy,
            UpdatedAt = updatedAt,
            UpdatedBy = updatedBy,
            Version = version
        };
    }
}

/// <summary>
/// Type of key share in the 2-of-3 Shamir secret sharing scheme.
/// </summary>
public enum KeyShareType
{
    /// <summary>
    /// User's share (part_user) - stored on device only.
    /// This value is never used for KeyShare entity, just for reference.
    /// </summary>
    User = 0,

    /// <summary>
    /// Control share (part_control) - stored by backend, encrypted with system KEM pubkey.
    /// </summary>
    Control = 1,

    /// <summary>
    /// Recovery share (part_recovery) - encrypted with user's recovery password.
    /// </summary>
    Recovery = 2
}
