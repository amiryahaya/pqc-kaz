using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.SharedKernel.Entities;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents an authentication credential for a user.
/// </summary>
public sealed class UserCredential : AuditableEntity
{
    public Guid UserId { get; private set; }
    public CredentialType Type { get; private set; }
    public string Name { get; private set; } = null!;
    public byte[] CredentialData { get; private set; } = [];
    public byte[]? PublicKey { get; private set; }
    public string? DeviceInfo { get; private set; }
    public DateTimeOffset? LastUsedAt { get; private set; }
    public int UseCount { get; private set; }
    public bool IsEnabled { get; private set; }

    private UserCredential() { }

    public static UserCredential CreatePasskey(
        Guid userId,
        string name,
        byte[] credentialId,
        byte[] publicKey,
        string? deviceInfo = null,
        Guid? createdBy = null)
    {
        var credential = new UserCredential
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            Type = CredentialType.Passkey,
            Name = name,
            CredentialData = credentialId,
            PublicKey = publicKey,
            DeviceInfo = deviceInfo,
            IsEnabled = true,
            UseCount = 0
        };

        credential.SetCreated(createdBy);
        return credential;
    }

    public static UserCredential CreateTotp(
        Guid userId,
        string name,
        byte[] secret,
        Guid? createdBy = null)
    {
        var credential = new UserCredential
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            Type = CredentialType.Totp,
            Name = name,
            CredentialData = secret,
            IsEnabled = true,
            UseCount = 0
        };

        credential.SetCreated(createdBy);
        return credential;
    }

    public static UserCredential CreateRecoveryCode(
        Guid userId,
        byte[] hashedCode,
        Guid? createdBy = null)
    {
        var credential = new UserCredential
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            Type = CredentialType.RecoveryCode,
            Name = "Recovery Code",
            CredentialData = hashedCode,
            IsEnabled = true,
            UseCount = 0
        };

        credential.SetCreated(createdBy);
        return credential;
    }

    public void RecordUsage()
    {
        LastUsedAt = DateTimeOffset.UtcNow;
        UseCount++;
    }

    public void Enable() => IsEnabled = true;

    public void Disable() => IsEnabled = false;

    public void UpdateName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Name = name;
    }
}
