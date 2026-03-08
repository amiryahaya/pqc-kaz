using Antrapol.IdP.Identity.Domain.Enums;
using Antrapol.IdP.Identity.Domain.Events;
using Antrapol.IdP.Identity.Domain.ValueObjects;
using Antrapol.IdP.SharedKernel.Entities;
using Antrapol.IdP.SharedKernel.Events;

namespace Antrapol.IdP.Identity.Domain.Entities;

/// <summary>
/// Represents a user in the identity system.
/// Note: Single device policy - each user can only have ONE registered device.
/// </summary>
public sealed class User : AuditableEntity, IHasDomainEvents
{
    private readonly List<IDomainEvent> _domainEvents = [];
    private readonly List<UserCredential> _credentials = [];
    private readonly List<UserSession> _sessions = [];

    // === Identity Information ===
    /// <summary>
    /// User's full name as per MyKad (Malaysian IC).
    /// </summary>
    public string FullName { get; private set; } = null!;

    /// <summary>
    /// Malaysian IC number (MyKad). Unique identifier for Malaysian citizens.
    /// Format: 12 digits (YYMMDD-PB-###G)
    /// </summary>
    public string MyKadNumber { get; private set; } = null!;

    public Email Email { get; private set; } = null!;
    public PhoneNumber? PhoneNumber { get; private set; }
    public string? DisplayName { get; private set; }
    public UserStatus Status { get; private set; }
    public bool EmailVerified { get; private set; }
    public bool PhoneVerified { get; private set; }
    public DateTimeOffset? LastLoginAt { get; private set; }
    public int FailedLoginAttempts { get; private set; }
    public DateTimeOffset? LockoutEndAt { get; private set; }

    /// <summary>
    /// The user's registered device (single device policy - only one device allowed).
    /// </summary>
    public UserDevice? Device { get; private set; }

    /// <summary>
    /// Whether the user has a registered device.
    /// </summary>
    public bool HasRegisteredDevice => Device is not null && Device.Status == DeviceStatus.Active;

    public IReadOnlyCollection<UserCredential> Credentials => _credentials.AsReadOnly();
    public IReadOnlyCollection<UserSession> Sessions => _sessions.AsReadOnly();
    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    private User() { }

    public static User Create(
        string fullName,
        string myKadNumber,
        Email email,
        PhoneNumber? phoneNumber = null,
        string? displayName = null,
        Guid? createdBy = null)
    {
        var user = new User
        {
            Id = Guid.CreateVersion7(),
            FullName = fullName,
            MyKadNumber = myKadNumber,
            Email = email,
            PhoneNumber = phoneNumber,
            DisplayName = displayName ?? fullName,
            Status = UserStatus.PendingVerification,
            EmailVerified = false,
            PhoneVerified = false,
            FailedLoginAttempts = 0
        };

        user.SetCreated(createdBy);
        user._domainEvents.Add(new UserCreatedEvent(user.Id, email.Value));

        return user;
    }

    // Legacy factory for backward compatibility
    public static User Create(Email email, string? displayName = null, Guid? createdBy = null)
    {
        return Create(
            fullName: displayName ?? "Unknown",
            myKadNumber: "000000000000",
            email: email,
            phoneNumber: null,
            displayName: displayName,
            createdBy: createdBy);
    }

    public void VerifyEmail()
    {
        if (EmailVerified)
            return;

        EmailVerified = true;
        if (Status == UserStatus.PendingVerification)
        {
            Status = UserStatus.Active;
        }

        _domainEvents.Add(new UserEmailVerifiedEvent(Id));
    }

    public void SetPhoneNumber(PhoneNumber phoneNumber)
    {
        PhoneNumber = phoneNumber;
        PhoneVerified = false;
    }

    public void VerifyPhone()
    {
        if (PhoneNumber is null)
            throw new InvalidOperationException("Cannot verify phone when no phone number is set.");

        PhoneVerified = true;
        _domainEvents.Add(new UserPhoneVerifiedEvent(Id));
    }

    public void UpdateDisplayName(string? displayName)
    {
        DisplayName = displayName;
    }

    public void RecordSuccessfulLogin()
    {
        LastLoginAt = DateTimeOffset.UtcNow;
        FailedLoginAttempts = 0;
        LockoutEndAt = null;
        _domainEvents.Add(new UserLoggedInEvent(Id));
    }

    public void RecordFailedLogin(int maxAttempts = 5, TimeSpan? lockoutDuration = null)
    {
        FailedLoginAttempts++;

        if (FailedLoginAttempts >= maxAttempts)
        {
            Status = UserStatus.Locked;
            LockoutEndAt = DateTimeOffset.UtcNow.Add(lockoutDuration ?? TimeSpan.FromMinutes(15));
            _domainEvents.Add(new UserLockedOutEvent(Id, LockoutEndAt.Value));
        }
    }

    public bool IsLockedOut()
    {
        if (Status != UserStatus.Locked)
            return false;

        if (LockoutEndAt.HasValue && LockoutEndAt.Value <= DateTimeOffset.UtcNow)
        {
            // Lockout expired, unlock the user
            Status = UserStatus.Active;
            FailedLoginAttempts = 0;
            LockoutEndAt = null;
            return false;
        }

        return true;
    }

    public void Suspend(Guid? suspendedBy = null)
    {
        if (Status == UserStatus.Deactivated)
            throw new InvalidOperationException("Cannot suspend a deactivated user.");

        Status = UserStatus.Suspended;
        SetUpdated(suspendedBy);
        _domainEvents.Add(new UserSuspendedEvent(Id));
    }

    public void Activate(Guid? activatedBy = null)
    {
        if (Status == UserStatus.Deactivated)
            throw new InvalidOperationException("Cannot activate a deactivated user.");

        if (!EmailVerified)
        {
            Status = UserStatus.PendingVerification;
        }
        else
        {
            Status = UserStatus.Active;
        }

        FailedLoginAttempts = 0;
        LockoutEndAt = null;
        SetUpdated(activatedBy);
    }

    public void Deactivate(Guid? deactivatedBy = null)
    {
        Status = UserStatus.Deactivated;
        SetDeleted(deactivatedBy);
        _domainEvents.Add(new UserDeactivatedEvent(Id));
    }

    public void AddCredential(UserCredential credential)
    {
        _credentials.Add(credential);
    }

    public void RemoveCredential(Guid credentialId)
    {
        var credential = _credentials.FirstOrDefault(c => c.Id == credentialId);
        if (credential is not null)
        {
            _credentials.Remove(credential);
        }
    }

    public void AddSession(UserSession session)
    {
        _sessions.Add(session);
    }

    public void RemoveSession(Guid sessionId)
    {
        var session = _sessions.FirstOrDefault(s => s.Id == sessionId);
        if (session is not null)
        {
            _sessions.Remove(session);
        }
    }

    /// <summary>
    /// Registers a device for this user.
    /// Due to single device policy, any existing device will be deactivated.
    /// </summary>
    public void RegisterDevice(UserDevice device)
    {
        if (Status == UserStatus.Deactivated)
            throw new InvalidOperationException("Cannot register device for a deactivated user.");

        // Deactivate any existing device (single device policy)
        Device?.Deactivate();

        Device = device;
    }

    /// <summary>
    /// Gets the current device if active, otherwise returns null.
    /// </summary>
    public UserDevice? GetActiveDevice()
    {
        if (Device is null || Device.Status != DeviceStatus.Active)
            return null;

        return Device;
    }

    public void ClearDomainEvents() => _domainEvents.Clear();
}
