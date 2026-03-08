using FluentAssertions;
using PqcIdentity.Identity.Domain.Entities;
using PqcIdentity.Identity.Domain.Enums;
using PqcIdentity.Identity.Domain.ValueObjects;

namespace PqcIdentity.Tests.Unit.Identity;

/// <summary>
/// Unit tests for User entity.
/// </summary>
public class UserTests
{
    [Fact]
    public void Create_WithFullProfile_ShouldCreateUser()
    {
        // Arrange
        var fullName = "Ahmad bin Abdullah";
        var myKadNumber = "901201145678";
        var email = Email.Create("ahmad@example.com");
        var phone = PhoneNumber.Create("+60123456789");

        // Act
        var user = User.Create(
            fullName: fullName,
            myKadNumber: myKadNumber,
            email: email,
            phoneNumber: phone);

        // Assert
        user.Should().NotBeNull();
        user.Id.Should().NotBeEmpty();
        user.FullName.Should().Be(fullName);
        user.MyKadNumber.Should().Be(myKadNumber);
        user.Email.Should().Be(email);
        user.PhoneNumber.Should().Be(phone);
        user.Status.Should().Be(UserStatus.PendingVerification);
        user.EmailVerified.Should().BeFalse();
        user.PhoneVerified.Should().BeFalse();
    }

    [Fact]
    public void Create_WithEmailOnly_ShouldCreateUserWithLegacyDefaults()
    {
        // Arrange
        var email = Email.Create("test@example.com");

        // Act
        var user = User.Create(email: email, displayName: "Test User");

        // Assert
        user.Should().NotBeNull();
        user.Email.Should().Be(email);
        user.DisplayName.Should().Be("Test User");
        user.Status.Should().Be(UserStatus.PendingVerification);
    }

    [Fact]
    public void Create_ShouldRaiseUserCreatedEvent()
    {
        // Arrange & Act
        var email = Email.Create("test@example.com");
        var user = User.Create(email);

        // Assert
        user.DomainEvents.Should().ContainSingle();
        user.DomainEvents.First().Should().BeOfType<PqcIdentity.Identity.Domain.Events.UserCreatedEvent>();
    }

    [Fact]
    public void VerifyEmail_WhenNotVerified_ShouldSetEmailVerifiedAndActivateUser()
    {
        // Arrange
        var user = CreateValidUser();
        user.EmailVerified.Should().BeFalse();

        // Act
        user.VerifyEmail();

        // Assert
        user.EmailVerified.Should().BeTrue();
        user.Status.Should().Be(UserStatus.Active);
    }

    [Fact]
    public void VerifyEmail_WhenAlreadyVerified_ShouldNotRaiseEvent()
    {
        // Arrange
        var user = CreateValidUser();
        user.VerifyEmail();
        user.ClearDomainEvents();

        // Act
        user.VerifyEmail();

        // Assert
        user.DomainEvents.Should().BeEmpty();
    }

    [Fact]
    public void SetPhoneNumber_ShouldSetPhoneAndClearVerification()
    {
        // Arrange
        var user = CreateValidUser();
        var phone = PhoneNumber.Create("+60123456789");

        // Act
        user.SetPhoneNumber(phone);

        // Assert
        user.PhoneNumber.Should().Be(phone);
        user.PhoneVerified.Should().BeFalse();
    }

    [Fact]
    public void VerifyPhone_WithPhoneNumberSet_ShouldSetPhoneVerified()
    {
        // Arrange
        var user = CreateValidUser();
        user.SetPhoneNumber(PhoneNumber.Create("+60123456789"));

        // Act
        user.VerifyPhone();

        // Assert
        user.PhoneVerified.Should().BeTrue();
    }

    [Fact]
    public void VerifyPhone_WithoutPhoneNumber_ShouldThrow()
    {
        // Arrange
        var user = CreateValidUser();

        // Act & Assert
        var act = () => user.VerifyPhone();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Suspend_WhenActive_ShouldSetStatusToSuspended()
    {
        // Arrange
        var user = CreateValidUser();
        user.VerifyEmail();

        // Act
        user.Suspend();

        // Assert
        user.Status.Should().Be(UserStatus.Suspended);
    }

    [Fact]
    public void Suspend_WhenDeactivated_ShouldThrow()
    {
        // Arrange
        var user = CreateValidUser();
        user.Deactivate();

        // Act & Assert
        var act = () => user.Suspend();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Activate_WhenSuspended_ShouldSetStatusToActive()
    {
        // Arrange
        var user = CreateValidUser();
        user.VerifyEmail();
        user.Suspend();

        // Act
        user.Activate();

        // Assert
        user.Status.Should().Be(UserStatus.Active);
    }

    [Fact]
    public void Activate_WhenNotVerified_ShouldSetStatusToPendingVerification()
    {
        // Arrange
        var user = CreateValidUser();
        user.Suspend();

        // Act
        user.Activate();

        // Assert
        user.Status.Should().Be(UserStatus.PendingVerification);
    }

    [Fact]
    public void Deactivate_ShouldSetStatusToDeactivated()
    {
        // Arrange
        var user = CreateValidUser();

        // Act
        user.Deactivate();

        // Assert
        user.Status.Should().Be(UserStatus.Deactivated);
    }

    [Fact]
    public void RecordSuccessfulLogin_ShouldUpdateLastLoginAndClearFailedAttempts()
    {
        // Arrange
        var user = CreateValidUser();
        var beforeLogin = DateTimeOffset.UtcNow;

        // Act
        user.RecordSuccessfulLogin();

        // Assert
        user.LastLoginAt.Should().NotBeNull();
        user.LastLoginAt.Should().BeOnOrAfter(beforeLogin);
        user.FailedLoginAttempts.Should().Be(0);
    }

    [Fact]
    public void RecordFailedLogin_ShouldIncrementAttempts()
    {
        // Arrange
        var user = CreateValidUser();

        // Act
        user.RecordFailedLogin();
        user.RecordFailedLogin();

        // Assert
        user.FailedLoginAttempts.Should().Be(2);
    }

    [Fact]
    public void RecordFailedLogin_WhenMaxAttemptsReached_ShouldLockUser()
    {
        // Arrange
        var user = CreateValidUser();

        // Act
        for (int i = 0; i < 5; i++)
        {
            user.RecordFailedLogin();
        }

        // Assert
        user.Status.Should().Be(UserStatus.Locked);
        user.LockoutEndAt.Should().NotBeNull();
    }

    [Fact]
    public void IsLockedOut_WhenLocked_ShouldReturnTrue()
    {
        // Arrange
        var user = CreateValidUser();
        for (int i = 0; i < 5; i++)
        {
            user.RecordFailedLogin();
        }

        // Act & Assert
        user.IsLockedOut().Should().BeTrue();
    }

    [Fact]
    public void IsLockedOut_WhenNotLocked_ShouldReturnFalse()
    {
        // Arrange
        var user = CreateValidUser();

        // Act & Assert
        user.IsLockedOut().Should().BeFalse();
    }

    [Fact]
    public void UpdateDisplayName_ShouldChangeDisplayName()
    {
        // Arrange
        var user = CreateValidUser();
        var newName = "New Display Name";

        // Act
        user.UpdateDisplayName(newName);

        // Assert
        user.DisplayName.Should().Be(newName);
    }

    [Fact]
    public void HasRegisteredDevice_WithNoDevice_ShouldReturnFalse()
    {
        // Arrange
        var user = CreateValidUser();

        // Act & Assert
        user.HasRegisteredDevice.Should().BeFalse();
    }

    private static User CreateValidUser()
    {
        return User.Create(
            fullName: "Test User",
            myKadNumber: "901201145678",
            email: Email.Create("test@example.com"));
    }
}
