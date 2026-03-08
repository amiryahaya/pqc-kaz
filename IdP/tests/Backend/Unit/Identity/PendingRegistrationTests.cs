using FluentAssertions;
using PqcIdentity.Identity.Domain.Entities;
using PqcIdentity.Identity.Domain.Enums;
using PqcIdentity.Identity.Domain.ValueObjects;

namespace PqcIdentity.Tests.Unit.Identity;

/// <summary>
/// Unit tests for PendingRegistration entity.
/// </summary>
public class PendingRegistrationTests
{
    private static readonly TimeSpan OtpValidityDuration = TimeSpan.FromMinutes(10);

    [Fact]
    public void Create_WithValidData_ShouldCreatePendingRegistration()
    {
        // Arrange
        var fullName = "Ahmad bin Abdullah";
        var myKadNumber = "901201145678";
        var email = Email.Create("ahmad@example.com");
        var otpHash = "hash123";

        // Act
        var registration = PendingRegistration.Create(
            fullName: fullName,
            myKadNumber: myKadNumber,
            email: email,
            emailOtpHash: otpHash,
            otpValidityDuration: OtpValidityDuration);

        // Assert
        registration.Should().NotBeNull();
        registration.Id.Should().NotBeEmpty();
        registration.FullName.Should().Be(fullName);
        registration.MyKadNumber.Should().Be(myKadNumber);
        registration.Email.Should().Be(email);
        registration.EmailOtpHash.Should().Be(otpHash);
        registration.Status.Should().Be(RegistrationStatus.Pending);
        registration.TrackingId.Should().NotBeEmpty();
    }

    [Fact]
    public void Create_WithDeviceInfo_ShouldSetDeviceFields()
    {
        // Arrange
        var email = Email.Create("test@example.com");
        var deviceId = "device-123";
        var deviceName = "Samsung Galaxy S24";
        var platform = DevicePlatform.Android;
        var osVersion = "14.0";
        var appVersion = "1.0.0";

        // Act
        var registration = PendingRegistration.Create(
            fullName: "Test User",
            myKadNumber: "901201145678",
            email: email,
            emailOtpHash: "hash",
            otpValidityDuration: OtpValidityDuration,
            deviceId: deviceId,
            deviceName: deviceName,
            devicePlatform: platform,
            deviceOsVersion: osVersion,
            appVersion: appVersion);

        // Assert
        registration.DeviceId.Should().Be(deviceId);
        registration.DeviceName.Should().Be(deviceName);
        registration.DevicePlatform.Should().Be(platform);
        registration.DeviceOsVersion.Should().Be(osVersion);
        registration.AppVersion.Should().Be(appVersion);
    }

    [Fact]
    public void Create_WithLegacyFactory_ShouldWork()
    {
        // Arrange
        var email = Email.Create("test@example.com");
        var otpHash = "hash123";

        // Act
        var registration = PendingRegistration.Create(email, otpHash, OtpValidityDuration);

        // Assert
        registration.Should().NotBeNull();
        registration.Email.Should().Be(email);
        registration.EmailOtpHash.Should().Be(otpHash);
        registration.Status.Should().Be(RegistrationStatus.Pending);
    }

    [Fact]
    public void CanVerifyEmailOtp_WithValidOtp_ShouldReturnTrue()
    {
        // Arrange
        var registration = CreateValidRegistration();

        // Act & Assert
        registration.CanVerifyEmailOtp().Should().BeTrue();
    }

    [Fact]
    public void CanVerifyEmailOtp_WhenExpired_ShouldReturnFalse()
    {
        // Arrange
        var email = Email.Create("test@example.com");
        var registration = PendingRegistration.Create(
            email,
            "hash",
            TimeSpan.FromMinutes(-1)); // Already expired

        // Act & Assert
        registration.CanVerifyEmailOtp().Should().BeFalse();
    }

    [Fact]
    public void CanVerifyEmailOtp_WhenMaxAttemptsReached_ShouldReturnFalse()
    {
        // Arrange
        var registration = CreateValidRegistration();

        // Simulate max attempts
        for (int i = 0; i < 5; i++)
        {
            registration.IncrementEmailOtpAttempts();
        }

        // Act & Assert
        registration.CanVerifyEmailOtp().Should().BeFalse();
    }

    [Fact]
    public void IsEmailOtpExpired_WhenPastExpiration_ShouldReturnTrue()
    {
        // Arrange
        var email = Email.Create("test@example.com");
        var registration = PendingRegistration.Create(
            email,
            "hash",
            TimeSpan.FromMinutes(-1)); // Already expired

        // Act & Assert
        registration.IsEmailOtpExpired().Should().BeTrue();
    }

    [Fact]
    public void IsEmailOtpExpired_WhenNotExpired_ShouldReturnFalse()
    {
        // Arrange
        var registration = CreateValidRegistration();

        // Act & Assert
        registration.IsEmailOtpExpired().Should().BeFalse();
    }

    [Fact]
    public void IncrementEmailOtpAttempts_ShouldIncreaseCount()
    {
        // Arrange
        var registration = CreateValidRegistration();
        var initialAttempts = registration.EmailOtpAttempts;

        // Act
        registration.IncrementEmailOtpAttempts();

        // Assert
        registration.EmailOtpAttempts.Should().Be(initialAttempts + 1);
    }

    [Fact]
    public void MarkEmailVerified_WhenPending_ShouldUpdateStatus()
    {
        // Arrange
        var registration = CreateValidRegistration();

        // Act
        registration.MarkEmailVerified();

        // Assert
        registration.Status.Should().Be(RegistrationStatus.EmailVerified);
    }

    [Fact]
    public void MarkEmailVerified_WhenExpired_ShouldThrow()
    {
        // Arrange
        var email = Email.Create("test@example.com");
        var registration = PendingRegistration.Create(
            email,
            "hash",
            TimeSpan.FromMinutes(-1)); // Already expired

        // Act & Assert
        var act = () => registration.MarkEmailVerified();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void SetPhoneOtp_AfterEmailVerified_ShouldSetPhoneOtpFields()
    {
        // Arrange
        var registration = CreateValidRegistration();
        registration.MarkEmailVerified();
        var phoneNumber = PhoneNumber.Create("+60123456789");
        var phoneOtpHash = "phonehash";

        // Act
        registration.SetPhoneOtp(phoneNumber, phoneOtpHash, OtpValidityDuration);

        // Assert
        registration.PhoneNumber.Should().Be(phoneNumber);
        registration.PhoneOtpHash.Should().Be(phoneOtpHash);
        registration.PhoneOtpExpiresAt.Should().NotBeNull();
        registration.PhoneOtpAttempts.Should().Be(0);
    }

    [Fact]
    public void SetPhoneOtp_WhenNotEmailVerified_ShouldThrow()
    {
        // Arrange
        var registration = CreateValidRegistration();
        var phoneNumber = PhoneNumber.Create("+60123456789");

        // Act & Assert
        var act = () => registration.SetPhoneOtp(phoneNumber, "hash", OtpValidityDuration);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void MarkPhoneVerified_AfterPhoneOtpSet_ShouldUpdateStatus()
    {
        // Arrange
        var registration = CreateValidRegistration();
        registration.MarkEmailVerified();
        registration.SetPhoneOtp(PhoneNumber.Create("+60123456789"), "hash", OtpValidityDuration);

        // Act
        registration.MarkPhoneVerified();

        // Assert
        registration.Status.Should().Be(RegistrationStatus.PhoneVerified);
    }

    [Fact]
    public void MarkCsrSubmitted_AfterPhoneVerified_ShouldUpdateStatus()
    {
        // Arrange
        var registration = CreateValidRegistration();
        registration.MarkEmailVerified();
        registration.SetPhoneOtp(PhoneNumber.Create("+60123456789"), "hash", OtpValidityDuration);
        registration.MarkPhoneVerified();

        // Act
        registration.MarkCsrSubmitted();

        // Assert
        registration.Status.Should().Be(RegistrationStatus.CsrSubmitted);
    }

    [Fact]
    public void MarkCsrSubmitted_WhenNotPhoneVerified_ShouldThrow()
    {
        // Arrange
        var registration = CreateValidRegistration();
        registration.MarkEmailVerified();

        // Act & Assert
        var act = () => registration.MarkCsrSubmitted();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void MarkCertificatesIssued_AfterCsrSubmitted_ShouldUpdateStatus()
    {
        // Arrange
        var registration = CreateRegistrationAtCsrSubmitted();

        // Act
        registration.MarkCertificatesIssued();

        // Assert
        registration.Status.Should().Be(RegistrationStatus.CertificatesIssued);
    }

    [Fact]
    public void MarkCompleted_AfterCertificatesIssued_ShouldSetFinalStatus()
    {
        // Arrange
        var registration = CreateRegistrationAtCsrSubmitted();
        registration.MarkCertificatesIssued();

        // Act
        registration.MarkCompleted();

        // Assert
        registration.Status.Should().Be(RegistrationStatus.Completed);
    }

    [Fact]
    public void MarkRejected_ShouldSetRejectedStatus()
    {
        // Arrange
        var registration = CreateValidRegistration();

        // Act
        registration.MarkRejected("Test rejection reason");

        // Assert
        registration.Status.Should().Be(RegistrationStatus.Rejected);
    }

    private static PendingRegistration CreateValidRegistration()
    {
        var email = Email.Create("test@example.com");
        return PendingRegistration.Create(
            fullName: "Test User",
            myKadNumber: "901201145678",
            email: email,
            emailOtpHash: "hash123",
            otpValidityDuration: OtpValidityDuration);
    }

    private static PendingRegistration CreateRegistrationAtCsrSubmitted()
    {
        var registration = CreateValidRegistration();
        registration.MarkEmailVerified();
        registration.SetPhoneOtp(PhoneNumber.Create("+60123456789"), "hash", OtpValidityDuration);
        registration.MarkPhoneVerified();
        registration.MarkCsrSubmitted();
        return registration;
    }
}
