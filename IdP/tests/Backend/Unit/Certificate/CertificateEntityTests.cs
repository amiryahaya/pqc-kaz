using FluentAssertions;
using PqcIdentity.Certificate.Domain.Enums;
using CertificateEntity = PqcIdentity.Certificate.Domain.Entities.Certificate;

namespace PqcIdentity.Tests.Unit.Certificate;

/// <summary>
/// Unit tests for Certificate entity.
/// </summary>
public class CertificateEntityTests
{
    [Fact]
    public void Create_WithValidData_ShouldCreateCertificate()
    {
        // Arrange
        var serialNumber = "abc123def456";
        var subjectDn = "CN=Test User, SERIALNUMBER=901201145678, C=MY";
        var issuerDn = "CN=PQC Identity CA, O=Malaysia Digital ID, C=MY";
        var publicKey = new byte[2592]; // KAZ-SIGN-256 public key size
        var certificateData = new byte[1000];
        var thumbprint = "abcdef1234567890";
        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddYears(1);

        // Act
        var cert = CertificateEntity.Create(
            serialNumber: serialNumber,
            subjectDn: subjectDn,
            issuerDn: issuerDn,
            issuerId: null,
            type: CertificateType.EndEntitySigning,
            algorithm: SignatureAlgorithm.KazSign256,
            publicKey: publicKey,
            certificateData: certificateData,
            thumbprint: thumbprint,
            notBefore: notBefore,
            notAfter: notAfter);

        // Assert
        cert.Should().NotBeNull();
        cert.Id.Should().NotBeEmpty();
        cert.SerialNumber.Should().Be(serialNumber);
        cert.SubjectDn.Should().Be(subjectDn);
        cert.IssuerDn.Should().Be(issuerDn);
        cert.Type.Should().Be(CertificateType.EndEntitySigning);
        cert.Algorithm.Should().Be(SignatureAlgorithm.KazSign256);
        cert.Status.Should().Be(CertificateStatus.Active);
        cert.PublicKey.Should().BeEquivalentTo(publicKey);
        cert.CertificateData.Should().BeEquivalentTo(certificateData);
        cert.Thumbprint.Should().Be(thumbprint);
        cert.NotBefore.Should().Be(notBefore);
        cert.NotAfter.Should().Be(notAfter);
    }

    [Fact]
    public void Create_WithUserId_ShouldSetUserId()
    {
        // Arrange
        var userId = Guid.CreateVersion7();

        // Act
        var cert = CreateValidCertificate(userId: userId);

        // Assert
        cert.UserId.Should().Be(userId);
    }

    [Fact]
    public void IsValid_WhenActiveAndWithinValidity_ShouldReturnTrue()
    {
        // Arrange
        var cert = CreateValidCertificate();

        // Act & Assert
        cert.IsValid().Should().BeTrue();
    }

    [Fact]
    public void IsValid_WhenRevoked_ShouldReturnFalse()
    {
        // Arrange
        var cert = CreateValidCertificate();
        cert.Revoke(RevocationReason.KeyCompromise);

        // Act & Assert
        cert.IsValid().Should().BeFalse();
    }

    [Fact]
    public void IsExpired_WhenPastNotAfter_ShouldReturnTrue()
    {
        // Arrange
        var cert = CreateCertificateWithDates(
            notBefore: DateTimeOffset.UtcNow.AddDays(-30),
            notAfter: DateTimeOffset.UtcNow.AddDays(-1));

        // Act & Assert
        cert.IsExpired().Should().BeTrue();
    }

    [Fact]
    public void IsExpired_WhenBeforeNotAfter_ShouldReturnFalse()
    {
        // Arrange
        var cert = CreateValidCertificate();

        // Act & Assert
        cert.IsExpired().Should().BeFalse();
    }

    [Fact]
    public void Revoke_ShouldSetStatusAndRevocationFields()
    {
        // Arrange
        var cert = CreateValidCertificate();
        var beforeRevocation = DateTimeOffset.UtcNow;

        // Act
        cert.Revoke(RevocationReason.KeyCompromise);

        // Assert
        cert.Status.Should().Be(CertificateStatus.Revoked);
        cert.RevocationReason.Should().Be(RevocationReason.KeyCompromise);
        cert.RevokedAt.Should().NotBeNull();
        cert.RevokedAt.Should().BeOnOrAfter(beforeRevocation);
    }

    [Fact]
    public void Revoke_WhenAlreadyRevoked_ShouldNotChangeFields()
    {
        // Arrange
        var cert = CreateValidCertificate();
        cert.Revoke(RevocationReason.KeyCompromise);
        var originalRevokedAt = cert.RevokedAt;

        // Act
        cert.Revoke(RevocationReason.CaCompromise);

        // Assert
        cert.RevocationReason.Should().Be(RevocationReason.KeyCompromise);
        cert.RevokedAt.Should().Be(originalRevokedAt);
    }

    [Fact]
    public void Suspend_WhenActive_ShouldChangeStatus()
    {
        // Arrange
        var cert = CreateValidCertificate();

        // Act
        cert.Suspend();

        // Assert
        cert.Status.Should().Be(CertificateStatus.Suspended);
    }

    [Fact]
    public void Suspend_WhenNotActive_ShouldThrow()
    {
        // Arrange
        var cert = CreateValidCertificate();
        cert.Revoke(RevocationReason.Unspecified);

        // Act & Assert
        var act = () => cert.Suspend();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void Reinstate_WhenSuspended_ShouldChangeStatusToActive()
    {
        // Arrange
        var cert = CreateValidCertificate();
        cert.Suspend();

        // Act
        cert.Reinstate();

        // Assert
        cert.Status.Should().Be(CertificateStatus.Active);
    }

    [Fact]
    public void Reinstate_WhenNotSuspended_ShouldThrow()
    {
        // Arrange
        var cert = CreateValidCertificate();

        // Act & Assert
        var act = () => cert.Reinstate();
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void MarkExpired_ShouldChangeStatus()
    {
        // Arrange
        var cert = CreateValidCertificate();

        // Act
        cert.MarkExpired();

        // Assert
        cert.Status.Should().Be(CertificateStatus.Expired);
    }

    [Fact]
    public void MarkExpired_WhenRevoked_ShouldNotChange()
    {
        // Arrange
        var cert = CreateValidCertificate();
        cert.Revoke(RevocationReason.Unspecified);

        // Act
        cert.MarkExpired();

        // Assert
        cert.Status.Should().Be(CertificateStatus.Revoked);
    }

    [Fact]
    public void Create_ShouldRaiseCertificateIssuedEvent()
    {
        // Arrange & Act
        var cert = CreateValidCertificate();

        // Assert
        cert.DomainEvents.Should().ContainSingle();
        cert.DomainEvents.First().Should().BeOfType<PqcIdentity.Certificate.Domain.Events.CertificateIssuedEvent>();
    }

    [Fact]
    public void Revoke_ShouldRaiseCertificateRevokedEvent()
    {
        // Arrange
        var cert = CreateValidCertificate();
        cert.ClearDomainEvents();

        // Act
        cert.Revoke(RevocationReason.KeyCompromise);

        // Assert
        cert.DomainEvents.Should().ContainSingle();
        cert.DomainEvents.First().Should().BeOfType<PqcIdentity.Certificate.Domain.Events.CertificateRevokedEvent>();
    }

    private static CertificateEntity CreateValidCertificate(Guid? userId = null)
    {
        return CreateCertificateWithDates(
            notBefore: DateTimeOffset.UtcNow,
            notAfter: DateTimeOffset.UtcNow.AddYears(1),
            userId: userId);
    }

    private static CertificateEntity CreateCertificateWithDates(
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        Guid? userId = null)
    {
        return CertificateEntity.Create(
            serialNumber: Guid.NewGuid().ToString("N"),
            subjectDn: "CN=Test User, C=MY",
            issuerDn: "CN=Test CA, C=MY",
            issuerId: null,
            type: CertificateType.EndEntitySigning,
            algorithm: SignatureAlgorithm.KazSign256,
            publicKey: new byte[2592],
            certificateData: new byte[1000],
            thumbprint: "thumbprint123",
            notBefore: notBefore,
            notAfter: notAfter,
            userId: userId);
    }
}
