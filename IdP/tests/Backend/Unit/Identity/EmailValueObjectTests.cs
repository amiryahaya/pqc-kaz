using FluentAssertions;
using PqcIdentity.Identity.Domain.ValueObjects;

namespace PqcIdentity.Tests.Unit.Identity;

/// <summary>
/// Unit tests for Email value object.
/// </summary>
public class EmailValueObjectTests
{
    [Theory]
    [InlineData("test@example.com")]
    [InlineData("user.name@domain.co.uk")]
    [InlineData("first+last@company.org")]
    [InlineData("email@subdomain.domain.com")]
    public void Create_WithValidEmail_ShouldCreateEmail(string emailAddress)
    {
        // Act
        var email = Email.Create(emailAddress);

        // Assert
        email.Should().NotBeNull();
        email.Value.Should().Be(emailAddress.ToLowerInvariant());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Create_WithNullOrEmpty_ShouldThrow(string? emailAddress)
    {
        // Act
        var act = () => Email.Create(emailAddress!);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("invalid@")]
    [InlineData("@domain.com")]
    [InlineData("user@.com")]
    [InlineData("user@domain")]
    public void Create_WithInvalidFormat_ShouldThrow(string emailAddress)
    {
        // Act
        var act = () => Email.Create(emailAddress);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Create_ShouldNormalizeToLowercase()
    {
        // Arrange
        var mixedCaseEmail = "Test.User@EXAMPLE.COM";

        // Act
        var email = Email.Create(mixedCaseEmail);

        // Assert
        email.Value.Should().Be("test.user@example.com");
    }

    [Fact]
    public void Create_ShouldTrimWhitespace()
    {
        // Arrange
        var emailWithWhitespace = "  test@example.com  ";

        // Act
        var email = Email.Create(emailWithWhitespace);

        // Assert
        email.Value.Should().Be("test@example.com");
    }

    [Fact]
    public void TryCreate_WithValidEmail_ShouldReturnTrueAndEmail()
    {
        // Arrange
        var emailAddress = "valid@example.com";

        // Act
        var result = Email.TryCreate(emailAddress, out var email);

        // Assert
        result.Should().BeTrue();
        email.Should().NotBeNull();
        email!.Value.Should().Be(emailAddress);
    }

    [Fact]
    public void TryCreate_WithInvalidEmail_ShouldReturnFalseAndNull()
    {
        // Arrange
        var invalidEmail = "invalid";

        // Act
        var result = Email.TryCreate(invalidEmail, out var email);

        // Assert
        result.Should().BeFalse();
        email.Should().BeNull();
    }

    [Fact]
    public void ImplicitConversion_ShouldReturnValue()
    {
        // Arrange
        var email = Email.Create("test@example.com");

        // Act
        string value = email;

        // Assert
        value.Should().Be("test@example.com");
    }

    [Fact]
    public void ToString_ShouldReturnValue()
    {
        // Arrange
        var email = Email.Create("test@example.com");

        // Act
        var result = email.ToString();

        // Assert
        result.Should().Be("test@example.com");
    }

    [Fact]
    public void Equals_WithSameEmail_ShouldReturnTrue()
    {
        // Arrange
        var email1 = Email.Create("test@example.com");
        var email2 = Email.Create("test@example.com");

        // Act & Assert
        email1.Should().Be(email2);
    }

    [Fact]
    public void Equals_WithDifferentEmail_ShouldReturnFalse()
    {
        // Arrange
        var email1 = Email.Create("test1@example.com");
        var email2 = Email.Create("test2@example.com");

        // Act & Assert
        email1.Should().NotBe(email2);
    }
}
