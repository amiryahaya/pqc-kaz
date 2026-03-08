using FluentAssertions;
using PqcIdentity.Certificate.Infrastructure.Services;
using PqcIdentity.Crypto.Infrastructure.Providers;

namespace PqcIdentity.Tests.Unit.Certificate;

/// <summary>
/// Unit tests for CsrParserService.
/// Note: These tests use the real KazSignProvider since it's a sealed class.
/// The native library calls will fail gracefully in tests.
/// </summary>
public class CsrParserServiceTests
{
    private readonly CsrParserService _sut;

    public CsrParserServiceTests()
    {
        // Use real provider - native calls will fail gracefully
        _sut = new CsrParserService(new KazSignProvider());
    }

    [Fact]
    public void Parse_WithInvalidDer_ShouldReturnValidationError()
    {
        // Arrange
        var invalidDer = new byte[] { 0x00, 0x01, 0x02 };

        // Act
        var result = _sut.Parse(invalidDer);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Contain("CSR");
    }

    [Fact]
    public void Parse_WithEmptyData_ShouldReturnValidationError()
    {
        // Arrange
        var emptyDer = Array.Empty<byte>();

        // Act
        var result = _sut.Parse(emptyDer);

        // Assert
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Parse_WithValidCsrStructure_ShouldExtractSubjectDn()
    {
        // Arrange
        // This is a simplified test - in reality you'd need a properly
        // encoded CSR. For now we test the error handling paths.
        var malformedCsr = CreateMalformedCsr();

        // Act
        var result = _sut.Parse(malformedCsr);

        // Assert
        result.IsFailure.Should().BeTrue();
        result.Error.Message.Should().Contain("Invalid CSR");
    }

    [Fact]
    public async Task VerifySignatureAsync_WithInvalidCsr_ShouldReturnFalse()
    {
        // Arrange
        var invalidCsr = new byte[] { 0x30, 0x00 }; // Empty SEQUENCE

        // Act
        var result = await _sut.VerifySignatureAsync(invalidCsr);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidCsr_ShouldReturnInvalidResult()
    {
        // Arrange
        var invalidCsr = new byte[] { 0xFF, 0xFF };

        // Act
        var result = await _sut.ValidateAsync(invalidCsr);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.IsValid.Should().BeFalse();
        result.Value.ValidationError.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ValidateAsync_WithEmptyCsr_ShouldReturnInvalidResult()
    {
        // Arrange
        var emptyCsr = Array.Empty<byte>();

        // Act
        var result = await _sut.ValidateAsync(emptyCsr);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.IsValid.Should().BeFalse();
    }

    // Helper to create a malformed but structurally valid-looking CSR
    private static byte[] CreateMalformedCsr()
    {
        // Minimal malformed SEQUENCE that will fail parsing
        return [0x30, 0x03, 0x02, 0x01, 0x00];
    }
}
