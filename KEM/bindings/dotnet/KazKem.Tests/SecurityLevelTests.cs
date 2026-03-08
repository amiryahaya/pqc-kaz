using Xunit;
using Antrapol.Kaz.Kem;

namespace Antrapol.Kaz.Kem.Tests;

/// <summary>
/// Tests for security level initialization and switching.
/// </summary>
public class SecurityLevelTests : IDisposable
{
    public void Dispose()
    {
        // Ensure cleanup after each test
        if (KazKemContext.IsInitialized)
        {
            KazKemContext.Current.Dispose();
        }
    }

    [Theory]
    [InlineData(SecurityLevel.Level128)]
    [InlineData(SecurityLevel.Level192)]
    [InlineData(SecurityLevel.Level256)]
    public void Initialize_AllLevels_ShouldSucceed(SecurityLevel level)
    {
        // Act
        using var context = KazKemContext.Initialize(level);

        // Assert
        Assert.NotNull(context);
        Assert.Equal(level, context.SecurityLevel);
        Assert.True(KazKemContext.IsInitialized);
    }

    [Theory]
    [InlineData(SecurityLevel.Level128, 108, 34)]
    [InlineData(SecurityLevel.Level192, 176, 50)]
    [InlineData(SecurityLevel.Level256, 236, 66)]
    public void Initialize_ShouldHaveCorrectKeySizes(SecurityLevel level, int expectedPkSize, int expectedSkSize)
    {
        // Act
        using var context = KazKemContext.Initialize(level);

        // Assert
        Assert.Equal(expectedPkSize, context.PublicKeySize);
        Assert.Equal(expectedSkSize, context.PrivateKeySize);
    }

    [Fact]
    public void Initialize_SameLevelTwice_ShouldReturnSameContext()
    {
        // Arrange
        var context1 = KazKemContext.Initialize(SecurityLevel.Level128);

        // Act
        var context2 = KazKemContext.Initialize(SecurityLevel.Level128);

        // Assert
        Assert.Same(context1, context2);

        context1.Dispose();
    }

    [Fact]
    public void Initialize_DifferentLevel_ShouldReinitialize()
    {
        // Arrange
        var context1 = KazKemContext.Initialize(SecurityLevel.Level128);
        var level1 = context1.SecurityLevel;

        // Act
        var context2 = KazKemContext.Initialize(SecurityLevel.Level256);

        // Assert
        Assert.Equal(SecurityLevel.Level128, level1);
        Assert.Equal(SecurityLevel.Level256, context2.SecurityLevel);

        context2.Dispose();
    }

    [Fact]
    public void Current_WhenNotInitialized_ShouldThrow()
    {
        // Ensure not initialized
        if (KazKemContext.IsInitialized)
        {
            KazKemContext.Current.Dispose();
        }

        // Act & Assert
        Assert.Throws<KazKemNotInitializedException>(() => KazKemContext.Current);
    }

    [Fact]
    public void IsInitialized_AfterDispose_ShouldBeFalse()
    {
        // Arrange
        var context = KazKemContext.Initialize(SecurityLevel.Level128);

        // Act
        context.Dispose();

        // Assert
        Assert.False(KazKemContext.IsInitialized);
    }
}
