using System.Collections.Concurrent;
using Xunit;
using Antrapol.Kaz.Kem;

namespace Antrapol.Kaz.Kem.Tests;

/// <summary>
/// Tests for thread safety and concurrent operations.
/// </summary>
public class ThreadSafetyTests : IDisposable
{
    private KazKemContext _context;

    public ThreadSafetyTests()
    {
        _context = KazKemContext.Initialize(SecurityLevel.Level128);
    }

    public void Dispose()
    {
        _context?.Dispose();
    }

    [Fact]
    public async Task GenerateKeyPair_ConcurrentCalls_ShouldAllSucceed()
    {
        // Arrange
        const int concurrentOperations = 10;
        var keyPairs = new ConcurrentBag<KazKemKeyPair>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, concurrentOperations).Select(_ => Task.Run(() =>
        {
            try
            {
                var keyPair = _context.GenerateKeyPair();
                keyPairs.Add(keyPair);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(concurrentOperations, keyPairs.Count);

        // All key pairs should be unique
        var publicKeys = keyPairs.Select(kp => Convert.ToBase64String(kp.ExportPublicKey())).ToList();
        Assert.Equal(concurrentOperations, publicKeys.Distinct().Count());

        // Cleanup
        foreach (var kp in keyPairs)
        {
            kp.Dispose();
        }
    }

    [Fact]
    public async Task EncapsulateDecapsulate_ConcurrentCalls_ShouldAllSucceed()
    {
        // Arrange
        const int concurrentOperations = 10;
        using var keyPair = _context.GenerateKeyPair();
        var results = new ConcurrentBag<bool>();
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        var tasks = Enumerable.Range(0, concurrentOperations).Select(_ => Task.Run(() =>
        {
            try
            {
                using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
                var decapsulatedSecret = _context.Decapsulate(encResult.Ciphertext, keyPair);
                var match = encResult.SharedSecret.ToArray().SequenceEqual(decapsulatedSecret);
                results.Add(match);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(exceptions);
        Assert.Equal(concurrentOperations, results.Count);
        Assert.All(results, r => Assert.True(r));
    }

    [Fact]
    public async Task MixedOperations_ConcurrentCalls_ShouldAllSucceed()
    {
        // Arrange
        const int operationsPerType = 5;
        var exceptions = new ConcurrentBag<Exception>();
        using var keyPair = _context.GenerateKeyPair();

        // Act - run key generation, encapsulation, and decapsulation concurrently
        var keyGenTasks = Enumerable.Range(0, operationsPerType).Select(_ => Task.Run(() =>
        {
            try
            {
                using var kp = _context.GenerateKeyPair();
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        var encapTasks = Enumerable.Range(0, operationsPerType).Select(_ => Task.Run(() =>
        {
            try
            {
                using var result = _context.Encapsulate(keyPair.GetPublicKey());
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        var decapTasks = Enumerable.Range(0, operationsPerType).Select(_ => Task.Run(() =>
        {
            try
            {
                using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
                _context.Decapsulate(encResult.Ciphertext, keyPair);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(keyGenTasks.Concat(encapTasks).Concat(decapTasks));

        // Assert
        Assert.Empty(exceptions);
    }

    [Fact]
    public async Task Initialize_ConcurrentCalls_ShouldNotCrash()
    {
        // Arrange
        const int concurrentCalls = 5;
        var contexts = new ConcurrentBag<KazKemContext>();
        var exceptions = new ConcurrentBag<Exception>();

        // Dispose current context first
        _context.Dispose();

        // Act - try to initialize concurrently
        var tasks = Enumerable.Range(0, concurrentCalls).Select(_ => Task.Run(() =>
        {
            try
            {
                var ctx = KazKemContext.Initialize(SecurityLevel.Level128);
                contexts.Add(ctx);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }));

        await Task.WhenAll(tasks);

        // Assert - should not have any exceptions
        Assert.Empty(exceptions);

        // All should return the same context (singleton)
        var distinctContexts = contexts.Distinct().Count();
        Assert.Equal(1, distinctContexts);

        // Re-assign for cleanup
        _context = contexts.First();
    }

    [Fact]
    public async Task KeyPairUsage_FromMultipleThreads_ShouldWork()
    {
        // Arrange
        const int threads = 5;
        using var keyPair = _context.GenerateKeyPair();
        var publicKey = keyPair.GetPublicKey();
        var results = new ConcurrentBag<byte[]>();

        // Act - use the same key pair from multiple threads
        var tasks = Enumerable.Range(0, threads).Select(_ => Task.Run(() =>
        {
            using var encResult = _context.Encapsulate(publicKey);
            var decapsulated = _context.Decapsulate(encResult.Ciphertext, keyPair);
            results.Add(decapsulated);
        }));

        await Task.WhenAll(tasks);

        // Assert
        Assert.Equal(threads, results.Count);

        // All results should have correct length
        Assert.All(results, r => Assert.Equal(_context.SharedSecretSize, r.Length));
    }

    [Fact]
    public void ParallelFor_KeyGeneration_ShouldWork()
    {
        // Arrange
        const int iterations = 20;
        var keyPairs = new KazKemKeyPair[iterations];
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        Parallel.For(0, iterations, i =>
        {
            try
            {
                keyPairs[i] = _context.GenerateKeyPair();
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // Assert
        Assert.Empty(exceptions);
        Assert.All(keyPairs, kp => Assert.NotNull(kp));

        // Cleanup
        foreach (var kp in keyPairs)
        {
            kp?.Dispose();
        }
    }

    [Fact]
    public void ParallelFor_EncapsulateDecapsulate_ShouldWork()
    {
        // Arrange
        const int iterations = 20;
        using var keyPair = _context.GenerateKeyPair();
        var results = new bool[iterations];
        var exceptions = new ConcurrentBag<Exception>();

        // Act
        Parallel.For(0, iterations, i =>
        {
            try
            {
                using var encResult = _context.Encapsulate(keyPair.GetPublicKey());
                var decapsulated = _context.Decapsulate(encResult.Ciphertext, keyPair);
                results[i] = encResult.SharedSecret.ToArray().SequenceEqual(decapsulated);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        });

        // Assert
        Assert.Empty(exceptions);
        Assert.All(results, r => Assert.True(r));
    }
}
