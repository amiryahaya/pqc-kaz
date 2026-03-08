using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Domain.Entities;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.Identity.Domain.ValueObjects;
using Antrapol.IdP.SharedKernel.Results;

namespace Antrapol.IdP.Identity.Infrastructure.Services;

/// <summary>
/// Service for managing recovery tokens using Shamir's secret sharing.
/// </summary>
public sealed partial class RecoveryTokenService : IRecoveryTokenService
{
    private readonly IRecoveryTokenRepository _recoveryTokenRepository;
    private readonly IKeyShareRepository _keyShareRepository;
    private readonly IUserRepository _userRepository;
    private readonly ILogger<RecoveryTokenService> _logger;

    // Recovery session cache (in production, use distributed cache like Redis)
    private static readonly Dictionary<Guid, RecoverySession> _recoverySessions = new();

    public RecoveryTokenService(
        IRecoveryTokenRepository recoveryTokenRepository,
        IKeyShareRepository keyShareRepository,
        IUserRepository userRepository,
        ILogger<RecoveryTokenService> logger)
    {
        _recoveryTokenRepository = recoveryTokenRepository;
        _keyShareRepository = keyShareRepository;
        _userRepository = userRepository;
        _logger = logger;
    }

    public async Task<Result<RecoveryTokenResult>> GenerateTokenAsync(
        Guid userId,
        Guid keyShareId,
        CancellationToken ct = default)
    {
        // Deactivate existing tokens
        var deactivatedCount = await _recoveryTokenRepository.DeactivateAllByUserIdAsync(userId, ct);
        if (deactivatedCount > 0)
        {
            LogDeactivatedTokens(_logger, userId, deactivatedCount);
        }

        // Generate a secure random token
        var tokenBytes = new byte[32];
        RandomNumberGenerator.Fill(tokenBytes);
        var token = Convert.ToBase64String(tokenBytes);

        // Hash the token for storage
        var tokenHash = ComputeTokenHash(token);

        // Get next token version
        var existingToken = await _recoveryTokenRepository.GetActiveByUserIdAsync(userId, ct);
        var tokenVersion = (existingToken?.TokenVersion ?? 0) + 1;

        // Create recovery token record
        var recoveryToken = RecoveryToken.Create(
            userId: userId,
            tokenHash: tokenHash,
            keyShareId: keyShareId,
            tokenVersion: tokenVersion);

        var tokenId = await _recoveryTokenRepository.CreateAsync(recoveryToken, ct);

        LogTokenGenerated(_logger, userId, tokenVersion);

        // Generate mnemonic (optional - human-readable representation)
        var mnemonic = GenerateMnemonic(tokenBytes);

        return new RecoveryTokenResult(
            Token: token,
            TokenId: tokenId,
            TokenVersion: tokenVersion,
            Mnemonic: mnemonic);
    }

    public async Task<Result<bool>> VerifyTokenAsync(
        Guid userId,
        string tokenHash,
        CancellationToken ct = default)
    {
        var token = await _recoveryTokenRepository.GetByUserIdAndHashAsync(userId, tokenHash, ct);

        if (token == null || !token.IsActive)
        {
            return false;
        }

        return true;
    }

    public async Task<Result<RecoverySessionResult>> InitiateRecoveryAsync(
        RecoveryInitiationRequest request,
        CancellationToken ct = default)
    {
        // Find user by email
        if (!Email.TryCreate(request.Email, out var email) || email == null)
        {
            return Error.Validation("Recovery.InvalidEmail", "Invalid email format");
        }

        var user = await _userRepository.GetByEmailAsync(email, ct);
        if (user == null)
        {
            return Error.NotFound("Recovery.UserNotFound", "No user found with the provided email");
        }

        // Hash the provided token
        var tokenHash = ComputeTokenHash(request.RecoveryToken);

        // Verify token
        var token = await _recoveryTokenRepository.GetByUserIdAndHashAsync(user.Id, tokenHash, ct);
        if (token == null || !token.IsActive)
        {
            LogInvalidTokenAttempt(_logger, user.Id, request.IpAddress);
            return Error.Validation("Recovery.InvalidToken", "Invalid or expired recovery token");
        }

        // Get the recovery key share
        var keyShare = await _keyShareRepository.GetByIdAsync(token.KeyShareId, ct);
        if (keyShare == null)
        {
            return Error.NotFound("Recovery.KeyShareNotFound", "Recovery key share not found");
        }

        // Create recovery session
        var sessionId = Guid.CreateVersion7();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(30);

        var session = new RecoverySession
        {
            SessionId = sessionId,
            UserId = user.Id,
            TokenId = token.Id,
            NewDeviceId = request.NewDeviceId,
            NewDeviceName = request.NewDeviceName,
            NewDevicePlatform = request.NewDevicePlatform,
            IpAddress = request.IpAddress,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = expiresAt
        };

        // Store session (in production, use distributed cache)
        lock (_recoverySessions)
        {
            _recoverySessions[sessionId] = session;
        }

        // Record token usage
        token.RecordUsage(request.IpAddress);
        await _recoveryTokenRepository.UpdateAsync(token, ct);

        LogRecoveryInitiated(_logger, user.Id, sessionId);

        return new RecoverySessionResult(
            RecoverySessionId: sessionId,
            UserId: user.Id,
            EncryptedPartRecovery: keyShare.EncryptedData,
            ExpiresAt: expiresAt);
    }

    public async Task<Result<RecoveryCompletionResult>> CompleteRecoveryAsync(
        RecoveryCompletionRequest request,
        CancellationToken ct = default)
    {
        // Get and validate recovery session
        RecoverySession? session;
        lock (_recoverySessions)
        {
            _recoverySessions.TryGetValue(request.RecoverySessionId, out session);
        }

        if (session == null)
        {
            return Error.NotFound("Recovery.SessionNotFound", "Recovery session not found");
        }

        if (DateTimeOffset.UtcNow > session.ExpiresAt)
        {
            lock (_recoverySessions)
            {
                _recoverySessions.Remove(request.RecoverySessionId);
            }
            return Error.Validation("Recovery.SessionExpired", "Recovery session has expired");
        }

        // TODO: Validate CSRs using ICertificateIssuanceService
        // TODO: Issue new device and user certificates
        // TODO: Store new key shares
        // TODO: Generate new recovery token

        // Remove session
        lock (_recoverySessions)
        {
            _recoverySessions.Remove(request.RecoverySessionId);
        }

        LogRecoveryCompleted(_logger, session.UserId);

        // Placeholder response - actual implementation needs certificate issuance
        return new RecoveryCompletionResult(
            UserId: session.UserId,
            NewDeviceCertificatePem: "placeholder",
            NewUserCertificatePem: "placeholder",
            NewRecoveryToken: new RecoveryTokenResult(
                Token: "placeholder",
                TokenId: Guid.Empty,
                TokenVersion: 1));
    }

    public async Task<Result<int>> RevokeAllTokensAsync(
        Guid userId,
        CancellationToken ct = default)
    {
        var count = await _recoveryTokenRepository.DeactivateAllByUserIdAsync(userId, ct);
        LogRevokedTokens(_logger, userId, count);
        return count;
    }

    private static string ComputeTokenHash(string token)
    {
        var tokenBytes = Convert.FromBase64String(token);
        var hash = SHA256.HashData(tokenBytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string GenerateMnemonic(byte[] tokenBytes)
    {
        // Simple mnemonic generation using BIP39-style word list subset
        // In production, use full BIP39 implementation
        var words = new List<string>();
        for (var i = 0; i < tokenBytes.Length; i += 2)
        {
            var index = (tokenBytes[i] << 8 | tokenBytes[Math.Min(i + 1, tokenBytes.Length - 1)]) % WordList.Length;
            words.Add(WordList[index]);
        }
        return string.Join(" ", words);
    }

    // Simplified word list for mnemonic generation
    private static readonly string[] WordList =
    [
        "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "address", "adjust", "admit",
        "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again",
        "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle",
        "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow",
        "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur",
        "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger"
    ];

    // Logger messages
    [LoggerMessage(Level = LogLevel.Information, Message = "Generated recovery token for user {UserId}, version {Version}")]
    private static partial void LogTokenGenerated(ILogger logger, Guid userId, int version);

    [LoggerMessage(Level = LogLevel.Information, Message = "Deactivated {Count} existing recovery tokens for user {UserId}")]
    private static partial void LogDeactivatedTokens(ILogger logger, Guid userId, int count);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Invalid recovery token attempt for user {UserId} from IP {IpAddress}")]
    private static partial void LogInvalidTokenAttempt(ILogger logger, Guid userId, string? ipAddress);

    [LoggerMessage(Level = LogLevel.Information, Message = "Recovery initiated for user {UserId}, session {SessionId}")]
    private static partial void LogRecoveryInitiated(ILogger logger, Guid userId, Guid sessionId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Recovery completed for user {UserId}")]
    private static partial void LogRecoveryCompleted(ILogger logger, Guid userId);

    [LoggerMessage(Level = LogLevel.Information, Message = "Revoked {Count} recovery tokens for user {UserId}")]
    private static partial void LogRevokedTokens(ILogger logger, Guid userId, int count);
}

/// <summary>
/// Internal recovery session tracking.
/// </summary>
internal sealed class RecoverySession
{
    public Guid SessionId { get; init; }
    public Guid UserId { get; init; }
    public Guid TokenId { get; init; }
    public string NewDeviceId { get; init; } = null!;
    public string NewDeviceName { get; init; } = null!;
    public string NewDevicePlatform { get; init; } = null!;
    public string? IpAddress { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
}
