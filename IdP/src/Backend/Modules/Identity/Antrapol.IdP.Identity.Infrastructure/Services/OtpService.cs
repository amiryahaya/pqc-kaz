using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Antrapol.IdP.Identity.Application.Interfaces;

namespace Antrapol.IdP.Identity.Infrastructure.Services;

public sealed partial class OtpService : IOtpService
{
    private readonly ILogger<OtpService> _logger;

    public OtpService(ILogger<OtpService> logger)
    {
        _logger = logger;
    }

    public string GenerateOtp()
    {
        var randomNumber = RandomNumberGenerator.GetInt32(100000, 999999);
        return randomNumber.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    public string HashOtp(string otp)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(otp);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    public bool VerifyOtp(string otp, string hash)
    {
        var otpHash = HashOtp(otp);
        return otpHash == hash;
    }

    public Task SendEmailOtpAsync(string email, string otp, string recipientName, CancellationToken ct = default)
    {
        // TODO: Implement actual email sending via SMTP or email service provider
        // For development, just log the OTP
        LogEmailOtp(_logger, recipientName, email, otp);
        return Task.CompletedTask;
    }

    public Task SendSmsOtpAsync(string phoneNumber, string otp, CancellationToken ct = default)
    {
        // TODO: Implement actual SMS sending via SMS gateway (Twilio, etc.)
        // For development, just log the OTP
        LogSmsOtp(_logger, phoneNumber, otp);
        return Task.CompletedTask;
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "EMAIL OTP for {RecipientName} ({Email}): {Otp}")]
    private static partial void LogEmailOtp(ILogger logger, string recipientName, string email, string otp);

    [LoggerMessage(Level = LogLevel.Information, Message = "SMS OTP for {PhoneNumber}: {Otp}")]
    private static partial void LogSmsOtp(ILogger logger, string phoneNumber, string otp);
}
