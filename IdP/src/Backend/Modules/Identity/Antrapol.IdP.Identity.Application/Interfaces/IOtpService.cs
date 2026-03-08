namespace Antrapol.IdP.Identity.Application.Interfaces;

/// <summary>
/// Service for generating and validating One-Time Passwords (OTP).
/// </summary>
public interface IOtpService
{
    /// <summary>
    /// Generates a random 6-digit OTP.
    /// </summary>
    string GenerateOtp();

    /// <summary>
    /// Hashes an OTP for secure storage.
    /// </summary>
    string HashOtp(string otp);

    /// <summary>
    /// Verifies an OTP against its hash.
    /// </summary>
    bool VerifyOtp(string otp, string hash);

    /// <summary>
    /// Sends an OTP via email.
    /// </summary>
    Task SendEmailOtpAsync(string email, string otp, string recipientName, CancellationToken ct = default);

    /// <summary>
    /// Sends an OTP via SMS.
    /// </summary>
    Task SendSmsOtpAsync(string phoneNumber, string otp, CancellationToken ct = default);
}
