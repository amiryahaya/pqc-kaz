namespace Antrapol.IdP.Identity.Application.Commands;

/// <summary>
/// Command to verify phone OTP.
/// </summary>
public sealed record VerifyPhoneOtpCommand(Guid RegistrationId, string Otp);
