namespace Antrapol.IdP.Identity.Application.Commands;

/// <summary>
/// Command to send phone OTP after email verification.
/// </summary>
public sealed record SendPhoneOtpCommand(Guid RegistrationId);
