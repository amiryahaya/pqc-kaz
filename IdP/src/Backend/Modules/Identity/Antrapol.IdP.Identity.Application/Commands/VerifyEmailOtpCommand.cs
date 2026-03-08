namespace Antrapol.IdP.Identity.Application.Commands;

public sealed record VerifyEmailOtpCommand(Guid RegistrationId, string Otp);
