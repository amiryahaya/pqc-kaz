using FluentValidation;
using Antrapol.IdP.Identity.Application.Commands;

namespace Antrapol.IdP.Identity.Application.Validators;

public sealed class VerifyEmailOtpCommandValidator : AbstractValidator<VerifyEmailOtpCommand>
{
    public VerifyEmailOtpCommandValidator()
    {
        RuleFor(x => x.RegistrationId)
            .NotEmpty().WithMessage("Registration ID is required.");

        RuleFor(x => x.Otp)
            .NotEmpty().WithMessage("OTP is required.")
            .Length(6).WithMessage("OTP must be 6 digits.")
            .Matches(@"^\d{6}$").WithMessage("OTP must contain only digits.");
    }
}
