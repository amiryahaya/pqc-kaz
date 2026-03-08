using FluentValidation;
using Antrapol.IdP.Identity.Application.Commands;

namespace Antrapol.IdP.Identity.Application.Validators;

public sealed class InitiateRegistrationCommandValidator : AbstractValidator<InitiateRegistrationCommand>
{
    public InitiateRegistrationCommandValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Invalid email format.")
            .MaximumLength(256).WithMessage("Email must not exceed 256 characters.");
    }
}
