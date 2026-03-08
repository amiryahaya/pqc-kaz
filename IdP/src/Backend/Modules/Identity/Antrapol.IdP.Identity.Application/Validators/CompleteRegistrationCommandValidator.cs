using FluentValidation;
using Antrapol.IdP.Identity.Application.Commands;

namespace Antrapol.IdP.Identity.Application.Validators;

public sealed class CompleteRegistrationCommandValidator : AbstractValidator<CompleteRegistrationCommand>
{
    public CompleteRegistrationCommandValidator()
    {
        RuleFor(x => x.RegistrationId)
            .NotEmpty().WithMessage("Registration ID is required.");
    }
}
