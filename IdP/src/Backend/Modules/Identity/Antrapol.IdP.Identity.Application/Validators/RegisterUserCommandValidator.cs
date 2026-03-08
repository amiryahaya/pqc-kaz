using FluentValidation;
using Antrapol.IdP.Identity.Application.Commands;

namespace Antrapol.IdP.Identity.Application.Validators;

public sealed class RegisterUserCommandValidator : AbstractValidator<RegisterUserCommand>
{
    public RegisterUserCommandValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email is required.")
            .EmailAddress().WithMessage("Invalid email format.")
            .MaximumLength(256).WithMessage("Email must not exceed 256 characters.");

        RuleFor(x => x.DisplayName)
            .MaximumLength(100).WithMessage("Display name must not exceed 100 characters.")
            .When(x => x.DisplayName is not null);
    }
}
