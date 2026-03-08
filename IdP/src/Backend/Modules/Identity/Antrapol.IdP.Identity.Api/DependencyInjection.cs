using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using Antrapol.IdP.Identity.Application.Commands;
using Antrapol.IdP.Identity.Application.DTOs;
using Antrapol.IdP.Identity.Application.Interfaces;
using Antrapol.IdP.Identity.Application.Queries;
using Antrapol.IdP.Identity.Application.Validators;
using Antrapol.IdP.Identity.Domain.Interfaces;
using Antrapol.IdP.Identity.Infrastructure.Persistence.Repositories;
using Antrapol.IdP.Identity.Infrastructure.Services;
using Antrapol.IdP.SharedKernel.Handlers;

namespace Antrapol.IdP.Identity.Api;

public static class DependencyInjection
{
    public static IServiceCollection AddIdentityModule(this IServiceCollection services)
    {
        // Repositories
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IPendingRegistrationRepository, PendingRegistrationRepository>();
        services.AddScoped<ICsrRequestRepository, CsrRequestRepository>();
        services.AddScoped<IKeyShareRepository, KeyShareRepository>();

        // Services
        services.AddScoped<IOtpService, OtpService>();
        services.AddScoped<ICsrService, CsrService>();
        services.AddScoped<IRegistrationCertificateService, RegistrationCertificateService>();

        // Command Handlers
        services.AddScoped<ICommandHandler<RegisterUserCommand, UserDto>, RegisterUserCommandHandler>();
        services.AddScoped<ICommandHandler<InitiateRegistrationCommand, InitiateRegistrationDto>, InitiateRegistrationCommandHandler>();
        services.AddScoped<ICommandHandler<VerifyEmailOtpCommand, VerifyEmailOtpDto>, VerifyEmailOtpCommandHandler>();
        services.AddScoped<ICommandHandler<SendPhoneOtpCommand, SendPhoneOtpDto>, SendPhoneOtpCommandHandler>();
        services.AddScoped<ICommandHandler<VerifyPhoneOtpCommand, VerifyPhoneOtpDto>, VerifyPhoneOtpCommandHandler>();
        services.AddScoped<ICommandHandler<SubmitCsrCommand, SubmitCsrDto>, SubmitCsrCommandHandler>();
        services.AddScoped<ICommandHandler<CompleteRegistrationCommand, CompleteRegistrationDto>, CompleteRegistrationCommandHandler>();

        // Query Handlers
        services.AddScoped<IQueryHandler<GetUserByIdQuery, UserDto>, GetUserByIdQueryHandler>();
        services.AddScoped<IQueryHandler<GetRegistrationStatusQuery, RegistrationStatusDto>, GetRegistrationStatusQueryHandler>();
        services.AddScoped<IQueryHandler<GetCertificateStatusQuery, CertificateStatusDto>, GetCertificateStatusQueryHandler>();

        // Validators
        services.AddValidatorsFromAssemblyContaining<RegisterUserCommandValidator>();

        return services;
    }
}
