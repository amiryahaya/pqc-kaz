using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Antrapol.IdP.Certificate.Application.Interfaces;
using Antrapol.IdP.Certificate.Domain.Interfaces;
using Antrapol.IdP.Certificate.Infrastructure.Persistence.Repositories;
using Antrapol.IdP.Certificate.Infrastructure.Services;

namespace Antrapol.IdP.Certificate.Api;

public static class DependencyInjection
{
    public static IServiceCollection AddCertificateModule(this IServiceCollection services, IConfiguration configuration)
    {
        // Configuration
        services.Configure<CaKeyOptions>(configuration.GetSection(CaKeyOptions.SectionName));

        // Note: ICryptoProvider is registered in the Crypto module (AddCryptoModule)
        // and will be injected into CertificateIssuanceService automatically

        // Repositories
        services.AddScoped<ICertificateRepository, CertificateRepository>();

        // Certificate Services
        services.AddScoped<ICsrParser, CsrParserService>();
        services.AddSingleton<ICaKeyProvider, FileBasedCaKeyProvider>();
        services.AddScoped<ICertificateIssuanceService, CertificateIssuanceService>();

        return services;
    }
}
