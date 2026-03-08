using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Antrapol.IdP.Crypto.Domain.Interfaces;
using Antrapol.IdP.Crypto.Infrastructure.Providers;

namespace Antrapol.IdP.Crypto.Api;

public static class DependencyInjection
{
    public static IServiceCollection AddCryptoModule(this IServiceCollection services, IConfiguration? configuration = null)
    {
        // ============================================
        // Post-Quantum Cryptography Providers
        // ============================================

        // KAZ-SIGN Managed Provider (using Antrapol.Kaz.Sign NuGet package)
        // Provides Malaysian National PQC Digital Signature at all security levels
        services.AddSingleton<KazSignManagedProvider>();

        // KAZ-KEM Managed Provider (using Antrapol.Kaz.Kem NuGet package)
        // Provides Malaysian National PQC Key Encapsulation at all security levels
        services.AddSingleton<KazKemManagedProvider>();

        // NIST PQC Provider (liboqs - placeholder for ML-DSA, ML-KEM)
        services.AddSingleton<LibOqsCryptoProvider>();

        // Unified Crypto Provider - delegates to appropriate provider based on algorithm
        // This is the primary interface for cryptographic operations
        services.AddSingleton<ICryptoProvider, UnifiedCryptoProvider>();

        // Legacy KAZ-SIGN Provider (native P/Invoke - kept for backward compatibility)
        services.AddSingleton<KazSignProvider>();

        // ============================================
        // HSM Provider
        // ============================================

        // HSM Provider - configure based on environment
        if (configuration != null)
        {
            services.Configure<SoftHsmOptions>(configuration.GetSection("Hsm:SoftHsm"));
        }
        services.AddSingleton<IHsmProvider, SoftHsmProvider>();

        return services;
    }
}
