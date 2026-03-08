using Microsoft.Extensions.DependencyInjection;

namespace Antrapol.IdP.Admin.Api;

public static class DependencyInjection
{
    public static IServiceCollection AddAdminModule(this IServiceCollection services)
    {
        // Repositories
        // services.AddScoped<IAuditLogRepository, AuditLogRepository>();

        // Query Handlers
        // services.AddScoped<IQueryHandler<SearchAuditLogsQuery, PagedResult<AuditLogDto>>, SearchAuditLogsQueryHandler>();

        return services;
    }
}
