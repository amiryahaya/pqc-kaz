using Microsoft.AspNetCore.Builder;
using Antrapol.IdP.Common.Middleware;

namespace Antrapol.IdP.Common.Extensions;

/// <summary>
/// Extension methods for IApplicationBuilder.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds the exception handling middleware to the pipeline.
    /// </summary>
    public static IApplicationBuilder UseExceptionHandling(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ExceptionHandlingMiddleware>();
    }
}
