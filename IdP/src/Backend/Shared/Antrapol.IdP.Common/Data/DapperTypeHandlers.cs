using System.Data;
using System.Globalization;
using Dapper;

namespace Antrapol.IdP.Common.Data;

/// <summary>
/// Dapper type handlers for custom types.
/// </summary>
public static class DapperTypeHandlers
{
    private static bool _initialized;
    private static readonly object Lock = new();

    /// <summary>
    /// Registers all custom type handlers with Dapper.
    /// </summary>
    public static void Register()
    {
        if (_initialized) return;

        lock (Lock)
        {
            if (_initialized) return;

            SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
            SqlMapper.AddTypeHandler(new GuidHandler());

            _initialized = true;
        }
    }
}

/// <summary>
/// Type handler for DateTimeOffset to handle PostgreSQL timestamptz.
/// </summary>
public sealed class DateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset>
{
    public override void SetValue(IDbDataParameter parameter, DateTimeOffset value)
    {
        parameter.Value = value.UtcDateTime;
        parameter.DbType = DbType.DateTimeOffset;
    }

    public override DateTimeOffset Parse(object value)
    {
        return value switch
        {
            DateTime dt => new DateTimeOffset(dt, TimeSpan.Zero),
            DateTimeOffset dto => dto,
            _ => DateTimeOffset.Parse(value.ToString()!, CultureInfo.InvariantCulture)
        };
    }
}

/// <summary>
/// Type handler for Guid to ensure proper handling.
/// </summary>
public sealed class GuidHandler : SqlMapper.TypeHandler<Guid>
{
    public override void SetValue(IDbDataParameter parameter, Guid value)
    {
        parameter.Value = value;
        parameter.DbType = DbType.Guid;
    }

    public override Guid Parse(object value)
    {
        return value switch
        {
            Guid g => g,
            string s => Guid.Parse(s),
            _ => Guid.Parse(value.ToString()!)
        };
    }
}
