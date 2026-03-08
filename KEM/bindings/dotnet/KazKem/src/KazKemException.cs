namespace Antrapol.Kaz.Kem;

/// <summary>
/// Exception thrown when a KAZ-KEM operation fails.
/// </summary>
public class KazKemException : Exception
{
    /// <summary>
    /// Native error code from the KAZ-KEM library.
    /// </summary>
    public int ErrorCode { get; }

    public KazKemException(string message) : base(message)
    {
        ErrorCode = -1;
    }

    public KazKemException(string message, int errorCode) : base(message)
    {
        ErrorCode = errorCode;
    }

    public KazKemException(string message, Exception innerException) : base(message, innerException)
    {
        ErrorCode = -1;
    }

    /// <summary>
    /// Create exception from native error code.
    /// </summary>
    internal static KazKemException FromErrorCode(int errorCode, string operation)
    {
        var message = errorCode switch
        {
            -1 => $"{operation}: Invalid parameter",
            -2 => $"{operation}: Memory allocation failed",
            -3 => $"{operation}: Random number generation failed",
            -4 => $"{operation}: Key generation failed",
            -5 => $"{operation}: Message value exceeds modulus",
            -6 => $"{operation}: Not initialized - call Initialize() first",
            -7 => $"{operation}: Invalid security level",
            _ => $"{operation}: Unknown error (code: {errorCode})"
        };
        return new KazKemException(message, errorCode);
    }
}

/// <summary>
/// Exception thrown when KAZ-KEM is not initialized.
/// </summary>
public class KazKemNotInitializedException : KazKemException
{
    public KazKemNotInitializedException()
        : base("KAZ-KEM is not initialized. Call KazKemContext.Initialize() first.", -6)
    {
    }
}

/// <summary>
/// Exception thrown when an invalid security level is specified.
/// </summary>
public class InvalidSecurityLevelException : KazKemException
{
    public SecurityLevel? AttemptedLevel { get; }

    public InvalidSecurityLevelException(int level)
        : base($"Invalid security level: {level}. Valid levels are 128, 192, or 256.", -7)
    {
        AttemptedLevel = null;
    }

    public InvalidSecurityLevelException(SecurityLevel level)
        : base($"Failed to initialize security level: {(int)level}", -7)
    {
        AttemptedLevel = level;
    }
}
