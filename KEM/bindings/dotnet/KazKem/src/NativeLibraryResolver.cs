using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Antrapol.Kaz.Kem.Native;

/// <summary>
/// Cross-platform native library resolver for KAZ-KEM.
/// Handles loading the correct native library based on OS and architecture.
/// </summary>
internal static class NativeLibraryResolver
{
    private static readonly object _lock = new();
    private static bool _initialized;

    /// <summary>
    /// Initialize the native library resolver.
    /// Call this early in your application to set up library resolution.
    /// </summary>
    public static void Initialize()
    {
        lock (_lock)
        {
            if (_initialized) return;

            NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, ResolveLibrary);
            _initialized = true;
        }
    }

    private static IntPtr ResolveLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != "kazkem")
        {
            return IntPtr.Zero;
        }

        // Try standard resolution first
        if (NativeLibrary.TryLoad(libraryName, assembly, searchPath, out IntPtr handle))
        {
            return handle;
        }

        // Get the native library path based on platform
        string? nativeLibPath = GetNativeLibraryPath();
        if (nativeLibPath != null && NativeLibrary.TryLoad(nativeLibPath, out handle))
        {
            return handle;
        }

        // Try platform-specific names
        string platformLibName = GetPlatformLibraryName();
        if (NativeLibrary.TryLoad(platformLibName, assembly, searchPath, out handle))
        {
            return handle;
        }

        return IntPtr.Zero;
    }

    private static string? GetNativeLibraryPath()
    {
        string assemblyDir = Path.GetDirectoryName(typeof(NativeLibraryResolver).Assembly.Location) ?? ".";
        string runtimeDir = GetRuntimeIdentifier();
        string libName = GetPlatformLibraryName();

        // Check in runtimes/{rid}/native/
        string runtimePath = Path.Combine(assemblyDir, "runtimes", runtimeDir, "native", libName);
        if (File.Exists(runtimePath))
        {
            return runtimePath;
        }

        // Check in same directory as assembly
        string localPath = Path.Combine(assemblyDir, libName);
        if (File.Exists(localPath))
        {
            return localPath;
        }

        // Check in native/ subdirectory
        string nativePath = Path.Combine(assemblyDir, "native", libName);
        if (File.Exists(nativePath))
        {
            return nativePath;
        }

        return null;
    }

    private static string GetRuntimeIdentifier()
    {
        string os = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" :
                    RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
                    RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" : "unknown";

        string arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.X86 => "x86",
            Architecture.Arm64 => "arm64",
            Architecture.Arm => "arm",
            _ => "unknown"
        };

        return $"{os}-{arch}";
    }

    private static string GetPlatformLibraryName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "kazkem.dll";
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "libkazkem.dylib";
        }
        else // Linux and others
        {
            return "libkazkem.so";
        }
    }
}
