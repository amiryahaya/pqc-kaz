# Build native KAZ-KEM library for .NET bindings (Windows)
# Requires: Visual Studio Build Tools or MSVC, OpenSSL

param(
    [string]$OpenSSLPath = "C:\OpenSSL-Win64",
    [string]$OutputDir = "",
    [string]$Architecture = "x64"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$KemRoot = (Get-Item "$ScriptDir\..\..\..").FullName

if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = "$ScriptDir\..\KazKem\runtimes"
}

# Determine RID
$RID = "win-$Architecture"
$RuntimeDir = "$OutputDir\$RID\native"

Write-Host "Building KAZ-KEM native library for Windows"
Write-Host "============================================"
Write-Host "Architecture: $Architecture"
Write-Host "Runtime ID:   $RID"
Write-Host "OpenSSL:      $OpenSSLPath"
Write-Host "Output:       $RuntimeDir"
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null

# Source files
$SrcDir = "$KemRoot\src\internal"
$IncDir = "$KemRoot\include"
$SrcFiles = @(
    "$SrcDir\kem_secure.c",
    "$SrcDir\nist_wrapper.c"
)

# Check if cl.exe is available
$ClPath = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $ClPath) {
    Write-Host "Error: cl.exe not found. Please run from Visual Studio Developer Command Prompt."
    Write-Host ""
    Write-Host "Or run: "
    Write-Host '  & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"'
    exit 1
}

# Check OpenSSL
if (-not (Test-Path "$OpenSSLPath\include\openssl\bn.h")) {
    Write-Host "Error: OpenSSL not found at $OpenSSLPath"
    Write-Host "Install OpenSSL or specify path with -OpenSSLPath parameter"
    exit 1
}

# Build flags
$CFlags = @(
    "/O2",
    "/W3",
    "/LD",
    "/DKAZ_KEM_USE_OPENSSL",
    "/DKAZ_KEM_VERSION=`"2.1.0`"",
    "/DKAZ_KEM_VERSION_MAJOR=2",
    "/DKAZ_KEM_VERSION_MINOR=1",
    "/DKAZ_KEM_VERSION_PATCH=0",
    "/I$IncDir",
    "/I$SrcDir",
    "/I$OpenSSLPath\include"
)

$LinkFlags = @(
    "/link",
    "/LIBPATH:$OpenSSLPath\lib",
    "libcrypto.lib",
    "/OUT:$RuntimeDir\kazkem.dll"
)

# Combine all arguments
$AllArgs = $CFlags + $SrcFiles + $LinkFlags

Write-Host "Compiling..."
& cl.exe @AllArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# Clean up intermediate files
Remove-Item -Force -ErrorAction SilentlyContinue "*.obj"
Remove-Item -Force -ErrorAction SilentlyContinue "*.exp"
Remove-Item -Force -ErrorAction SilentlyContinue "*.lib" -Exclude "kazkem.lib"

Write-Host ""
Write-Host "Successfully built: $RuntimeDir\kazkem.dll"
Write-Host ""
Get-Item "$RuntimeDir\kazkem.dll" | Format-List Name, Length, LastWriteTime
