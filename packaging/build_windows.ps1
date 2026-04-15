param(
    [switch]$Clean,
    [switch]$Installer
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Spec = Join-Path $PSScriptRoot "CSCI480_IDS.spec"
$DistDir = Join-Path $Root "dist"
$BuildDir = Join-Path $Root "build"

if (-not (Test-Path $Python)) {
    throw "Virtual environment not found at $Python"
}

if ($Clean) {
    if (Test-Path $DistDir) { Remove-Item $DistDir -Recurse -Force }
    if (Test-Path $BuildDir) { Remove-Item $BuildDir -Recurse -Force }
}

Write-Host "Ensuring PyInstaller is available..."
& $Python -m pip install pyinstaller | Out-Host

Write-Host "Building Windows executable..."
Push-Location $Root
try {
    & $Python -m PyInstaller --noconfirm $Spec | Out-Host
}
finally {
    Pop-Location
}

$BundleDir = Join-Path $DistDir "CSCI480 Layered IDS"
$ExePath = Join-Path $BundleDir "CSCI480 Layered IDS.exe"
if (-not (Test-Path $ExePath)) {
    throw "Build did not produce expected executable: $ExePath"
}

Write-Host ""
Write-Host "Executable ready:"
Write-Host "  $ExePath"
Write-Host "Bundle folder:"
Write-Host "  $BundleDir"

if ($Installer) {
    $Iscc = (Get-Command iscc -ErrorAction SilentlyContinue)
    $CompilerPath = $null
    if ($Iscc) {
        $CompilerPath = $Iscc.Source
    }
    if (-not $Iscc) {
        $CandidatePaths = @(
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
        ) | Where-Object { $_ -and (Test-Path $_) }

        if ($CandidatePaths.Count -gt 0) {
            $CompilerPath = $CandidatePaths[0]
        }
    }

    if (-not $CompilerPath) {
        throw "Inno Setup compiler (iscc) was not found on PATH or in standard install locations."
    }

    $Iss = Join-Path $PSScriptRoot "installer.iss"
    Write-Host "Building installer..."
    $proc = Start-Process -FilePath $CompilerPath -ArgumentList @($Iss) -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        throw "Inno Setup compiler failed with exit code $($proc.ExitCode)."
    }
}
