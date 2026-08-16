<#
.SYNOPSIS
  Zen IdP installer for Windows.

.DESCRIPTION
  Downloads, verifies, and installs the Zen IdP executable for Windows.

.EXAMPLE
  # Install or update to latest version
  irm https://get.varavel.com/zen-idp.ps1 | iex

.EXAMPLE
  # Install specific version
  $env:VERSION = "vx.x.x"; irm https://get.varavel.com/zen-idp.ps1 | iex

.EXAMPLE
  # Install to a custom directory quietly
  $env:INSTALL_DIR = "$HOME\.local\bin"; $env:QUIET = "true"; irm https://get.varavel.com/zen-idp.ps1 | iex

.EXAMPLE
  # If you encounter an execution policy error, use this command instead:
  powershell -ExecutionPolicy ByPass -Command "irm https://get.varavel.com/zen-idp.ps1 | iex"
  # Or with configuration
  powershell -ExecutionPolicy ByPass -Command "`$env:VERSION = 'vx.x.x'; irm https://get.varavel.com/zen-idp.ps1 | iex"

.NOTES
  Options (environment variables):
    VERSION      : Version to install (e.g., vx.x.x). Defaults to "latest".
    INSTALL_DIR  : Install directory. Defaults to "$env:LOCALAPPDATA\Programs\zen-idp".
    QUIET        : Set to "true" to suppress output.
#>

$ErrorActionPreference = "Stop"

$script:Repo = "varavelio/zen-idp"
$script:BinaryName = "zen-idp"
$script:InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:LOCALAPPDATA\Programs\zen-idp" }
$script:Version = if ($env:VERSION) { $env:VERSION } else { "" }
$script:Quiet = $env:QUIET -eq "true"
$script:TmpDir = $null
$script:UseColors = $Host.UI.SupportsVirtualTerminal -and -not $script:Quiet

function Write-Info($Message) {
  if (-not $script:Quiet) {
    if ($script:UseColors) { Write-Host "[INFO] " -ForegroundColor Green -NoNewline; Write-Host $Message }
    else { Write-Host "[INFO] $Message" }
  }
}

function Write-Warn($Message) {
  if (-not $script:Quiet) {
    if ($script:UseColors) { Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $Message }
    else { Write-Host "[WARN] $Message" }
  }
}

function Write-Err($Message) {
  if (-not $script:Quiet) {
    if ($script:UseColors) { Write-Host "[ERROR] " -ForegroundColor Red -NoNewline; Write-Host $Message }
    else { Write-Host "[ERROR] $Message" }
  }
}

function Show-Banner {
  if (-not $script:Quiet) {
    if ($script:UseColors) { Write-Host "Zen IdP - declarative, zero-maintenance OIDC Identity Provider" -ForegroundColor Blue }
    else { Write-Host "Zen IdP - declarative, zero-maintenance OIDC Identity Provider" }
  }
}

function Invoke-Cleanup {
  if ($script:TmpDir -and (Test-Path $script:TmpDir)) {
    Remove-Item -Recurse -Force $script:TmpDir -ErrorAction SilentlyContinue
  }
}

function Get-PlatformArch {
  $arch = if ($env:PROCESSOR_ARCHITECTURE) { $env:PROCESSOR_ARCHITECTURE } else { "unknown" }
  switch ($arch.ToUpper()) {
    "AMD64" { return "amd64" }
    "X86_64" { return "amd64" }
    "ARM64" { return "arm64" }
    "AARCH64" { return "arm64" }
    default {
      Write-Err "Unsupported architecture: $arch. Zen IdP publishes Windows amd64 and arm64 binaries."
      exit 1
    }
  }
}

function Get-LatestVersion {
  if ([string]::IsNullOrEmpty($script:Version) -or $script:Version -eq "latest") {
    Write-Info "Fetching latest version..."
    try {
      $null = Invoke-WebRequest -Uri "https://github.com/$script:Repo/releases/latest" -Method Head -MaximumRedirection 0 -ErrorAction Stop -UseBasicParsing
    } catch {
      $response = $_.Exception.Response
      if ($response -and $response.Headers.Location) {
        $location = $response.Headers.Location
        if ($location -is [array]) { $location = $location[0] }
        if ($location -match "/tag/(v?[^/?#\s]+)") { $script:Version = $Matches[1] }
      }
    }

    if ([string]::IsNullOrEmpty($script:Version)) {
      Write-Err "Failed to determine latest version. Set VERSION=vx.y.z and retry."
      exit 1
    }
  }

  if (-not $script:Version.StartsWith("v")) { $script:Version = "v$($script:Version)" }
  if ($script:Version -eq "v") {
    Write-Err "Invalid version. Set VERSION=vx.y.z and retry."
    exit 1
  }
}

function Install-ZenIdp {
  $script:TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "zen-idp-install-$(Get-Random)"
  New-Item -ItemType Directory -Path $script:TmpDir -Force | Out-Null

  try {
    $arch = Get-PlatformArch
    $filename = "$($script:BinaryName)_windows_${arch}.zip"
    $downloadUrl = "https://github.com/$script:Repo/releases/download/$script:Version/$filename"
    $checksumsUrl = "https://github.com/$script:Repo/releases/download/$script:Version/checksums.txt"
    $zipPath = Join-Path $script:TmpDir $filename
    $checksumsPath = Join-Path $script:TmpDir "checksums.txt"

    Write-Info "Installing $script:Version"
    Write-Info "Downloading $filename..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing

    Write-Info "Verifying checksum..."
    $expectedLine = Get-Content $checksumsPath | Where-Object { ($_ -split "\s+")[1] -eq $filename }
    if (-not $expectedLine) {
      Write-Err "Checksum entry for $filename was not found."
      exit 1
    }
    $expectedHash = ($expectedLine -split "\s+")[0].ToUpper()
    $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpper()
    if ($expectedHash -ne $actualHash) {
      Write-Err "Checksum verification failed."
      exit 1
    }

    Write-Info "Extracting..."
    Expand-Archive -Path $zipPath -DestinationPath $script:TmpDir -Force

    $binSource = Join-Path $script:TmpDir "$($script:BinaryName).exe"
    if (-not (Test-Path $binSource)) {
      Write-Err "Binary not found in archive."
      exit 1
    }

    Write-Info "Installing to $script:InstallDir..."
    if (-not (Test-Path $script:InstallDir)) {
      New-Item -ItemType Directory -Path $script:InstallDir -Force | Out-Null
    }

    $binDest = Join-Path $script:InstallDir "$($script:BinaryName).exe"
    Copy-Item -Path $binSource -Destination $binDest -Force

    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$script:InstallDir*") {
      Write-Info "Adding $script:InstallDir to user PATH..."
      $newPath = if ($currentPath) { "$currentPath;$script:InstallDir" } else { $script:InstallDir }
      [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
      $env:PATH = "$env:PATH;$script:InstallDir"
    }

    Write-Info "Installation complete. Restart your terminal and run 'zen-idp help' to verify."
  } finally {
    Invoke-Cleanup
  }
}

Show-Banner
Get-LatestVersion
Install-ZenIdp
