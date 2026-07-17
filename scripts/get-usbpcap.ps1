<#
.SYNOPSIS
    Download and install USBPcap - the free kernel-mode USB capture driver this
    project's USB backend drives (see README / DESIGN.md section 4).

.DESCRIPTION
    reveng-rec's USB capture talks to the USBPcap kernel driver (USBPcap.sys)
    directly over its IOCTL interface; it does not need USBPcapCMD.exe at runtime.
    This script installs that driver: it fetches the official signed installer
    straight from the desowin/usbpcap GitHub releases, verifies it, and runs it
    (which installs both the driver and the bundled USBPcapCMD.exe). After install
    it reports where USBPcapCMD.exe landed and, unless you pass -NoEnv, sets a
    user-level USBPCAPCMD env var pointing at it -- used only by the optional legacy
    CLI fallback (REVENG_USBPCAP_CLI=1).

    USBPcap installs a kernel driver: installation needs Administrator, and a reboot
    is usually required before the first capture works.

.PARAMETER Silent
    Install without the interactive NSIS UI (passes /S to the installer).

.PARAMETER DownloadOnly
    Download and verify the installer but do not run it. Prints the path.

.PARAMETER Version
    Pin a specific release tag (e.g. 1.5.4.0). Default: whatever the GitHub API
    reports as the latest release.

.PARAMETER OutDir
    Where to save the installer. Default: $env:TEMP.

.PARAMETER NoEnv
    Do not set the user-level USBPCAPCMD environment variable after install.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/get-usbpcap.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/get-usbpcap.ps1 -Silent
#>
[CmdletBinding()]
param(
    [switch]$Silent,
    [switch]$DownloadOnly,
    [string]$Version,
    [string]$OutDir = $env:TEMP,
    [switch]$NoEnv
)

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 defaults to TLS 1.0 - GitHub requires 1.2+.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }

$repo    = 'desowin/usbpcap'
$headers = @{ 'User-Agent' = 'reveng-recorder-installer'; 'Accept' = 'application/vnd.github+json' }

# ----------------------------------------------------------------------------
# 0. Already installed?
# ----------------------------------------------------------------------------
function Find-UsbPcapCmd {
    $cmd = Get-Command USBPcapCMD.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
            (Join-Path $env:ProgramFiles        'USBPcap\USBPcapCMD.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'USBPcap\USBPcapCMD.exe'))) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    return $null
}

$existing = Find-UsbPcapCmd
if ($existing -and -not $DownloadOnly) {
    Write-Ok "USBPcap already installed: $existing"
    Write-Ok "(delete it first if you want to reinstall). Nothing to do."
    if (-not $NoEnv) {
        [Environment]::SetEnvironmentVariable('USBPCAPCMD', $existing, 'User')
        Write-Ok "Set user env USBPCAPCMD=$existing"
    }
    exit 0
}

# ----------------------------------------------------------------------------
# 1. Resolve the installer asset URL from the GitHub releases API.
#    Falls back to the known-good 1.5.4.0 pin if the API is unreachable.
# ----------------------------------------------------------------------------
$assetUrl = $null
$assetName = $null
$assetSize = 0
try {
    $rel = if ($Version) {
        Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repo/releases/tags/$Version"
    } else {
        Invoke-RestMethod -Headers $headers -Uri "https://api.github.com/repos/$repo/releases/latest"
    }
    Write-Step "Latest USBPcap release: $($rel.tag_name) - $($rel.name)"
    $asset = $rel.assets | Where-Object { $_.name -like 'USBPcapSetup-*.exe' } | Select-Object -First 1
    if ($asset) {
        $assetUrl  = $asset.browser_download_url
        $assetName = $asset.name
        $assetSize = [int]$asset.size
    }
} catch {
    Write-Warn2 "GitHub API lookup failed ($($_.Exception.Message)); using pinned fallback."
}

if (-not $assetUrl) {
    $assetName = 'USBPcapSetup-1.5.4.0.exe'
    $assetUrl  = "https://github.com/$repo/releases/download/1.5.4.0/$assetName"
    $assetSize = 195040
    Write-Step "Using pinned installer: $assetName"
}

# ----------------------------------------------------------------------------
# 2. Download + verify.
# ----------------------------------------------------------------------------
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$dest = Join-Path $OutDir $assetName

Write-Step "Downloading $assetUrl"
Invoke-WebRequest -Headers $headers -Uri $assetUrl -OutFile $dest
$got = (Get-Item $dest).Length
Write-Ok "Saved $dest ($got bytes)"

if ($assetSize -gt 0 -and $got -ne $assetSize) {
    throw "Size mismatch: expected $assetSize bytes, got $got. Delete $dest and retry."
}

# Sanity: it must be a PE ('MZ') executable, and ideally Authenticode-signed by desowin.
$mz = [System.IO.File]::ReadAllBytes($dest)[0..1]
if ($mz[0] -ne 0x4D -or $mz[1] -ne 0x5A) {
    throw "Downloaded file is not a Windows executable (bad MZ header): $dest"
}
$sha = (Get-FileHash -Algorithm SHA256 -Path $dest).Hash
Write-Ok "SHA256: $sha"
try {
    $sig = Get-AuthenticodeSignature -FilePath $dest
    if ($sig.Status -eq 'Valid') {
        Write-Ok "Authenticode: Valid - $($sig.SignerCertificate.Subject)"
    } else {
        throw "Authenticode signature is not valid ($($sig.Status)); refusing to run $dest."
    }
} catch {
    throw "Could not verify the installer signature: $($_.Exception.Message)"
}

if ($DownloadOnly) {
    Write-Step "Download-only requested. Installer at: $dest"
    exit 0
}

# ----------------------------------------------------------------------------
# 3. Install (needs Administrator - the driver install elevates via UAC).
# ----------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn2 "Not elevated - the installer will raise its own UAC prompt. Approve it to install the driver."
}

Write-Step "Running installer$(if ($Silent) {' (silent)'})"
$installArgs = if ($Silent) { '/S' } else { $null }
$proc = if ($installArgs) { Start-Process -FilePath $dest -ArgumentList $installArgs -Wait -PassThru }
        else               { Start-Process -FilePath $dest -Wait -PassThru }
Write-Ok "Installer exited with code $($proc.ExitCode)"
if ($proc.ExitCode -ne 0) {
    throw "USBPcap installer failed with exit code $($proc.ExitCode)."
}

# ----------------------------------------------------------------------------
# 4. Verify + wire up discovery.
# ----------------------------------------------------------------------------
$cmd = Find-UsbPcapCmd
if ($cmd) {
    Write-Step "USBPcap installed."
    Write-Ok "USBPcapCMD.exe -> $cmd"
    if (-not $NoEnv) {
        [Environment]::SetEnvironmentVariable('USBPCAPCMD', $cmd, 'User')
        Write-Ok "Set user env USBPCAPCMD=$cmd (open a new shell to pick it up)."
    }
    Write-Host ""
    Write-Warn2 "A REBOOT is usually required before the first capture works (kernel driver)."
    Write-Host  "    Then: reveng-rec devices --format json" -ForegroundColor Gray
} else {
    Write-Warn2 "Install finished but USBPcapCMD.exe was not found on PATH or in Program Files\USBPcap."
    Write-Warn2 "If you chose a custom install dir, set USBPCAPCMD to its USBPcapCMD.exe path."
    exit 1
}
