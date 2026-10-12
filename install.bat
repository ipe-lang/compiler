@echo off
rem Ipe installer for Windows (experimental) - downloads the latest release,
rem verifies its SHA-256 against the release's SHA256SUMS, installs ipe.exe and
rem ipe-ffi-inspector.exe, and adds the install directory to your user PATH.
rem No administrator rights needed.
rem
rem   install.bat
rem
rem Override the install directory:  set IPE_INSTALL_DIR=C:\tools\ipe
rem The PowerShell body below the marker line is copied to a temp .ps1 and run.
set "IPE_BAT=%~f0"
set "IPE_PS1=%TEMP%\ipe-install-%RANDOM%.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$l = Get-Content -LiteralPath $env:IPE_BAT; $n = [array]::IndexOf($l, '#PS' + '-BODY'); Set-Content -LiteralPath $env:IPE_PS1 -Value $l[($n + 1)..($l.Count - 1)]"
powershell -NoProfile -ExecutionPolicy Bypass -File "%IPE_PS1%"
set "IPE_RC=%errorlevel%"
del "%IPE_PS1%" 2>nul
exit /b %IPE_RC%
#PS-BODY
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocol]::Tls12
$artifact = 'ipe-windows-x64.zip'
$base = 'https://github.com/ipe-lang/compiler/releases/latest/download'
$dir = if ($env:IPE_INSTALL_DIR) { $env:IPE_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.ipe\bin' }
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('ipe-install-' + [guid]::NewGuid())

Write-Host 'Ipe installer for Windows - EXPERIMENTAL'
try {
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $zip = Join-Path $tmp $artifact
    $sums = Join-Path $tmp 'SHA256SUMS'
    Write-Host 'Downloading the latest release...'
    Invoke-WebRequest -UseBasicParsing "$base/$artifact" -OutFile $zip
    Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile $sums

    $want = $null
    foreach ($line in Get-Content $sums) {
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $artifact) {
            $want = $Matches[1]
            break
        }
    }
    if (-not $want) { throw "no checksum listed for $artifact - refusing to install" }
    $got = (Get-FileHash -Algorithm SHA256 $zip).Hash
    if ($got -ne $want.ToUpperInvariant()) {
        throw "checksum mismatch for $artifact - refusing to install (expected $want, got $got)"
    }

    Write-Host "Installing to $dir ..."
    $out = Join-Path $tmp 'out'
    Expand-Archive -LiteralPath $zip -DestinationPath $out
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($exe in 'ipe.exe', 'ipe-ffi-inspector.exe') {
        Copy-Item -LiteralPath (Join-Path $out $exe) -Destination $dir -Force
    }

    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($user -split ';' | Where-Object { $_ })
    if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') })) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $dir) -join ';'), 'User')
        Write-Host "Added $dir to your user PATH."
    }

    Write-Host 'Installed. Open a NEW terminal, then run: ipe --version'
    $missing = @()
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $missing += 'Rust (cargo)' }
    if (-not ((Get-Command gcc -ErrorAction SilentlyContinue) -or (Get-Command link -ErrorAction SilentlyContinue))) {
        $missing += 'a C linker (gcc or MSVC link.exe)'
    }
    if ($missing) {
        Write-Warning ("ipe compiles to Rust and still needs: " + ($missing -join ', ') + '. See docs/guide/windows.md, steps 1 and 2.')
    }
} catch {
    Write-Host "install failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
}
