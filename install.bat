@echo off
rem Ipe installer for Windows (experimental). Same flow as install.sh: resolves
rem the latest release, checks for a Rust toolchain (and offers to install it),
rem downloads ipe with a progress line, verifies its SHA-256 against the
rem release's SHA256SUMS, installs ipe.exe and ipe-ffi-inspector.exe, and offers
rem to add the install directory to your user PATH. No administrator rights.
rem
rem   install.bat
rem
rem   set IPE_INSTALL_DIR=C:\tools\ipe   install somewhere else
rem   set IPE_VERSION=v0.2.3             install a specific release
rem
rem The PowerShell body below the marker line is copied to a temp .ps1 and run.
set "IPE_BAT=%~f0"
set "IPE_PS1=%TEMP%\ipe-install-%RANDOM%.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$l = Get-Content -LiteralPath $env:IPE_BAT; $n = [array]::IndexOf($l, '#PS' + '-BODY'); Set-Content -LiteralPath $env:IPE_PS1 -Value $l[($n + 1)..($l.Count - 1)]"
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%IPE_PS1%"
set "IPE_RC=%errorlevel%"
del "%IPE_PS1%" 2>nul
exit /b %IPE_RC%
#PS-BODY
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ASCII-only file: every non-ASCII glyph is built from a code point.
$Repo = 'ipe-lang/compiler'
$Artifact = 'ipe-windows-x64.zip'
$MinCargo = [version]'1.85.0'
$MaxBytes = 512MB
$Ipe = 'Ip' + [string][char]0x00EA
$Ell = [string][char]0x2026
$Dash = [string][char]0x2014

$Interactive = -not [Console]::IsInputRedirected
$Tty = -not [Console]::IsOutputRedirected
$Color = $Tty -and (-not $env:NO_COLOR)
$Uni = $Tty -and [bool]($env:WT_SESSION -or $env:TERM_PROGRAM -or $env:ConEmuPID)
if ($Uni) {
    $GOk = [string][char]0x2713
    $GFail = [string][char]0x2717
    $GSkip = [string][char]0x2022
    $Spin = @(0x280B, 0x2819, 0x2839, 0x2838, 0x283C, 0x2834, 0x2826, 0x2827, 0x2807, 0x280F | ForEach-Object { [string][char]$_ })
} else {
    $GOk = '+'
    $GFail = 'x'
    $GSkip = '.'
    $Spin = @('-', '\', '|', '/')
}

$script:Pending = $false
$script:Label = ''
$script:LastLen = 0
$script:Rc = 0
$script:Printed = $false
$script:DieMsg = ''
$script:Tmp = ''

function Put([string]$s, [string]$c = '') {
    if ($Color -and $c) { Write-Host $s -NoNewline -ForegroundColor $c } else { Write-Host $s -NoNewline }
}

function Nl { Write-Host '' }

# Escape control, format, separator and lone-surrogate characters and
# backslashes, so no interpolated value can drive the terminal.
function Safe([string]$s) {
    $sb = New-Object Text.StringBuilder
    for ($i = 0; $i -lt $s.Length; $i++) {
        $c = $s[$i]
        if ($c -eq '\') { [void]$sb.Append('\\'); continue }
        if ([char]::IsHighSurrogate($c) -and ($i + 1) -lt $s.Length -and [char]::IsLowSurrogate($s[$i + 1])) {
            [void]$sb.Append($c)
            [void]$sb.Append($s[$i + 1])
            $i++
            continue
        }
        $cat = [char]::GetUnicodeCategory($c).ToString()
        if ($cat -in 'Control', 'Format', 'LineSeparator', 'ParagraphSeparator', 'Surrogate') {
            [void]$sb.Append('\u{' + ([int]$c).ToString('X4') + '}')
        } else {
            [void]$sb.Append($c)
        }
    }
    return $sb.ToString()
}

function ClearLine {
    if ($Tty) {
        $w = 79
        try { $w = [Console]::WindowWidth - 1 } catch { $w = 79 }
        if ($w -lt 20) { $w = 79 }
        Write-Host ("`r" + (' ' * $w) + "`r") -NoNewline
    }
    $script:LastLen = 0
}

# A stage still running is closed as a dim skip line before anything else prints.
function Detach {
    if ($script:Pending) {
        ClearLine
        Put "  $GSkip $($script:Label)" 'DarkGray'
        Nl
        $script:Pending = $false
    }
}

function StageStart([string]$label) {
    Detach
    $script:Label = $label
    if ($Tty) {
        Put ('  ' + $Spin[0] + ' ') 'Yellow'
        Put $label
        $script:Pending = $true
    } else {
        Put "  $label"
        Nl
    }
}

function StageEnd([string]$glyph, [string]$color, [string]$msg) {
    if ($script:Pending) { ClearLine; $script:Pending = $false }
    Put "  $glyph " $color
    Put $msg
    Nl
}

function StageOk([string]$msg) { StageEnd $GOk 'Green' $msg }
function StageFail([string]$msg) { StageEnd $GFail 'Red' $msg }

function Info([string]$msg) {
    Detach
    Put "    $msg" 'DarkGray'
    Nl
}

function Die([string]$msg) {
    $script:DieMsg = $msg
    throw 'die'
}

function Ask([string]$q) {
    Detach
    if (-not $Interactive) { return $false }
    # Keys typed while a stage was running must never answer a later question.
    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { $null = $_ }
    Put "  $q [Y/n] " 'Yellow'
    $a = [Console]::In.ReadLine()
    if ($null -eq $a) { Nl; return $false }
    $a = $a.Trim()
    return ($a -eq '' -or $a -match '^(y|yes)$')
}

# Runs a native tool to completion while the stage line animates a spinner and
# the elapsed time; its output goes to temp files and is discarded. Returns the
# exit code, or -1 when the tool is missing or cannot start.
function RunSpin([string]$exe, [string[]]$argv) {
    $cmd = Get-Command $exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { return -1 }
    $so = [IO.Path]::GetTempFileName()
    $se = [IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $cmd.Source -ArgumentList $argv -NoNewWindow -PassThru -RedirectStandardOutput $so -RedirectStandardError $se
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $frame = 0
        while (-not $p.HasExited) {
            if ($Tty -and $script:Pending) {
                $sp = $Spin[$frame % $Spin.Count]
                Write-Host "`r" -NoNewline
                Put "  $sp " 'Yellow'
                Put ("{0}  {1}s   " -f $script:Label, [int]$sw.Elapsed.TotalSeconds)
                $frame++
            }
            Start-Sleep -Milliseconds 100
        }
        $p.WaitForExit()
        return [int]$p.ExitCode
    } catch {
        return -1
    } finally {
        Remove-Item -LiteralPath $so, $se -Force -ErrorAction SilentlyContinue
    }
}

function Banner([string]$ver) {
    Put '  '
    Put "$Ipe language" 'Yellow'
    Put " - $ver" 'DarkGray'
    Nl
    Nl
}

function TagOk([string]$t) {
    return ($t.Length -le 128 -and $t -cmatch '^(ipe-)?v[0-9][A-Za-z0-9.+-]*$')
}

function Size([long]$b) {
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($b -ge 1MB) { return ($b / 1MB).ToString('0.0', $inv) + ' MB' }
    if ($b -ge 1KB) { return ($b / 1KB).ToString('0', $inv) + ' KB' }
    return "$b B"
}

function Exists([string]$url) {
    try {
        $r = [Net.HttpWebRequest]::Create($url)
        $r.Method = 'HEAD'
        $r.AllowAutoRedirect = $false
        $r.Timeout = 10000
        $r.UserAgent = 'ipe-install'
        $resp = $r.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        return ($code -ge 200 -and $code -lt 400)
    } catch {
        return $false
    }
}

function Progress([long]$done, [long]$total, $sw, [int]$frame) {
    $sp = $Spin[$frame % $Spin.Count]
    if ($total -gt 0) {
        $pct = [int][math]::Min(100, [math]::Floor(100.0 * $done / $total))
        $fill = [int][math]::Min(24, [math]::Floor(24.0 * $done / $total))
        $bar = ('#' * $fill) + ('-' * (24 - $fill))
        $secs = $sw.Elapsed.TotalSeconds
        $eta = ''
        if ($done -gt 0 -and $secs -gt 0.5 -and $done -lt $total) {
            $rem = [int][math]::Ceiling(($total - $done) / ($done / $secs))
            $eta = '  ETA {0}:{1:00}' -f [int][math]::Floor($rem / 60), ($rem % 60)
        }
        $text = '{0,3}% [{1}]  {2} / {3}{4}' -f $pct, $bar, (Size $done), (Size $total), $eta
    } else {
        $text = '{0} downloaded  {1}s elapsed' -f (Size $done), [int]$sw.Elapsed.TotalSeconds
    }
    $len = 4 + $text.Length
    $pad = [math]::Max(0, $script:LastLen - $len)
    Write-Host "`r" -NoNewline
    Put "  $sp " 'Yellow'
    Put ($text + (' ' * $pad))
    $script:LastLen = $len
}

# Streams the URL to a file with a bounded size; returns the byte count.
function Fetch([string]$url, [string]$dest) {
    $req = [Net.HttpWebRequest]::Create($url)
    $req.UserAgent = 'ipe-install'
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 30000
    $resp = $req.GetResponse()
    $src = $null
    $dst = $null
    try {
        $total = $resp.ContentLength
        if ($total -gt $MaxBytes) { Die 'The download is larger than the 512 MB limit - refusing to continue.' }
        $src = $resp.GetResponseStream()
        $dst = [IO.File]::Create($dest)
        $buf = New-Object byte[] 65536
        $done = [long]0
        $frame = 0
        $last = -1000
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while (($n = $src.Read($buf, 0, $buf.Length)) -gt 0) {
            $dst.Write($buf, 0, $n)
            $done += $n
            if ($done -gt $MaxBytes) { Die 'The download exceeded the 512 MB limit - refusing to continue.' }
            if ($Tty -and ($sw.ElapsedMilliseconds - $last) -ge 100) {
                $last = $sw.ElapsedMilliseconds
                Progress $done $total $sw $frame
                $frame++
            }
        }
        return $done
    } finally {
        if ($dst) { $dst.Dispose() }
        if ($src) { $src.Dispose() }
        $resp.Close()
    }
}

function CargoVersion {
    $ErrorActionPreference = 'Continue'
    try {
        $o = (& cargo --version 2>$null) -join ' '
        if ($o -match 'cargo (\d+\.\d+\.\d+)') { return [version]$Matches[1] }
    } catch {
        return $null
    }
    return $null
}

function RustHost {
    $ErrorActionPreference = 'Continue'
    try {
        foreach ($l in (& rustc -vV)) {
            if ($l -match '^host: (\S+)') { return $Matches[1] }
        }
    } catch {
        return ''
    }
    return ''
}

function HasCmd([string]$name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

function HasMsvcTools {
    $pf = ${env:ProgramFiles(x86)}
    if (-not $pf) { return $false }
    $vw = Join-Path $pf 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vw)) { return $false }
    $ErrorActionPreference = 'Continue'
    try {
        $p = (& $vw -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -join ''
        return [bool]$p
    } catch {
        return $false
    }
}

function RefreshPath {
    $m = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $u = [Environment]::GetEnvironmentVariable('Path', 'User')
    $fresh = (@($m, $u) | Where-Object { $_ }) -join ';'
    $env:Path = "$fresh;$env:Path"
}

function NoPrebuilt([string]$tag, [string]$plat) {
    Detach
    Nl
    Put "  $GFail " 'Red'
    Put ("No prebuilt binary for $(Safe $tag) on $plat.")
    Nl
    Info 'Possibly the binaries for that version are still being generated.'
    Info 'If you prefer, build from source:'
    Info "    cargo install --git https://github.com/$Repo ipe"
    $script:Printed = $true
    $script:Rc = 2
    throw 'die'
}

function ResolveLatest {
    $headers = @{ 'User-Agent' = 'ipe-install'; 'Accept' = 'application/vnd.github+json' }
    $tok = if ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } elseif ($env:GH_TOKEN) { $env:GH_TOKEN } else { $null }
    if ($tok) { $headers['Authorization'] = "Bearer $tok" }
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers -TimeoutSec 20
    } catch {
        Die ('Could not resolve the latest release: ' + (Safe $_.Exception.Message))
    }
    $t = [string]$rel.tag_name
    if (-not (TagOk $t)) { Die ('The latest release tag is not a recognised version: ' + (Safe $t)) }
    return $t
}

function Main {
    $pinned = $env:IPE_VERSION
    if ($pinned -and -not (TagOk $pinned)) {
        Die 'IPE_VERSION must look like v1.2.3 or ipe-v1.2.3.'
    }
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    $dir = Join-Path $env:USERPROFILE '.ipe\bin'
    if ($env:IPE_INSTALL_DIR) {
        $d = $env:IPE_INSTALL_DIR
        $okChars = $d -match '^[A-Za-z0-9._\\/+@:() -]+$'
        $dotdot = $d -match '(^|[\\/])\.\.([\\/]|$)'
        if (-not $okChars -or $dotdot -or -not [IO.Path]::IsPathRooted($d)) {
            Die 'IPE_INSTALL_DIR must be an absolute path made of letters, digits and . _ / \ + @ : ( ) space, with no "..".'
        }
        $dir = $d
    }

    Banner $(if ($pinned) { Safe $pinned } else { 'latest' })

    if ($pinned) {
        $tag = $pinned
    } else {
        StageStart "Resolving the latest release$Ell"
        $tag = ResolveLatest
        StageOk ('Found ' + (Safe $tag) + '.')
    }
    $ver = $tag -replace '^ipe-', ''
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $x64 = ($arch -eq 'AMD64')
    $plat = if ($x64) { 'windows-x64' } else { 'windows-' + (Safe (([string]$arch).ToLowerInvariant())) }

    StageStart "Checking for prebuilt binaries$Ell"
    $dl = "https://github.com/$Repo/releases/download/$tag"
    $have = $x64 -and (Exists "$dl/$Artifact")
    if ($have) {
        StageOk "Prebuilt binary available for $plat."
    } else {
        Info ('No prebuilt ipe ' + (Safe $ver) + " binary for $plat.")
        if ($pinned -and $x64 -and (Ask 'Install the latest release instead?')) {
            $tag = ResolveLatest
            $ver = $tag -replace '^ipe-', ''
            $dl = "https://github.com/$Repo/releases/download/$tag"
            $have = Exists "$dl/$Artifact"
            if ($have) { StageOk ('Prebuilt binary available for ' + (Safe $ver) + " on $plat.") }
        }
    }

    StageStart "Checking Rust toolchain$Ell"
    $cargoOk = $false
    if (HasCmd 'cargo') {
        $cv = CargoVersion
        if ($cv -and $cv -ge $MinCargo) {
            $cargoOk = $true
            StageOk "Found cargo $cv (>= $MinCargo)."
        } elseif ($cv) {
            Info "Found cargo $cv (< required $MinCargo)."
            Info 'Update it with: rustup update'
        } else {
            Info 'Found cargo, but it did not report a version.'
        }
    } else {
        Info 'Rust is not installed.'
        if (Test-Path -LiteralPath (Join-Path $cargoBin 'cargo.exe')) {
            Info 'Rust seems installed but not on your PATH.'
            if (Ask 'Add ~\.cargo\bin to PATH for this session?') {
                $env:Path = "$cargoBin;$env:Path"
                $cv = CargoVersion
                if ($cv) {
                    $cargoOk = $true
                    StageOk "Rust now available ($cv)."
                }
            }
        }
        if (-not $cargoOk -and (HasCmd 'winget')) {
            if (Ask 'Install Rust via rustup (winget)?') {
                StageStart "Installing Rust via rustup$Ell"
                $toolchain = if (HasMsvcTools) { 'stable-x86_64-pc-windows-msvc' } else { 'stable-x86_64-pc-windows-gnu' }
                $ErrorActionPreference = 'Continue'
                try {
                    $null = RunSpin 'winget' @('install', '-e', '--id', 'Rustlang.Rustup', '--accept-source-agreements', '--accept-package-agreements')
                    $env:Path = "$cargoBin;$env:Path"
                    RefreshPath
                    $null = RunSpin 'rustup' @('toolchain', 'install', $toolchain)
                    $null = RunSpin 'rustup' @('default', $toolchain)
                } catch {
                    $null = $_
                }
                $ErrorActionPreference = 'Stop'
                $cv = CargoVersion
                if ($cv) {
                    $cargoOk = $true
                    StageOk "Rust installed ($cv)."
                } else {
                    Info "rustup did not finish $Dash check https://rustup.rs for manual install."
                }
            }
        } elseif (-not $cargoOk) {
            Info 'Download the Rust installer from: https://win.rustup.rs/x86_64'
        }
        if (-not $cargoOk) { Info 'Install Rust later: https://rustup.rs' }
    }

    if ($cargoOk) {
        StageStart "Checking C linker$Ell"
        $rhost = RustHost
        $msvc = $rhost -like '*-msvc'
        if ((HasCmd 'gcc') -or ($msvc -and (HasMsvcTools))) {
            StageOk 'Found a C linker.'
        } elseif ($msvc) {
            Info 'The MSVC toolchain needs the "Desktop development with C++" Build Tools.'
            Info 'Or switch to the GNU toolchain: rustup default stable-x86_64-pc-windows-gnu'
        } else {
            Info 'No C linker (gcc) found.'
            if ((HasCmd 'winget') -and (Ask 'Install a C linker (WinLibs MinGW-w64) via winget?')) {
                StageStart "Installing a C linker via winget$Ell"
                $ErrorActionPreference = 'Continue'
                try {
                    $null = RunSpin 'winget' @('install', '-e', '--id', 'BrechtSanders.WinLibs.POSIX.UCRT', '--accept-source-agreements', '--accept-package-agreements')
                } catch {
                    $null = $_
                }
                $ErrorActionPreference = 'Stop'
                RefreshPath
                if (HasCmd 'gcc') {
                    StageOk 'C linker installed.'
                } else {
                    Info 'Open a new terminal, then check: gcc --version'
                }
            } else {
                Info 'Install one: winget install BrechtSanders.WinLibs.POSIX.UCRT'
            }
        }
    }

    if (-not $have) { NoPrebuilt $tag $plat }

    New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
    $zip = Join-Path $script:Tmp $Artifact
    $sums = Join-Path $script:Tmp 'SHA256SUMS'

    StageStart ('Downloading ipe ' + (Safe $ver) + " for windows-x64$Ell")
    try { [Console]::CursorVisible = $false } catch { $null = $_ }
    try {
        $size = Fetch "$dl/$Artifact" $zip
    } finally {
        try { [Console]::CursorVisible = $true } catch { $null = $_ }
    }
    StageOk ('Downloaded ' + (Size $size) + '.')

    StageStart "Verifying the download$Ell"
    try {
        Invoke-WebRequest -UseBasicParsing "$dl/SHA256SUMS" -OutFile $sums
    } catch {
        Die ('Could not fetch SHA256SUMS ' + $Dash + ' refusing to install: ' + (Safe $_.Exception.Message))
    }
    $want = $null
    foreach ($line in Get-Content $sums) {
        if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $Artifact) {
            $want = $Matches[1]
            break
        }
    }
    if (-not $want) { Die "No checksum is listed for $Artifact $Dash refusing to install." }
    $got = (Get-FileHash -Algorithm SHA256 $zip).Hash
    if ($got -ne $want.ToUpperInvariant()) {
        Die "Checksum mismatch for $Artifact $Dash refusing to install (expected $want, got $got)."
    }
    StageOk 'Checksum verified.'

    StageStart ('Installing to ' + (Safe $dir) + $Ell)
    $out = Join-Path $script:Tmp 'out'
    Expand-Archive -LiteralPath $zip -DestinationPath $out
    foreach ($exe in 'ipe.exe', 'ipe-ffi-inspector.exe') {
        if (-not (Test-Path -LiteralPath (Join-Path $out $exe))) { Die "The archive does not contain $exe." }
    }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    foreach ($exe in 'ipe.exe', 'ipe-ffi-inspector.exe') {
        Copy-Item -LiteralPath (Join-Path $out $exe) -Destination $dir -Force
    }
    StageOk ('Installed ipe ' + (Safe $ver) + ' to ' + (Safe (Join-Path $dir 'ipe.exe')))

    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($user -split ';' | Where-Object { $_ })
    $onPath = [bool]($parts | Where-Object { $_.TrimEnd('\') -ieq $dir.TrimEnd('\') })
    if (-not $onPath) {
        Info ((Safe $dir) + ' is not on your PATH yet.')
        if (Ask 'Add it to your user PATH so every terminal finds ipe?') {
            [Environment]::SetEnvironmentVariable('Path', (($parts + $dir) -join ';'), 'User')
            $env:Path = "$dir;$env:Path"
            StageOk 'Added ipe to your user PATH.'
            Info 'Open a new terminal so it picks up the change.'
        } else {
            Info 'Left your PATH untouched.'
            Info 'Add it yourself (PowerShell):'
            Info ("  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';" + $dir.Replace("'", "''") + "', 'User')")
        }
    }

    Nl
    Put '  '
    Put "$Ipe $(Safe $ver) was "
    Put 'successfully' 'Green'
    Put ' installed!'
    Nl
    Nl
    Put "  If you find any bugs, please report them at https://github.com/$Repo/issues."
    Nl
    Nl
}

$oldEnc = $null
if ($Tty) {
    try {
        $oldEnc = [Console]::OutputEncoding
        [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
    } catch { $oldEnc = $null }
}
$script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('ipe-install-' + [guid]::NewGuid())
try {
    Main
} catch {
    $m = if ($script:DieMsg) { $script:DieMsg } else { Safe $_.Exception.Message }
    if (-not $script:Printed) {
        if ($script:Pending) { ClearLine; $script:Pending = $false }
        StageFail $m
    }
    if ($script:Rc -eq 0) { $script:Rc = 1 }
} finally {
    Remove-Item -Recurse -Force -LiteralPath $script:Tmp -ErrorAction SilentlyContinue
    if ($oldEnc) { try { [Console]::OutputEncoding = $oldEnc } catch { $null = $_ } }
}
exit $script:Rc
