# Install Open Trestle for the current user from a GitHub release.
#
#   irm https://georgejieh.dev/open-trestle/install.ps1 | iex
#   powershell -ExecutionPolicy Bypass -File install.ps1 [-Version VERSION] [-Uninstall] [-NoModifyPath]
#
# Under irm | iex, pass options as environment variables:
# OPEN_TRESTLE_VERSION, OPEN_TRESTLE_UNINSTALL=1, OPEN_TRESTLE_NO_MODIFY_PATH=1
# (show the PATH change without making it), OPEN_TRESTLE_INSTALL_ROOT,
# NO_COLOR. For testing a mirror: OPEN_TRESTLE_BASE_URL (files at
# BASE/vVERSION/NAME) and OPEN_TRESTLE_API_URL (a GitHub release list).
#
# Everything is inside one function that the last lines call, so a download
# cut short inside it runs nothing. It calls exit only when run as a file:
# under irm | iex, exit would close the window. It never reads input.

param(
    [string]$Version = $env:OPEN_TRESTLE_VERSION,
    [switch]$Uninstall,
    [switch]$NoModifyPath
)

$openTrestleOptions = @{
    Version = $Version
    Uninstall = $Uninstall.IsPresent -or $env:OPEN_TRESTLE_UNINSTALL -eq '1'
    NoModifyPath = $NoModifyPath.IsPresent -or $env:OPEN_TRESTLE_NO_MODIFY_PATH -eq '1'
}

# It takes no arguments, so a call cut short still runs with the options above.
function Install-OpenTrestle {
    $Version = $openTrestleOptions.Version
    $Uninstall = $openTrestleOptions.Uninstall
    $NoModifyPath = $openTrestleOptions.NoModifyPath

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    $repository = 'georgejieh/open-trestle'
    $baseUrl = if ($env:OPEN_TRESTLE_BASE_URL) { $env:OPEN_TRESTLE_BASE_URL.TrimEnd('/') } else { "https://github.com/$repository/releases/download" }
    $apiUrl = if ($env:OPEN_TRESTLE_API_URL) { $env:OPEN_TRESTLE_API_URL } else { "https://api.github.com/repos/$repository/releases?per_page=10" }
    $semver = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'

    $utf8 = [Console]::OutputEncoding.CodePage -eq 65001
    $color = -not (Test-Path Env:NO_COLOR) -and -not [Console]::IsOutputRedirected
    $okMark = if ($utf8) { [string][char]0x2713 } else { '[ok]' }
    $waitMark = if ($utf8) { [string][char]0x2026 } else { '[..]' }
    $badMark = if ($utf8) { [string][char]0x2717 } else { '[x]' }
    $dot = if ($utf8) { [string][char]0x00B7 } else { '-' }
    function Write-Line([string]$Text) { Write-Host $Text }
    function Write-Mark([string]$Mark, [string]$Text, [string]$Tone) {
        Write-Host '  ' -NoNewline
        if ($color) { Write-Host $Mark -NoNewline -ForegroundColor $Tone } else { Write-Host $Mark -NoNewline }
        Write-Host " $Text"
    }
    function Write-Step([string]$Text) { Write-Mark $waitMark $Text 'Yellow' }
    function Write-Done([string]$Text) { Write-Mark $okMark $Text 'Green' }
    function Write-Fail([string]$Text) { Write-Mark $badMark $Text 'Red' }

    if ($color) { Write-Host "Open Trestle $dot install" -ForegroundColor White } else { Write-Line "Open Trestle $dot install" }

    if ($env:OS -ne 'Windows_NT') {
        Write-Fail 'This installer is for Windows; on Linux, run: curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash'
        return 1
    }
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -ne 'AMD64') {
        Write-Fail "Releases are built for amd64 only, and this machine is $arch. Build from source instead: https://github.com/$repository/blob/main/docs/install.md"
        return 1
    }
    if (-not $env:LOCALAPPDATA -and -not $env:OPEN_TRESTLE_INSTALL_ROOT) {
        Write-Fail 'LOCALAPPDATA is not set.'
        return 1
    }
    $root = if ($env:OPEN_TRESTLE_INSTALL_ROOT) { $env:OPEN_TRESTLE_INSTALL_ROOT } else { Join-Path $env:LOCALAPPDATA 'Programs\OpenTrestle' }
    if (-not [System.IO.Path]::IsPathRooted($root)) {
        Write-Fail 'OPEN_TRESTLE_INSTALL_ROOT must be an absolute path.'
        return 1
    }
    $root = [System.IO.Path]::GetFullPath($root).TrimEnd('\')

    # An install folder is one this script made: a version name holding
    # bin\trestle.exe and the archive's README.txt.
    function Test-Install([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        if ($item.Name -notmatch $semver -or -not (Test-Path -LiteralPath (Join-Path $Path 'bin\trestle.exe') -PathType Leaf)) { return $false }
        $readme = Join-Path $Path 'README.txt'
        return (Test-Path -LiteralPath $readme -PathType Leaf) -and ((Get-Content -LiteralPath $readme -TotalCount 1) -like 'Open Trestle *')
    }
    function Get-Installs {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
        return @(Get-ChildItem -LiteralPath $root -Directory -Force | Where-Object { Test-Install $_.FullName })
    }
    # A virus scanner may hold a program it has just seen for a moment.
    function Remove-Tree([string]$Path) {
        for ($try = 1; ; $try++) {
            try { Remove-Item -LiteralPath $Path -Recurse -Force; return $true }
            catch { if ($try -ge 10) { return $false }; Start-Sleep -Milliseconds 500 }
        }
    }

    # The user PATH is read raw and written as REG_EXPAND_SZ, so entries such
    # as %USERPROFILE%\bin stay unexpanded.
    $environmentKey = 'Environment'
    function Get-UserPath {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($environmentKey)
        try { return [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $key.Close() }
    }
    function Test-OurPathEntry([string]$Entry) {
        $prefix = [regex]::Escape($root + '\')
        return $Entry -match "^$prefix[^\\]+\\bin\\?$" -and ($Entry.Substring($root.Length + 1) -split '\\')[0] -match $semver
    }
    function Set-UserPath([string]$Wanted) {
        $current = Get-UserPath
        $entries = @($current -split ';' | Where-Object { $_ -and -not (Test-OurPathEntry $_) })
        if ($Wanted) { $entries = @($Wanted) + $entries }
        $updated = $entries -join ';'
        if ($updated -eq $current) { return $false }
        if ($NoModifyPath) {
            $dropped = @($current -split ';' | Where-Object { $_ -and (Test-OurPathEntry $_) })
            if ($Wanted) { Write-Line "  Would add $Wanted to the user PATH." }
            foreach ($entry in $dropped) { Write-Line "  Would remove $entry from the user PATH." }
            Write-Line '  The user PATH was not changed (-NoModifyPath).'
            return $false
        }
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($environmentKey, $true)
        try { $key.SetValue('Path', $updated, [Microsoft.Win32.RegistryValueKind]::ExpandString) } finally { $key.Close() }
        # Tell Explorer, so new terminals see the change.
        if (-not ('OpenTrestleInstall.Broadcast' -as [type])) {
            Add-Type -Namespace OpenTrestleInstall -Name Broadcast -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
        }
        $result = [UIntPtr]::Zero
        [void][OpenTrestleInstall.Broadcast]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
        $session = @($env:Path -split ';' | Where-Object { $_ -and -not (Test-OurPathEntry $_) })
        if ($Wanted) { $session = @($Wanted) + $session }
        $env:Path = $session -join ';'
        return $true
    }

    $userHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { '~' }
    $state = if ($env:XDG_STATE_HOME -and [System.IO.Path]::IsPathRooted($env:XDG_STATE_HOME)) { $env:XDG_STATE_HOME } else { Join-Path $userHome '.local\state' }

    if ($Uninstall) {
        $grants = Join-Path $state 'open-trestle\sandbox-grants'
        if (Test-Path -LiteralPath $grants) {
            Write-Fail "Repository checks recorded folder grants in $grants. Run trestle checks off to take them back, then run the uninstall again. Nothing was removed."
            return 1
        }
        $removed = $false
        if (Set-UserPath '') { $removed = $true }
        foreach ($install in Get-Installs) {
            if (-not (Remove-Tree $install.FullName)) { Write-Fail "Could not remove $($install.FullName): close any running trestle or trestled and run the uninstall again."; return 1 }
            $removed = $true
        }
        Get-ChildItem -LiteralPath $root -Directory -Force -Filter '.download-*' -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        Remove-Item -LiteralPath (Join-Path $root 'install.log') -Force -ErrorAction SilentlyContinue
        if ((Test-Path -LiteralPath $root) -and -not (Get-ChildItem -LiteralPath $root -Force)) { Remove-Item -LiteralPath $root -Force }
        if ($removed) { Write-Done "Removed Open Trestle from $root and the user PATH." }
        else { Write-Done "Nothing to remove: no install by this script was found in $root." }
        Write-Line "  Kept your setup and usage records ($state\open-trestle),"
        Write-Line "  saved keys ($userHome\.config\open-trestle\credentials) and the scanner"
        Write-Line "  cache ($userHome\.cache\open-trestle, safe to delete)."
        return 0
    }

    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    $defaultUrls = -not $env:OPEN_TRESTLE_BASE_URL -and -not $env:OPEN_TRESTLE_API_URL

    try { New-Item -ItemType Directory -Force -Path $root | Out-Null }
    catch { Write-Fail "Cannot create $root."; return 1 }
    # Only this account and the system's own accounts may change the install.
    # Every file inherits this, which is what Open Trestle requires of its
    # secret scan helper.
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $root /inheritance:r /grant:r "*${userSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Fail "Cannot set owner-only access on $root."; return 1 }

    $log = Join-Path $root 'install.log'
    Set-Content -LiteralPath $log -Value '' -Encoding UTF8
    function Write-Log([string]$Text) { Add-Content -LiteralPath $log -Value $Text -Encoding UTF8 }
    function Show-LogTail {
        Get-Content -LiteralPath $log -Tail 15 | ForEach-Object { Write-Host "      $_" }
    }
    function Get-Url([string]$Url, [string]$OutFile) {
        Write-Log "==> GET $Url"
        if ($defaultUrls -and $Url -notmatch '^https://') { throw "refusing a non-HTTPS address: $Url" }
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -MaximumRedirection 10
    }

    $staging = Join-Path $root ('.download-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $staging | Out-Null
    try {
        if (-not $Version) {
            Write-Step 'Finding the latest release'
            try {
                Get-Url $apiUrl (Join-Path $staging 'releases.json')
                $releases = Get-Content -LiteralPath (Join-Path $staging 'releases.json') -Raw | ConvertFrom-Json
            } catch {
                Write-Log $_.Exception.Message
                Write-Fail "Reading the release list failed. Last lines of ${log}:"
                Show-LogTail
                return 1
            }
            $tag = @($releases | ForEach-Object { $_.tag_name } | Where-Object { $_ -match '^v' -and $_.Substring(1) -match $semver }) | Select-Object -First 1
            if (-not $tag) { Write-Fail "No release was found at $apiUrl."; return 1 }
            $Version = $tag
            Write-Done "Latest release: $tag."
        }
        $Version = $Version -replace '^v', ''
        if ($Version -notmatch $semver) { Write-Fail "$Version is not a release version (such as 0.1.0-alpha.1)."; return 1 }

        function Get-Revision([string]$Program) {
            try { $info = (& $Program build-info 2>>$log) -join '' } catch { Write-Log $_.Exception.Message; return $null }
            if ($LASTEXITCODE -ne 0) { return $null }
            try { $document = $info | ConvertFrom-Json } catch { return $null }
            if ($document.version -ne $Version -or $document.source_bound -ne $true -or $document.source_revision -notmatch '^[0-9a-f]{40,64}$') { return $null }
            return $document.source_revision.Substring(0, 12)
        }

        $target = Join-Path $root $Version
        $bin = Join-Path $target 'bin'
        $previous = @(Get-Installs | Where-Object { $_.Name -ne $Version } | ForEach-Object { $_.Name })
        $revision = $null
        if ((Test-Install $target) -and ($revision = Get-Revision (Join-Path $bin 'trestle.exe'))) {
            Write-Done "Open Trestle $Version is already installed (source revision $revision)."
        } else {
            $name = "open-trestle-$Version-windows-amd64"
            $archive = "$name.zip"
            Write-Step "Downloading Open Trestle $Version"
            try {
                Get-Url "$baseUrl/v$Version/$archive" (Join-Path $staging $archive)
                Get-Url "$baseUrl/v$Version/SHA256SUMS" (Join-Path $staging 'SHA256SUMS')
            } catch {
                Write-Log $_.Exception.Message
                Write-Fail "Downloading $archive failed. Last lines of ${log}:"
                Show-LogTail
                return 1
            }
            $expected = $null
            foreach ($line in Get-Content -LiteralPath (Join-Path $staging 'SHA256SUMS')) {
                $fields = $line -split '\s+'
                if ($fields.Count -ge 2 -and ($fields[1] -eq $archive -or $fields[1] -eq "*$archive")) { $expected = $fields[0].ToLowerInvariant() }
            }
            $actual = (Get-FileHash -LiteralPath (Join-Path $staging $archive) -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -ne $actual) {
                Write-Fail "$archive does not match its SHA-256 in SHA256SUMS. Nothing was changed."
                return 1
            }
            Write-Done "Checked the SHA-256 of $archive against SHA256SUMS."

            $unpacked = Join-Path $staging 'x'
            try { Expand-Archive -LiteralPath (Join-Path $staging $archive) -DestinationPath $unpacked }
            catch { Write-Log $_.Exception.Message; Write-Fail "Unpacking $archive failed. Last lines of ${log}:"; Show-LogTail; return 1 }
            $new = Join-Path $unpacked $name
            $helper = Join-Path $new 'libexec\open-trestle\open-trestle-scan-helper.exe'
            foreach ($path in @((Join-Path $new 'bin\trestle.exe'), (Join-Path $new 'bin\trestled.exe'), $helper)) {
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Write-Fail "$archive does not hold the expected programs. Nothing was changed."; return 1 }
            }
            # The program refuses a helper that an account other than yours or
            # the system's own may change.
            $trusted = @($userSid, 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
            $changeRights = [int]([Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, ChangePermissions, TakeOwnership')
            $sidType = [Security.Principal.SecurityIdentifier]
            $acl = Get-Acl -LiteralPath $helper
            $owner = $acl.GetOwner($sidType).Value
            $open = @($acl.GetAccessRules($true, $true, $sidType) | Where-Object {
                $_.AccessControlType -eq 'Allow' -and ([int]$_.FileSystemRights -band $changeRights) -and $trusted -notcontains $_.IdentityReference.Value
            })
            if ($trusted -notcontains $owner -or $open.Count -ne 0) {
                Write-Fail "Another account may change the secret scan helper in $root, which Open Trestle refuses. Nothing was changed."
                return 1
            }
            $revision = Get-Revision (Join-Path $new 'bin\trestle.exe')
            if (-not $revision) {
                Write-Fail "The downloaded trestle does not run or does not report version $Version. Nothing was changed."
                Show-LogTail
                return 1
            }
            Write-Done "Unpacked and checked: trestle build-info reports $Version (source revision $revision)."

            if (Test-Path -LiteralPath $target) {
                try { Move-Item -LiteralPath $target -Destination (Join-Path $staging 'replaced') }
                catch { Write-Fail "Cannot move the old $target aside: close any running trestle or trestled and run the installer again."; return 1 }
            }
            Move-Item -LiteralPath $new -Destination $target
            if (-not (Get-Revision (Join-Path $bin 'trestle.exe'))) {
                Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path -LiteralPath (Join-Path $staging 'replaced')) { Move-Item -LiteralPath (Join-Path $staging 'replaced') -Destination $target }
                Write-Fail "trestle $Version did not start from $target. Kept what was installed before."
                return 1
            }
        }

        $pathChanged = Set-UserPath $bin
        foreach ($old in $previous) {
            if (-not (Remove-Tree (Join-Path $root $old))) { Write-Line "  Note: $old could not be removed yet (is trestle running?); the next run removes it." }
        }
        if ($previous.Count -gt 0) { Write-Done "Replaced $($previous -join ', ') with $Version." }
        Write-Done "Installed in $target."

        $next = 'trestle init'
        $userEntries = @((Get-UserPath) -split ';')
        if ($NoModifyPath -and $userEntries -notcontains $bin) {
            Write-Line "  $bin is not on your PATH."
            $next = "& '$bin\trestle.exe' init"
        } elseif ($pathChanged) {
            Write-Line "  Added $bin to your user PATH. Terminals that were already open"
            Write-Line '  keep the old PATH; open a new one there.'
        }
        $found = Get-Command trestle -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found -and $userEntries -contains $bin -and $found.Source -ne (Join-Path $bin 'trestle.exe')) {
            Write-Line "  Note: $($found.Source) comes first on your PATH, so trestle runs that one."
            $next = "& '$bin\trestle.exe' init"
        }
        Write-Line ''
        Write-Line "Next, inside the Git repository you want reviewed: $next"
        return 0
    } finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$openTrestleCode = Install-OpenTrestle
if ($PSCommandPath) { exit ([int]@($openTrestleCode)[-1]) }
