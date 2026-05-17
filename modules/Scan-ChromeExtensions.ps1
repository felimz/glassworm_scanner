function Scan-ChromeExtensions {
    <#
    .SYNOPSIS
        Phase 3: Chrome extension forensics - manifest analysis, known-bad matching, content scanning.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DataDir
    )

    $findings = @()
    $extData = Get-Content "$DataDir\known_bad_extensions.json" -Raw | ConvertFrom-Json
    $c2Data  = Get-Content "$DataDir\known_c2_ips.json" -Raw | ConvertFrom-Json

    $chromeBase = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (-not (Test-Path $chromeBase)) {
        $findings += [PSCustomObject]@{
            Phase    = "3-Chrome"
            Severity = "INFO"
            Item     = "Chrome Installation"
            Detail   = "Chrome user data directory not found at $chromeBase"
            Reason   = "Chrome may not be installed"
        }
        return $findings
    }

    # Find all profile Extension directories
    $extDirs = @()
    Get-ChildItem -Path $chromeBase -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -eq "Default" -or $_.Name -match "^Profile \d+"
    } | ForEach-Object {
        $extPath = Join-Path $_.FullName "Extensions"
        if (Test-Path $extPath) { $extDirs += $extPath }
    }

    $legitimateDocsOfflineId = $extData.chrome_legitimate.google_docs_offline

    # Known-good extension IDs that legitimately need broad permissions
    $knownGoodExtIds = @(
        "ghbmnnjooekpmoecnnnilnnbdlolhkhi",  # Google Docs Offline
        "nmmhkkegccagdldgiimedpiccmgmieda",  # Google Payments
        "eeijfnjmjelapkebgockoeaadonbchdd",  # Antigravity Browser Extension
        "fgddmllnllkalaagkghckoinaemmogpe",  # ExpressVPN
        "kbmfpngjjgdllneeigpgjifpgocmfgmb",  # Reddit Enhancement Suite
        "ddkjiahejlhfcafbddmgiahcphecmpfh"   # uBlock Origin / other known
    )

    foreach ($extDir in $extDirs) {
        $profileName = Split-Path (Split-Path $extDir) -Leaf
        Write-Host "  [3A] Scanning profile: $profileName..." -ForegroundColor Cyan

        Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extensionId = $_.Name
            $extRoot = $_.FullName

            # Find latest version directory
            $versionDir = Get-ChildItem -Path $extRoot -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -First 1
            if (-not $versionDir) { return }

            $manifestPath = Join-Path $versionDir.FullName "manifest.json"
            if (-not (Test-Path $manifestPath)) { return }

            try {
                $manifest = Get-Content $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
            } catch {
                $findings += [PSCustomObject]@{
                    Phase    = "3A-Manifest"
                    Severity = "MEDIUM"
                    Item     = "Unknown Extension ($extensionId)"
                    Detail   = "Profile: $profileName | Failed to parse manifest.json at $manifestPath"
                    Reason   = "Corrupt or obfuscated manifest"
                }
                return
            }

            # Resolve localized extension name
            $extName = if ($manifest.name) { $manifest.name } else { "UNKNOWN" }
            $resolvedName = $extName
            if ($extName -match "^__MSG_(.+)__$") {
                $msgKey = $Matches[1]
                $localeFile = Join-Path $versionDir.FullName "_locales\en\messages.json"
                if (-not (Test-Path $localeFile)) {
                    $localeFile = Join-Path $versionDir.FullName "_locales\en_US\messages.json"
                }
                if (Test-Path $localeFile) {
                    try {
                        $msgs = Get-Content $localeFile -Raw | ConvertFrom-Json
                        if ($msgs.$msgKey) { $resolvedName = $msgs.$msgKey.message }
                    } catch { }
                }
                if ($resolvedName -eq $extName) { $resolvedName = "$extName (localized name not resolved)" }
            }

            $permissions = @()
            if ($manifest.permissions) { $permissions += $manifest.permissions }
            if ($manifest.optional_permissions) { $permissions += $manifest.optional_permissions }
            $hostPerms = @()
            if ($manifest.host_permissions) { $hostPerms += $manifest.host_permissions }

            $permDisplay = if ($permissions.Count -gt 0) { $permissions -join ", " } else { "none" }

            # --- 3A: Permission Analysis ---

            # CRITICAL: Fake Google Docs Offline detection
            if ($extName -match "Google Docs Offline" -and $extensionId -ne $legitimateDocsOfflineId) {
                $findings += [PSCustomObject]@{
                    Phase    = "3A-Manifest"
                    Severity = "CRITICAL"
                    Item     = "FAKE: $resolvedName ($extensionId)"
                    Detail   = "Profile: $profileName | Version: $($manifest.version) | Legitimate ID is $legitimateDocsOfflineId but this extension uses $extensionId | Permissions: $permDisplay"
                    Reason   = "GLASSWORM INDICATOR: Fake Google Docs Offline extension detected"
                }
            }

            # HIGH: Dangerous permission combos (surveillance kit)
            $hasCookies    = "cookies" -in $permissions
            $hasWebRequest = ($permissions | Where-Object { $_ -match "webRequest" }).Count -gt 0
            $hasTabs       = "tabs" -in $permissions
            $hasAllUrls    = ("<all_urls>" -in $permissions) -or ("<all_urls>" -in $hostPerms)
            $hasScripting  = "scripting" -in $permissions
            $hasDebugger   = "debugger" -in $permissions
            $hasNativeMsg  = "nativeMessaging" -in $permissions
            $hasClipboard  = "clipboardRead" -in $permissions

            if ($hasCookies -and $hasWebRequest -and $hasTabs -and $hasAllUrls) {
                if ($extensionId -notin $knownGoodExtIds) {
                    $findings += [PSCustomObject]@{
                        Phase    = "3A-Manifest"
                        Severity = "HIGH"
                        Item     = "$resolvedName ($extensionId)"
                        Detail   = "Profile: $profileName | Version: $($manifest.version) | Dangerous combo: cookies + webRequest + tabs + <all_urls> | Full permissions: $permDisplay"
                        Reason   = "Surveillance-capable permission set - can intercept all traffic and steal sessions"
                    }
                }
            }

            if ($hasDebugger) {
                $findings += [PSCustomObject]@{
                    Phase    = "3A-Manifest"
                    Severity = "HIGH"
                    Item     = "$resolvedName ($extensionId)"
                    Detail   = "Profile: $profileName | Version: $($manifest.version) | Has 'debugger' permission | Full permissions: $permDisplay"
                    Reason   = "Can attach to any tab and intercept all network traffic"
                }
            }

            if ($hasNativeMsg -and $extensionId -notin $knownGoodExtIds) {
                $findings += [PSCustomObject]@{
                    Phase    = "3A-Manifest"
                    Severity = "MEDIUM"
                    Item     = "$resolvedName ($extensionId)"
                    Detail   = "Profile: $profileName | Version: $($manifest.version) | Has 'nativeMessaging' permission - can launch host binaries | Full permissions: $permDisplay"
                    Reason   = "Can launch host processes - verify this is expected"
                }
            }

            # --- 3C: Content Scanning (JS files) ---
            $jsFiles = Get-ChildItem -Path $versionDir.FullName -Recurse -Include "*.js","*.html" -ErrorAction SilentlyContinue
            foreach ($jsFile in $jsFiles) {
                try {
                    $content = Get-Content $jsFile.FullName -Raw -ErrorAction Stop
                    if (-not $content) { continue }

                    # Check for C2 IPs
                    foreach ($c2 in ($c2Data.c2_servers + $c2Data.exfiltration + $c2Data.phishing)) {
                        if ($content -match [regex]::Escape($c2.ip)) {
                            $findings += [PSCustomObject]@{
                                Phase    = "3C-Content"
                                Severity = "CRITICAL"
                                Item     = "$resolvedName ($extensionId)"
                                Detail   = "Profile: $profileName | File: $($jsFile.Name) | Contains known C2 IP: $($c2.ip) ($($c2.type): $($c2.note))"
                                Reason   = "GLASSWORM INDICATOR: Known C2/exfil IP found in extension source"
                            }
                        }
                    }

                    # Check for Solana RPC endpoints
                    foreach ($rpc in $c2Data.solana.rpc_domains) {
                        if ($content -match [regex]::Escape($rpc)) {
                            $findings += [PSCustomObject]@{
                                Phase    = "3C-Content"
                                Severity = "CRITICAL"
                                Item     = "$resolvedName ($extensionId)"
                                Detail   = "Profile: $profileName | File: $($jsFile.Name) | References Solana RPC endpoint: $rpc"
                                Reason   = "GLASSWORM INDICATOR: Solana blockchain C2 resolution pattern"
                            }
                        }
                    }

                    # Check for Solana wallet address
                    if ($content -match [regex]::Escape($c2Data.solana.wallet)) {
                        $findings += [PSCustomObject]@{
                            Phase    = "3C-Content"
                            Severity = "CRITICAL"
                            Item     = "$resolvedName ($extensionId)"
                            Detail   = "Profile: $profileName | File: $($jsFile.Name) | Contains GlassWorm attacker wallet: $($c2Data.solana.wallet)"
                            Reason   = "GLASSWORM CONFIRMED: Known attacker wallet address in extension"
                        }
                    }

                    # Check for suspicious patterns
                    $suspPatterns = @(
                        @{ Pattern = "document\.cookie"; Reason = "Cookie access via DOM" },
                        @{ Pattern = "chrome\.cookies\.getAll"; Reason = "Bulk cookie theft API" },
                        @{ Pattern = "addEventListener\s*\(\s*['""]key(down|press|up)['""]"; Reason = "Keylogger pattern (keydown/keypress/keyup listener)" },
                        @{ Pattern = "chrome\.debugger\.attach"; Reason = "Debugger attachment API" }
                    )

                    foreach ($sp in $suspPatterns) {
                        if ($content -match $sp.Pattern) {
                            # Only flag if not a well-known extension
                            if ($extensionId -notin $knownGoodExtIds) {
                                $findings += [PSCustomObject]@{
                                    Phase    = "3C-Content"
                                    Severity = "MEDIUM"
                                    Item     = "$resolvedName ($extensionId)"
                                    Detail   = "Profile: $profileName | File: $($jsFile.Name) | Pattern: $($sp.Reason)"
                                    Reason   = "Suspicious code pattern - verify legitimacy"
                                }
                            }
                        }
                    }
                } catch { }
            }

            # Baseline entry for clean extensions
            $extFindings = $findings | Where-Object { $_.Item -match [regex]::Escape($extensionId) -and $_.Severity -notin @("INFO") }
            if ($extFindings.Count -eq 0) {
                $findings += [PSCustomObject]@{
                    Phase    = "3-Chrome"
                    Severity = "INFO"
                    Item     = "$resolvedName ($extensionId)"
                    Detail   = "Profile: $profileName | Version: $($manifest.version) | Permissions: $permDisplay"
                    Reason   = "No suspicious indicators detected"
                }
            }
        }
    }

    return $findings
}
