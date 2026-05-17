function Scan-Registry {
    <#
    .SYNOPSIS
        Phase 1: Windows Registry audit for GlassWorm persistence indicators.
    .DESCRIPTION
        Scans Run/RunOnce keys, Chrome extension force-install policies,
        and browser shortcut hijacking for GlassWorm fingerprints.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DataDir
    )

    $findings = @()
    $regData = Get-Content "$DataDir\suspicious_registry_values.json" -Raw | ConvertFrom-Json

    Write-Host "  [1A] Scanning Run/RunOnce keys..." -ForegroundColor Cyan

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($keyPath in $runKeys) {
        if (-not (Test-Path $keyPath)) { continue }
        $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        # Determine hive shorthand for display
        $hiveShort = if ($keyPath -match "^HKCU") { "HKCU" } else { "HKLM" }
        $keyType   = if ($keyPath -match "RunOnce") { "RunOnce" } else { "Run" }

        $props.PSObject.Properties | Where-Object {
            $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
        } | ForEach-Object {
            $valName = $_.Name
            $valData = $_.Value
            $severity = "INFO"
            $reason = "Baseline entry"

            # Check against known-bad value names
            if ($valName -in $regData.known_bad_value_names) {
                $severity = "CRITICAL"
                $reason = "Matches known GlassWorm registry value name"
            }
            # Check against suspicious name patterns
            elseif ($regData.suspicious_patterns | Where-Object { $valName -match $_ }) {
                $severity = "HIGH"
                $reason = "Value name matches suspicious pattern: $($regData.suspicious_patterns | Where-Object { $valName -match $_ } | Select-Object -First 1)"
            }
            # Check against suspicious path patterns
            elseif ($regData.suspicious_path_patterns | Where-Object { $valData -match $_ }) {
                $matchedPattern = $regData.suspicious_path_patterns | Where-Object { $valData -match $_ } | Select-Object -First 1
                $severity = "HIGH"
                $reason = "Executable path matches suspicious pattern: $matchedPattern"
            }
            # Check if known-good
            elseif ($valName -in $regData.known_good_value_names) {
                $severity = "INFO"
                $reason = "Known-good application"
            }
            # Unknown entry - flag for review
            else {
                $severity = "MEDIUM"
                $reason = "Unrecognized Run key entry - manual review recommended"
            }

            # Signature verification for non-INFO entries
            $sigStatus = "N/A"
            $sigDetail = ""
            if ($severity -ne "INFO") {
                $exePath = $valData -replace '^"([^"]+)".*', '$1'
                $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)
                if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                    $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                    $sigStatus = if ($sig) { $sig.Status.ToString() } else { "NoSignature" }
                    $sigDetail = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unknown signer" }
                    if ($sigStatus -ne "Valid" -and $severity -eq "MEDIUM") {
                        $severity = "HIGH"
                        $reason += " | Binary is NOT digitally signed"
                    }
                } else {
                    $sigStatus = "FileNotFound"
                    $sigDetail = "Target binary does not exist on disk"
                }
            }

            $findings += [PSCustomObject]@{
                Phase    = "1A-Registry"
                Severity = $severity
                Item     = "[$hiveShort\$keyType] $valName"
                Detail   = "Command: $valData | Signature: $sigStatus $(if($sigDetail){" ($sigDetail)"})"
                Reason   = $reason
            }
        }
    }

    # --- 1B: Chrome Extension Force-Install Policies ---
    Write-Host "  [1B] Scanning Chrome extension policies..." -ForegroundColor Cyan

    $policyKeys = @(
        "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
        "HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
        "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist",
        "HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist"
    )

    foreach ($pKey in $policyKeys) {
        if (Test-Path $pKey) {
            $props = Get-ItemProperty -Path $pKey -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object {
                    $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
                } | ForEach-Object {
                    $findings += [PSCustomObject]@{
                        Phase    = "1B-ChromePolicy"
                        Severity = "HIGH"
                        Item     = "Force-Install Policy: $($_.Name)"
                        Detail   = "Key: $pKey | Value: $($_.Value)"
                        Reason   = "Chrome extension force-install policy detected - verify this is from enterprise GPO"
                    }
                }
            }
        }
    }

    $noPolicies = -not ($policyKeys | Where-Object { Test-Path $_ })
    if ($noPolicies) {
        $findings += [PSCustomObject]@{
            Phase    = "1B-ChromePolicy"
            Severity = "INFO"
            Item     = "Chrome Extension Policies"
            Detail   = "Checked 4 policy registry paths (HKLM/HKCU Forcelist + Allowlist) - none exist"
            Reason   = "No Chrome extension force-install policies found - clean"
        }
    }

    # --- 1C: Browser Shortcut Hijacking ---
    Write-Host "  [1C] Scanning browser shortcuts for hijacking..." -ForegroundColor Cyan

    $shortcutPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    )
    $browserExes = @("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe")
    $shell = New-Object -ComObject WScript.Shell
    $shortcutsScanned = 0

    foreach ($dir in $shortcutPaths) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $lnk = $shell.CreateShortcut($_.FullName)
                $target = $lnk.TargetPath
                $args = $lnk.Arguments
                $shortcutsScanned++

                $isBrowser = $browserExes | Where-Object { $target -like "*$_*" }
                if ($isBrowser -and $args) {
                    if ($args -match "--load-extension=" -or $args -match "--disable-extensions-except=") {
                        $findings += [PSCustomObject]@{
                            Phase    = "1C-ShortcutHijack"
                            Severity = "CRITICAL"
                            Item     = "Hijacked Shortcut: $($_.Name)"
                            Detail   = "Location: $($_.FullName) | Target: $target | Args: $args"
                            Reason   = "Browser shortcut contains extension-loading arguments - possible GlassWorm sideload"
                        }
                    }
                }
            } catch { }
        }
    }

    $findings += [PSCustomObject]@{
        Phase    = "1C-ShortcutHijack"
        Severity = "INFO"
        Item     = "Browser Shortcuts"
        Detail   = "Scanned $shortcutsScanned shortcuts across Desktop, Start Menu, and Taskbar - no hijacking detected"
        Reason   = "No browser shortcut manipulation found"
    }

    return $findings
}
