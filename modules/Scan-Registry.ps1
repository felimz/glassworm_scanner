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

    $findings = [System.Collections.Generic.List[PSObject]]::new()
    try {
        $regData = Get-Content "$DataDir\suspicious_registry_values.json" -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Host "  ERROR: Failed to load $DataDir\suspicious_registry_values.json — $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }

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

            [void]$findings.Add([PSCustomObject]@{
                Phase    = "1A-Registry"
                Severity = $severity
                Item     = "[$hiveShort\$keyType] $valName"
                Detail   = "Command: $valData | Signature: $sigStatus $(if($sigDetail){" ($sigDetail)"})"
                Reason   = $reason
            })
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
                    [void]$findings.Add([PSCustomObject]@{
                        Phase    = "1B-ChromePolicy"
                        Severity = "HIGH"
                        Item     = "Force-Install Policy: $($_.Name)"
                        Detail   = "Key: $pKey | Value: $($_.Value)"
                        Reason   = "Chrome extension force-install policy detected - verify this is from enterprise GPO"
                    })
                }
            }
        }
    }

    $noPolicies = -not ($policyKeys | Where-Object { Test-Path $_ })
    if ($noPolicies) {
        [void]$findings.Add([PSCustomObject]@{
            Phase    = "1B-ChromePolicy"
            Severity = "INFO"
            Item     = "Chrome Extension Policies"
            Detail   = "Checked 4 policy registry paths (HKLM/HKCU Forcelist + Allowlist) - none exist"
            Reason   = "No Chrome extension force-install policies found - clean"
        })
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
    try {
        foreach ($dir in $shortcutPaths) {
            if (-not (Test-Path $dir)) { continue }
            Get-ChildItem -Path $dir -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $lnk = $shell.CreateShortcut($_.FullName)
                    $target = $lnk.TargetPath
                    $lnkArgs = $lnk.Arguments
                    $shortcutsScanned++

                    $isBrowser = $browserExes | Where-Object { $target -like "*$_*" }
                    if ($isBrowser -and $lnkArgs) {
                        if ($lnkArgs -match "--load-extension=" -or $lnkArgs -match "--disable-extensions-except=") {
                            [void]$findings.Add([PSCustomObject]@{
                                Phase    = "1C-ShortcutHijack"
                                Severity = "CRITICAL"
                                Item     = "Hijacked Shortcut: $($_.Name)"
                                Detail   = "Location: $($_.FullName) | Target: $target | Args: $lnkArgs"
                                Reason   = "Browser shortcut contains extension-loading arguments - possible GlassWorm sideload"
                            })
                        }
                    }
                } catch { }
            }
        }
    } finally {
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
    }

    $hijackFindings = $findings | Where-Object { $_.Phase -eq "1C-ShortcutHijack" -and $_.Severity -ne "INFO" }
    if (-not $hijackFindings -or $hijackFindings.Count -eq 0) {
        [void]$findings.Add([PSCustomObject]@{
            Phase    = "1C-ShortcutHijack"
            Severity = "INFO"
            Item     = "Browser Shortcuts"
            Detail   = "Scanned $shortcutsScanned shortcuts across Desktop, Start Menu, and Taskbar"
            Reason   = "No browser shortcut manipulation found"
        })
    }

    # --- 1D: GlassWorm Filesystem IOCs (jucku, staging directories, persistence scripts) ---
    Write-Host "  [1D] Scanning for GlassWorm filesystem IOCs..." -ForegroundColor Cyan


    # Check for jucku directory (primary GlassWorm Chrome extension staging)
    $juckuPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\jucku",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\jucku",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\jucku"
    )
    foreach ($jp in $juckuPaths) {
        if (Test-Path $jp) {
            $fileCount = (Get-ChildItem $jp -Recurse -ErrorAction SilentlyContinue).Count
            [void]$findings.Add([PSCustomObject]@{
                Phase    = "1D-FilesystemIOC"
                Severity = "CRITICAL"
                Item     = "JUCKU DIRECTORY FOUND"
                Detail   = "Path: $jp | Files: $fileCount | This is the GlassWorm fake Chrome extension staging directory"
                Reason   = "GLASSWORM CONFIRMED: jucku directory is a primary indicator of active GlassWorm infection"
            })
        }
    }

    # Check for staging directories
    $stagingDirs = @(
        "$env:LOCALAPPDATA\QtCvyfVWKH"
    )
    foreach ($sd in $stagingDirs) {
        if (Test-Path $sd) {
            $files = Get-ChildItem $sd -Recurse -ErrorAction SilentlyContinue
            $fileList = ($files | Select-Object -First 5 -ExpandProperty Name) -join ", "
            [void]$findings.Add([PSCustomObject]@{
                Phase    = "1D-FilesystemIOC"
                Severity = "CRITICAL"
                Item     = "GLASSWORM STAGING DIRECTORY"
                Detail   = "Path: $sd | Files: $($files.Count) | Contents: $fileList"
                Reason   = "GLASSWORM CONFIRMED: QtCvyfVWKH is a known GlassWorm malware staging directory"
            })
        }
    }

    # Check for AghzgY.ps1 persistence script anywhere in AppData
    Write-Host "  [1D] Scanning for persistence scripts..." -ForegroundColor Cyan
    $persistScripts = @("AghzgY.ps1")
    foreach ($ps in $persistScripts) {
        $found = Get-ChildItem "$env:LOCALAPPDATA" -Filter $ps -Recurse -ErrorAction SilentlyContinue
        if ($found) {
            foreach ($f in $found) {
                [void]$findings.Add([PSCustomObject]@{
                    Phase    = "1D-FilesystemIOC"
                    Severity = "CRITICAL"
                    Item     = "GLASSWORM PERSISTENCE SCRIPT: $ps"
                    Detail   = "Path: $($f.FullName) | Size: $($f.Length) bytes | Modified: $($f.LastWriteTime)"
                    Reason   = "GLASSWORM CONFIRMED: AghzgY.ps1 is the GlassWorm Stage 3 persistence launcher"
                })
            }
        }
    }

    # Check for fake Google Docs Offline with known-bad version
    $chromeExtDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
    if (Test-Path $chromeExtDir) {
        $docsOfflineId = "ghbmnnjooekpmoecnnnilnnbdlolhkhi"
        $docsExtDir = Join-Path $chromeExtDir $docsOfflineId
        if (Test-Path $docsExtDir) {
            Get-ChildItem $docsExtDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $manifestPath = Join-Path $_.FullName "manifest.json"
                if (Test-Path $manifestPath) {
                    try {
                        $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
                        if ($m.version -eq "1.95.1") {
                            [void]$findings.Add([PSCustomObject]@{
                                Phase    = "1D-FilesystemIOC"
                                Severity = "CRITICAL"
                                Item     = "FAKE GOOGLE DOCS OFFLINE v1.95.1"
                                Detail   = "Extension ID: $docsOfflineId | Version: 1.95.1 | This is a known GlassWorm trojanized version"
                                Reason   = "GLASSWORM CONFIRMED: Google Docs Offline v1.95.1 is a known-compromised version deployed by GlassWorm"
                            })
                        }
                    } catch { }
                }
            }
        }
    }

    # Report clean if no filesystem IOCs found
    $fsFindings = $findings | Where-Object { $_.Phase -eq "1D-FilesystemIOC" }
    if (-not $fsFindings -or $fsFindings.Count -eq 0) {
        [void]$findings.Add([PSCustomObject]@{
            Phase    = "1D-FilesystemIOC"
            Severity = "INFO"
            Item     = "GlassWorm Filesystem IOCs"
            Detail   = "Checked jucku directory, QtCvyfVWKH staging, AghzgY.ps1 script, Docs Offline v1.95.1 - none found"
            Reason   = "No GlassWorm filesystem artifacts detected"
        })
    }

    return $findings
}
