function Scan-AntigravityExtensions {
    <#
    .SYNOPSIS
        Phase 4: Antigravity extension and configuration audit.
    .DESCRIPTION
        Verifies MCP configuration integrity, implicit data store anomalies,
        Antigravity Chrome extension authenticity, and brain/knowledge directory safety.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AntigravityDir
    )

    $findings = @()

    # --- 4A: MCP Configuration Integrity ---
    Write-Host "  [4A] Auditing MCP configuration..." -ForegroundColor Cyan

    $mcpConfigPath = Join-Path $AntigravityDir "mcp_config.json"
    if (Test-Path $mcpConfigPath) {
        try {
            $mcpConfig = Get-Content $mcpConfigPath -Raw | ConvertFrom-Json

            # Check for unexpected server configurations
            if ($mcpConfig.mcpServers -or $mcpConfig.servers) {
                $servers = if ($mcpConfig.mcpServers) { $mcpConfig.mcpServers } else { $mcpConfig.servers }
                $serverProps = $servers.PSObject.Properties

                foreach ($srv in $serverProps) {
                    $srvName = $srv.Name
                    $srvConfig = $srv.Value
                    $command = $srvConfig.command
                    $srvArgs = $srvConfig.args

                    # Check if command executable exists and is signed
                    if ($command) {
                        $resolvedCmd = $command
                        if (-not (Test-Path $resolvedCmd -ErrorAction SilentlyContinue)) {
                            # Try to resolve via PATH
                            $resolvedCmd = (Get-Command $command -ErrorAction SilentlyContinue).Source
                        }

                        if ($resolvedCmd -and (Test-Path $resolvedCmd -ErrorAction SilentlyContinue)) {
                            $sig = Get-AuthenticodeSignature -FilePath $resolvedCmd -ErrorAction SilentlyContinue
                            if ($sig -and $sig.Status -ne "Valid") {
                                $findings += [PSCustomObject]@{
                                    Phase    = "4A-MCP"
                                    Severity = "MEDIUM"
                                    Item     = "MCP Server: $srvName"
                                    Detail   = "Command: $command (Signature: $($sig.Status))"
                                    Reason   = "MCP server binary is not digitally signed"
                                }
                            }
                        }

                        # Check for suspicious command patterns
                        if ($command -match "curl|wget|Invoke-WebRequest|Invoke-RestMethod") {
                            $findings += [PSCustomObject]@{
                                Phase    = "4A-MCP"
                                Severity = "HIGH"
                                Item     = "MCP Server: $srvName"
                                Detail   = "Command: $command"
                                Reason   = "MCP server uses network download command — verify intent"
                            }
                        }
                    }

                    # Check environment variables for suspicious URLs or tokens
                    if ($srvConfig.env) {
                        $srvConfig.env.PSObject.Properties | ForEach-Object {
                            $envVal = $_.Value
                            if ($envVal -match "^https?://" -and $envVal -notmatch "localhost|127\.0\.0\.1|github\.com|googleapis\.com") {
                                $findings += [PSCustomObject]@{
                                    Phase    = "4A-MCP"
                                    Severity = "MEDIUM"
                                    Item     = "MCP Server: $srvName"
                                    Detail   = "Env var $($_.Name) contains external URL: $envVal"
                                    Reason   = "MCP server env references non-standard external URL — verify legitimacy"
                                }
                            }
                        }
                    }
                }

                $findings += [PSCustomObject]@{
                    Phase    = "4A-MCP"
                    Severity = "INFO"
                    Item     = "MCP Config"
                    Detail   = "$($serverProps.Count) MCP server(s) configured"
                    Reason   = "MCP configuration parsed successfully"
                }
            }
        } catch {
            $findings += [PSCustomObject]@{
                Phase    = "4A-MCP"
                Severity = "MEDIUM"
                Item     = "MCP Config"
                Detail   = "Failed to parse: $($_.Exception.Message)"
                Reason   = "Corrupt or tampered MCP configuration"
            }
        }
    } else {
        $findings += [PSCustomObject]@{
            Phase    = "4A-MCP"
            Severity = "INFO"
            Item     = "MCP Config"
            Detail   = "No mcp_config.json found"
            Reason   = "No MCP servers configured"
        }
    }

    # --- 4B: Implicit Data Store Analysis ---
    Write-Host "  [4B] Analyzing implicit data store..." -ForegroundColor Cyan

    $implicitDir = Join-Path $AntigravityDir "implicit"
    if (Test-Path $implicitDir) {
        $pbFiles = Get-ChildItem -Path $implicitDir -File -ErrorAction SilentlyContinue
        $sizes = $pbFiles | ForEach-Object { $_.Length }
        $avgSize = if ($sizes.Count -gt 0) { ($sizes | Measure-Object -Average).Average } else { 0 }
        $maxSize = if ($sizes.Count -gt 0) { ($sizes | Measure-Object -Maximum).Maximum } else { 0 }

        foreach ($pb in $pbFiles) {
            # Flag files much larger than average (>5x) — could contain injected payloads
            if ($avgSize -gt 0 -and $pb.Length -gt ($avgSize * 5)) {
                $findings += [PSCustomObject]@{
                    Phase    = "4B-ImplicitData"
                    Severity = "MEDIUM"
                    Item     = $pb.Name
                    Detail   = "Size: $($pb.Length) bytes (avg: $([math]::Round($avgSize)) bytes, $([math]::Round($pb.Length / $avgSize, 1))x average)"
                    Reason   = "Anomalously large protobuf file — may warrant inspection"
                }
            }

            # Flag files modified at unusual hours (midnight-5am)
            $hour = $pb.LastWriteTime.Hour
            if ($hour -ge 0 -and $hour -lt 5) {
                $findings += [PSCustomObject]@{
                    Phase    = "4B-ImplicitData"
                    Severity = "INFO"
                    Item     = $pb.Name
                    Detail   = "Last modified: $($pb.LastWriteTime)"
                    Reason   = "File modified during unusual hours (midnight-5am)"
                }
            }
        }

        # Check for non-.pb files (unexpected file types)
        $nonPbFiles = Get-ChildItem -Path $implicitDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -ne ".pb" }
        foreach ($npf in $nonPbFiles) {
            $findings += [PSCustomObject]@{
                Phase    = "4B-ImplicitData"
                Severity = "HIGH"
                Item     = $npf.Name
                Detail   = "Unexpected file type in implicit dir: $($npf.Extension)"
                Reason   = "Only .pb files expected — could be injected payload"
            }
        }

        $findings += [PSCustomObject]@{
            Phase    = "4B-ImplicitData"
            Severity = "INFO"
            Item     = "Implicit Store"
            Detail   = "$($pbFiles.Count) protobuf files, avg $([math]::Round($avgSize)) bytes"
            Reason   = "Data store enumerated"
        }
    }

    # --- 4C: Antigravity Chrome Extension Verification ---
    Write-Host "  [4C] Verifying Antigravity Chrome extension..." -ForegroundColor Cyan

    $expectedExtId = "eeijfnjmjelapkebgockoeaadonbchdd"
    $expectedPerms = @("activeTab", "tabs", "webRequest", "storage", "offscreen")
    $chromeExtDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions\$expectedExtId"

    if (Test-Path $chromeExtDir) {
        $versionDir = Get-ChildItem -Path $chromeExtDir -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1

        if ($versionDir) {
            $manifestPath = Join-Path $versionDir.FullName "manifest.json"
            if (Test-Path $manifestPath) {
                $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

                # Verify name
                if ($manifest.name -ne "Antigravity Browser Extension") {
                    $findings += [PSCustomObject]@{
                        Phase    = "4C-AntigravityExt"
                        Severity = "CRITICAL"
                        Item     = "Antigravity Extension"
                        Detail   = "Name mismatch: expected 'Antigravity Browser Extension', got '$($manifest.name)'"
                        Reason   = "Extension identity has been tampered with"
                    }
                }

                # Verify permissions haven't been expanded
                $actualPerms = @($manifest.permissions)
                $unexpectedPerms = $actualPerms | Where-Object { $_ -notin $expectedPerms }
                if ($unexpectedPerms) {
                    $findings += [PSCustomObject]@{
                        Phase    = "4C-AntigravityExt"
                        Severity = "HIGH"
                        Item     = "Antigravity Extension"
                        Detail   = "Unexpected permissions: $($unexpectedPerms -join ', ')"
                        Reason   = "Antigravity extension has permissions beyond expected set"
                    }
                }

                # Check for duplicate Antigravity extensions with different IDs
                $profiles = Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq "Default" -or $_.Name -match "^Profile \d+" }
                foreach ($profile in $profiles) {
                    $extPath = Join-Path $profile.FullName "Extensions"
                    if (-not (Test-Path $extPath)) { continue }
                    Get-ChildItem $extPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        if ($_.Name -ne $expectedExtId) {
                            $otherManifest = Get-ChildItem $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($otherManifest) {
                                try {
                                    $om = Get-Content $otherManifest.FullName -Raw | ConvertFrom-Json
                                    if ($om.name -match "Antigravity") {
                                        $findings += [PSCustomObject]@{
                                            Phase    = "4C-AntigravityExt"
                                            Severity = "CRITICAL"
                                            Item     = "Duplicate Antigravity"
                                            Detail   = "Second extension with name '$($om.name)' found with ID: $($_.Name)"
                                            Reason   = "POSSIBLE SHADOW EXTENSION — Antigravity is being impersonated"
                                        }
                                    }
                                } catch { }
                            }
                        }
                    }
                }

                $findings += [PSCustomObject]@{
                    Phase    = "4C-AntigravityExt"
                    Severity = "INFO"
                    Item     = "Antigravity Extension"
                    Detail   = "Version: $($manifest.version) | Permissions: $($actualPerms -join ', ')"
                    Reason   = "Extension verified"
                }
            }
        }
    } else {
        $findings += [PSCustomObject]@{
            Phase    = "4C-AntigravityExt"
            Severity = "INFO"
            Item     = "Antigravity Extension"
            Detail   = "Extension directory not found at expected path"
            Reason   = "Antigravity Chrome extension may not be installed"
        }
    }

    # --- 4D: Brain/Knowledge Directory Audit ---
    Write-Host "  [4D] Scanning brain/knowledge directories for executable files..." -ForegroundColor Cyan

    $dangerousExtensions = @(".exe",".dll",".bat",".cmd",".ps1",".vbs",".wsf",".scr",".com",".pif",".msi")
    $scanDirs = @(
        (Join-Path $AntigravityDir "brain"),
        (Join-Path $AntigravityDir "knowledge")
    )

    foreach ($scanDir in $scanDirs) {
        if (-not (Test-Path $scanDir)) { continue }
        Get-ChildItem -Path $scanDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Extension -in $dangerousExtensions) {
                $findings += [PSCustomObject]@{
                    Phase    = "4D-BrainKnowledge"
                    Severity = "HIGH"
                    Item     = $_.FullName
                    Detail   = "Executable file in data directory: $($_.Name) ($($_.Length) bytes)"
                    Reason   = "Executable files should NOT be present in brain/knowledge stores"
                }
            }
        }
    }

    return $findings
}
