function Scan-VSCodeExtensions {
    <#
    .SYNOPSIS
        Phase 5: VS Code extension audit — known-bad matching, dependency chain, and source code analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DataDir
    )

    $findings = @()
    $extData = Get-Content "$DataDir\known_bad_extensions.json" -Raw | ConvertFrom-Json
    $knownBadIds = $extData.vscode | ForEach-Object { $_.id.ToLower() }

    $vscodePaths = @(
        "$env:USERPROFILE\.vscode\extensions",
        "$env:USERPROFILE\.vscode-insiders\extensions",
        "$env:USERPROFILE\.vscode-oss\extensions"
    )

    $foundAny = $false

    foreach ($vscPath in $vscodePaths) {
        if (-not (Test-Path $vscPath)) { continue }
        $foundAny = $true

        Write-Host "  [5A] Scanning VS Code extensions at: $vscPath" -ForegroundColor Cyan

        Get-ChildItem -Path $vscPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extFolder = $_
            $pkgJsonPath = Join-Path $extFolder.FullName "package.json"

            if (-not (Test-Path $pkgJsonPath)) { return }

            try {
                $pkgJson = Get-Content $pkgJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json
            } catch {
                $findings += [PSCustomObject]@{
                    Phase    = "5A-VSCode"
                    Severity = "MEDIUM"
                    Item     = $extFolder.Name
                    Detail   = "Could not parse package.json"
                    Reason   = "Corrupt or obfuscated extension metadata"
                }
                return
            }

            $publisher = $pkgJson.publisher
            $name = $pkgJson.name
            $version = $pkgJson.version
            $fullId = "$publisher.$name".ToLower()

            # --- 5A: Known-Bad Extension Check ---
            if ($fullId -in $knownBadIds) {
                $matchInfo = $extData.vscode | Where-Object { $_.id.ToLower() -eq $fullId }
                $versionMatch = $version -in $matchInfo.versions

                $findings += [PSCustomObject]@{
                    Phase    = "5A-VSCode"
                    Severity = "CRITICAL"
                    Item     = $fullId
                    Detail   = "Version: $version | Known-bad versions: $($matchInfo.versions -join ', ') | Note: $($matchInfo.note)"
                    Reason   = if ($versionMatch) {
                        "GLASSWORM CONFIRMED: Known compromised extension AND version installed"
                    } else {
                        "GLASSWORM WARNING: Known compromised extension installed (different version)"
                    }
                }
            }

            # --- 5B: Dependency Chain Analysis ---
            $extDeps = @()
            if ($pkgJson.extensionDependencies) { $extDeps += $pkgJson.extensionDependencies }
            if ($pkgJson.extensionPack) { $extDeps += $pkgJson.extensionPack }

            foreach ($dep in $extDeps) {
                if ($dep.ToLower() -in $knownBadIds) {
                    $findings += [PSCustomObject]@{
                        Phase    = "5B-Dependencies"
                        Severity = "CRITICAL"
                        Item     = $fullId
                        Detail   = "Depends on known-bad extension: $dep"
                        Reason   = "GLASSWORM SUPPLY CHAIN: Extension pulls in compromised dependency"
                    }
                }
            }

            # Check for post-install scripts
            if ($pkgJson.scripts) {
                $dangerousScripts = @("postinstall", "preinstall", "install", "prepare")
                foreach ($ds in $dangerousScripts) {
                    if ($pkgJson.scripts.$ds) {
                        $findings += [PSCustomObject]@{
                            Phase    = "5B-Dependencies"
                            Severity = "MEDIUM"
                            Item     = $fullId
                            Detail   = "Has '$ds' script: $($pkgJson.scripts.$ds)"
                            Reason   = "Post-install scripts can execute arbitrary code during extension installation"
                        }
                    }
                }
            }

            # --- 5C: Source Code Spot Check ---
            $jsFiles = Get-ChildItem -Path $extFolder.FullName -Recurse -Include "*.js" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch "node_modules" } | Select-Object -First 20

            foreach ($jsFile in $jsFiles) {
                try {
                    $content = Get-Content $jsFile.FullName -Raw -ErrorAction Stop
                    if (-not $content) { continue }

                    # Check for credential file access
                    $credPatterns = @(
                        @{ P = "\.npmrc"; R = "npm token file access" },
                        @{ P = "\.ssh/"; R = "SSH key directory access" },
                        @{ P = "\.git-credentials"; R = "Git credential file access" },
                        @{ P = "process\.env\.(NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN)"; R = "Token environment variable access" },
                        @{ P = "child_process"; R = "Child process spawning" }
                    )

                    foreach ($cp in $credPatterns) {
                        if ($content -match $cp.P) {
                            $findings += [PSCustomObject]@{
                                Phase    = "5C-SourceCode"
                                Severity = "MEDIUM"
                                Item     = "$fullId/$($jsFile.Name)"
                                Detail   = $cp.R
                                Reason   = "Extension source accesses sensitive resources"
                            }
                        }
                    }
                } catch { }
            }
        }
    }

    if (-not $foundAny) {
        $findings += [PSCustomObject]@{
            Phase    = "5-VSCode"
            Severity = "INFO"
            Item     = "VS Code"
            Detail   = "No VS Code extension directories found"
            Reason   = "VS Code may not be installed or has no extensions"
        }
    }

    return $findings
}
