function Scan-CredentialExposure {
    <#
    .SYNOPSIS
        Phase 8: Credential exposure assessment — token files, sensitive env vars.
    #>
    [CmdletBinding()]
    param()

    $findings = [System.Collections.Generic.List[PSObject]]::new()

    # --- 8A: Sensitive File Check ---
    Write-Host "  [8A] Checking credential file exposure..." -ForegroundColor Cyan

    $credFiles = @(
        @{Path="$env:USERPROFILE\.npmrc"; Name="npm config/tokens"},
        @{Path="$env:USERPROFILE\.gitconfig"; Name="Git configuration"},
        @{Path="$env:USERPROFILE\.git-credentials"; Name="Git stored credentials"},
        @{Path="$env:USERPROFILE\.ssh\id_rsa"; Name="SSH private key (RSA)"},
        @{Path="$env:USERPROFILE\.ssh\id_ed25519"; Name="SSH private key (Ed25519)"},
        @{Path="$env:USERPROFILE\.ssh\id_ecdsa"; Name="SSH private key (ECDSA)"},
        @{Path="$env:APPDATA\Ledger Live"; Name="Ledger Live wallet data"; IsDir=$true},
        @{Path="$env:APPDATA\@aspect-build"; Name="Aspect build npm cache"; IsDir=$true},
        @{Path="$env:APPDATA\Code\User\globalStorage"; Name="VS Code global storage/secrets"; IsDir=$true}
    )

    foreach ($cf in $credFiles) {
        $exists = Test-Path $cf.Path -ErrorAction SilentlyContinue
        if ($exists) {
            $item = Get-Item $cf.Path -ErrorAction SilentlyContinue
            $modTime = $item.LastWriteTime
            $daysSinceModified = ((Get-Date) - $modTime).Days

            $severity = "INFO"
            $reason = "Credential file present — potential GlassWorm target"

            # Flag if recently modified (could indicate harvesting)
            if ($daysSinceModified -lt 7) {
                $severity = "MEDIUM"
                $reason = "Credential file modified in last 7 days — verify no unauthorized access"
            }

            $findings.Add([PSCustomObject]@{
                Phase="8A-CredFiles"; Severity=$severity
                Item=$cf.Name; Detail="Path: $($cf.Path) | Last Modified: $modTime ($daysSinceModified days ago)"
                Reason=$reason
            }) | Out-Null
        }
    }

    # --- 8B: Process Environment Variable Check ---
    Write-Host "  [8B] Scanning process environment for exposed tokens..." -ForegroundColor Cyan

    $sensitiveVars = @("NPM_TOKEN","GITHUB_TOKEN","GH_TOKEN","OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY","AZURE_CLIENT_SECRET","GOOGLE_APPLICATION_CREDENTIALS",
        "DISCORD_TOKEN","SLACK_TOKEN","ANTHROPIC_API_KEY")

    # Check current session env
    foreach ($sv in $sensitiveVars) {
        $val = [Environment]::GetEnvironmentVariable($sv)
        if ($val) {
            $masked = $val.Substring(0, [Math]::Min(4, $val.Length)) + "****"
            $findings.Add([PSCustomObject]@{
                Phase="8B-EnvVars"; Severity="MEDIUM"
                Item=$sv; Detail="Value present (masked): $masked"
                Reason="Sensitive token in environment — GlassWorm harvests these"
            }) | Out-Null
        }
    }

    # Check for crypto wallet processes that GlassWorm targets
    Write-Host "  [8C] Checking for targeted crypto wallet software..." -ForegroundColor Cyan
    $walletProcesses = @("Ledger Live","Trezor Suite","Exodus","Electrum","Atomic")
    $runningProcs = Get-Process -ErrorAction SilentlyContinue
    foreach ($wp in $walletProcesses) {
        $match = $runningProcs | Where-Object { $_.ProcessName -match $wp -or $_.MainWindowTitle -match $wp }
        if ($match) {
            $findings.Add([PSCustomObject]@{
                Phase="8C-CryptoWallets"; Severity="INFO"
                Item=$wp; Detail="Running process: $($match.ProcessName)"
                Reason="Crypto wallet software running — GlassWorm targets 49+ wallet types"
            }) | Out-Null
        }
    }

    return $findings
}
