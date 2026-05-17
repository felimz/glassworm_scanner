<#
.SYNOPSIS
    GlassWorm Backdoor Detection Scanner v1.0
.DESCRIPTION
    Scans a Windows system for indicators of GlassWorm backdoor compromise
    across registry, browser extensions, VS Code extensions, scheduled tasks,
    network connections, and credential files.

    GlassWorm is a self-propagating supply-chain worm (first seen Oct 2025)
    that infects developers through trojanized VS Code/OpenVSX extensions
    using invisible Unicode characters to hide malicious JavaScript.

    For full hidden-task detection and event log analysis, run as Administrator.
.PARAMETER SkipUnicode
    Skip the invisible Unicode payload scan (Phase 6). Faster but less thorough.
.PARAMETER SkipAntigravity
    Skip the Antigravity IDE extension audit (Phase 4). Use if Antigravity is not installed.
.PARAMETER HTMLReport
    Generate an HTML report in the reports/ directory.
.PARAMETER AntigravityDir
    Custom path to Antigravity data directory. Defaults to $env:USERPROFILE\.gemini\antigravity
.EXAMPLE
    .\Scan-GlassWorm.ps1 -HTMLReport
    # Full scan with HTML report

    .\Scan-GlassWorm.ps1 -SkipUnicode -SkipAntigravity
    # Quick scan, no Unicode deep scan, no Antigravity checks

    # For full scan (hidden tasks + event logs), run as Administrator:
    Start-Process pwsh -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File .\Scan-GlassWorm.ps1 -HTMLReport'
.LINK
    https://github.com/felimz/glassworm_scanner
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipUnicode,
    [switch]$SkipAntigravity,
    [switch]$HTMLReport,
    [string]$AntigravityDir = "$env:USERPROFILE\.gemini\antigravity"
)

$ErrorActionPreference = "Continue"
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) {
    Write-Error "This script must be run as a file, not pasted into a console. Use: pwsh -File .\Scan-GlassWorm.ps1"
    exit 1
}
$dataDir    = Join-Path $scriptRoot "data"
$modulesDir = Join-Path $scriptRoot "modules"
$reportsDir = Join-Path $scriptRoot "reports"

# Ensure reports directory
New-Item -ItemType Directory -Path $reportsDir -Force -ErrorAction SilentlyContinue | Out-Null

# --- Detect privileges ---
$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

# --- Version Check ---
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "GlassWorm Scanner is designed for PowerShell 7+. Some phases may produce inaccurate results on Windows PowerShell 5.1."
}

# --- Banner ---
Write-Host ""
Write-Host "  ======================================================" -ForegroundColor Red
Write-Host "       GLASSWORM BACKDOOR DETECTION SCANNER v1.0" -ForegroundColor Red
Write-Host "    Threat Intel-Driven  |  8-Phase Deep Scan" -ForegroundColor Red
Write-Host "  ======================================================" -ForegroundColor Red
Write-Host ""
Write-Host "  Target:  $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "  User:    $env:USERNAME" -ForegroundColor Yellow
Write-Host "  Time:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "  Admin:   $isAdmin" -ForegroundColor $(if ($isAdmin) {"Green"} else {"DarkYellow"})
if (-not $isAdmin) {
    Write-Host "  NOTE:    Run as Administrator for full hidden-task and event log analysis" -ForegroundColor DarkYellow
}
Write-Host ""

# --- Load Modules ---
Write-Host "Loading detection modules..." -ForegroundColor White
Get-ChildItem "$modulesDir\*.ps1" | ForEach-Object {
    . $_.FullName
    Write-Host "    Loaded: $($_.Name)" -ForegroundColor DarkGray
}

$allFindings = [System.Collections.ArrayList]@()

# Helper to accumulate phase results
function Add-PhaseResults {
    param($Results)
    if ($Results) {
        $Results | ForEach-Object { [void]$allFindings.Add($_) }
    }
}

# === PHASE 1: Registry ===
Write-Host "`nPhase 1: REGISTRY AUDIT" -ForegroundColor Magenta
Write-Host ("=" * 50) -ForegroundColor DarkGray
Add-PhaseResults (Scan-Registry -DataDir $dataDir)

# === PHASE 2: Scheduled Tasks ===
Write-Host "`nPhase 2: SCHEDULED TASK FORENSICS" -ForegroundColor Magenta
Write-Host ("=" * 50) -ForegroundColor DarkGray
Add-PhaseResults (Scan-ScheduledTasks)

# === PHASE 3: Chrome Extensions ===
Write-Host "`nPhase 3: CHROME EXTENSION FORENSICS" -ForegroundColor Magenta
Write-Host ("=" * 50) -ForegroundColor DarkGray
Add-PhaseResults (Scan-ChromeExtensions -DataDir $dataDir)

# === PHASE 4: Antigravity IDE Extensions (optional) ===
if (-not $SkipAntigravity) {
    if (Test-Path $AntigravityDir) {
        Write-Host "`nPhase 4: ANTIGRAVITY IDE EXTENSION AUDIT" -ForegroundColor Magenta
        Write-Host ("=" * 50) -ForegroundColor DarkGray
        Add-PhaseResults (Scan-AntigravityExtensions -AntigravityDir $AntigravityDir)
    } else {
        Write-Host "`nPhase 4: SKIPPED - Antigravity not found at $AntigravityDir" -ForegroundColor DarkGray
    }
} else {
    Write-Host "`nPhase 4: SKIPPED (-SkipAntigravity)" -ForegroundColor DarkGray
}

# === PHASE 5: VS Code Extensions ===
Write-Host "`nPhase 5: VS CODE EXTENSION AUDIT" -ForegroundColor Magenta
Write-Host ("=" * 50) -ForegroundColor DarkGray
Add-PhaseResults (Scan-VSCodeExtensions -DataDir $dataDir)

# === PHASE 6: Unicode Payloads (optional) ===
if (-not $SkipUnicode) {
    Write-Host "`nPhase 6: INVISIBLE UNICODE PAYLOAD SCAN" -ForegroundColor Magenta
    Write-Host ("=" * 50) -ForegroundColor DarkGray
    $unicodePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:USERPROFILE\.vscode\extensions"
    )
    # Include Antigravity dir if it exists and not skipped
    if (-not $SkipAntigravity -and (Test-Path $AntigravityDir)) {
        $unicodePaths += $AntigravityDir
    }
    # Filter to only existing paths
    $unicodePaths = $unicodePaths | Where-Object { Test-Path $_ }
    if ($unicodePaths.Count -gt 0) {
        Add-PhaseResults (Scan-UnicodePayloads -ScanPaths $unicodePaths)
    } else {
        Write-Host "  No scannable directories found" -ForegroundColor DarkGray
    }
} else {
    Write-Host "`nPhase 6: SKIPPED (-SkipUnicode)" -ForegroundColor DarkGray
}

# === PHASE 7: Network IOCs ===
Write-Host "`nPhase 7: NETWORK IOC CORRELATION" -ForegroundColor Magenta
Write-Host ("=" * 50) -ForegroundColor DarkGray
Add-PhaseResults (Scan-NetworkIOCs -DataDir $dataDir)

# === PHASE 8: Credential Exposure ===
Write-Host "`nPhase 8: CREDENTIAL EXPOSURE ASSESSMENT" -ForegroundColor Magenta
Write-Host ("=" * 50) -ForegroundColor DarkGray
Add-PhaseResults (Scan-CredentialExposure)

# === RESULTS SUMMARY ===
Write-Host ""
Write-Host "  ======================================================" -ForegroundColor White
Write-Host "                     SCAN RESULTS" -ForegroundColor White
Write-Host "  ======================================================" -ForegroundColor White

$critical = @($allFindings | Where-Object { $_.Severity -eq "CRITICAL" })
$high     = @($allFindings | Where-Object { $_.Severity -eq "HIGH" })
$medium   = @($allFindings | Where-Object { $_.Severity -eq "MEDIUM" })
$info     = @($allFindings | Where-Object { $_.Severity -eq "INFO" })

$statusColor = "Green"
$statusText  = "CLEAN - No GlassWorm indicators detected"
if ($medium.Count -gt 0) { $statusColor = "Yellow"; $statusText = "REVIEW - Some items need manual verification" }
if ($high.Count -gt 0)   { $statusColor = "DarkYellow"; $statusText = "SUSPICIOUS - High-severity indicators found" }
if ($critical.Count -gt 0) { $statusColor = "Red"; $statusText = "COMPROMISED - Critical GlassWorm indicators detected!" }

Write-Host ""
Write-Host "  STATUS: $statusText" -ForegroundColor $statusColor
Write-Host ""
Write-Host "  CRITICAL : $($critical.Count)" -ForegroundColor $(if ($critical.Count) {"Red"} else {"DarkGray"})
Write-Host "  HIGH     : $($high.Count)" -ForegroundColor $(if ($high.Count) {"DarkYellow"} else {"DarkGray"})
Write-Host "  MEDIUM   : $($medium.Count)" -ForegroundColor $(if ($medium.Count) {"Yellow"} else {"DarkGray"})
Write-Host "  INFO     : $($info.Count)" -ForegroundColor DarkGray

# Show non-INFO findings
if ($critical.Count + $high.Count + $medium.Count -gt 0) {
    Write-Host "`n  -- Findings Detail --" -ForegroundColor White
    foreach ($f in ($critical + $high + $medium)) {
        $sColor = switch ($f.Severity) { "CRITICAL" {"Red"} "HIGH" {"DarkYellow"} "MEDIUM" {"Yellow"} }
        Write-Host ""
        Write-Host "  $($f.Severity) | $($f.Phase)" -ForegroundColor $sColor
        Write-Host "    Item:   $($f.Item)" -ForegroundColor White
        Write-Host "    Detail: $($f.Detail)" -ForegroundColor Gray
        Write-Host "    Reason: $($f.Reason)" -ForegroundColor $sColor
    }
}

# --- Shared report timestamp ---
$reportTimestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

# --- HTML Report ---
if ($HTMLReport) {
    $reportPath = Join-Path $reportsDir "glassworm_scan_$reportTimestamp.html"

    # Escape HTML in cell content
    function ConvertTo-EscapedHtml { param([string]$s) return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;') }

    $rows = $allFindings | ForEach-Object {
        $bgColor = switch ($_.Severity) {
            "CRITICAL" { "#ff4444" } "HIGH" { "#ff8800" } "MEDIUM" { "#ffcc00" } default { "#333" }
        }
        $textColor = if ($_.Severity -in @("MEDIUM")) { "#000" } else { "#fff" }
        "<tr style='background:$bgColor;color:$textColor'><td>$(ConvertTo-EscapedHtml $_.Severity)</td><td>$(ConvertTo-EscapedHtml $_.Phase)</td><td>$(ConvertTo-EscapedHtml $_.Item)</td><td>$(ConvertTo-EscapedHtml $_.Detail)</td><td>$(ConvertTo-EscapedHtml $_.Reason)</td></tr>"
    }

    $adminNote = if ($isAdmin) { "Yes (full scan)" } else { "No (limited - run as Admin for full scan)" }

    $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>GlassWorm Scan Report - $env:COMPUTERNAME</title>
<style>
body{background:#111;color:#eee;font-family:'Segoe UI',Arial,sans-serif;padding:2em;max-width:1400px;margin:0 auto}
h1{color:#ff4444;margin-bottom:0.2em}
h2{margin-top:0.5em}
table{width:100%;border-collapse:collapse;margin:1em 0}
th{background:#222;padding:10px;text-align:left;border-bottom:2px solid #444;position:sticky;top:0}
td{padding:8px 10px;border-bottom:1px solid #333;word-break:break-word;max-width:450px;vertical-align:top}
tr:hover td{opacity:0.9}
.meta{color:#888;font-size:0.9em;margin:0.5em 0}
.status-clean{color:#44ff44}.status-warn{color:#ffcc00}.status-bad{color:#ff4444}
.counts{font-size:1.1em;margin:0.5em 0}
.counts span{margin-right:1.5em}
footer{margin-top:2em;padding-top:1em;border-top:1px solid #333;color:#666;font-size:0.85em}
</style></head><body>
<h1>GlassWorm Backdoor Scan Report</h1>
<p class="meta">Host: <strong>$env:COMPUTERNAME</strong> | User: <strong>$env:USERNAME</strong> | Admin: <strong>$adminNote</strong> | Time: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></p>
<h2 class="status-$(if($critical.Count){'bad'}elseif($high.Count){'warn'}else{'clean'})">$statusText</h2>
<p class="counts"><span>CRITICAL: $($critical.Count)</span><span>HIGH: $($high.Count)</span><span>MEDIUM: $($medium.Count)</span><span>INFO: $($info.Count)</span></p>
<table><tr><th>Severity</th><th>Phase</th><th>Item</th><th>Detail</th><th>Reason</th></tr>
$($rows -join "`n")
</table>
<footer>Generated by GlassWorm Scanner v1.0 | github.com/felimz/glassworm_scanner</footer>
</body></html>
"@
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "`n  HTML Report: $reportPath" -ForegroundColor Cyan
}

# --- CSV Export (always) ---
$csvPath = Join-Path $reportsDir "glassworm_scan_$reportTimestamp.csv"
if ($allFindings.Count -gt 0) {
    $allFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV Export: $csvPath" -ForegroundColor Cyan
} else {
    Write-Host "  CSV Export: (no findings to export)" -ForegroundColor DarkGray
}
Write-Host ""

# Return findings for pipeline use
return $allFindings
