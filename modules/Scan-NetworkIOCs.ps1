function Scan-NetworkIOCs {
    <#
    .SYNOPSIS
        Phase 7: Network IOC correlation — active connections, DNS cache, known C2 IPs.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DataDir)

    $findings = [System.Collections.Generic.List[PSObject]]::new()
    try {
        $c2Data = Get-Content "$DataDir\known_c2_ips.json" -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        Write-Host "  ERROR: Failed to load $DataDir\known_c2_ips.json — $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
    $allIPs = @()
    $c2Data.c2_servers | ForEach-Object { $allIPs += $_.ip }
    $c2Data.exfiltration | ForEach-Object { $allIPs += $_.ip }
    $c2Data.phishing | ForEach-Object { $allIPs += $_.ip }

    # --- 7A: Active TCP Connections ---
    Write-Host "  [7A] Checking active connections against C2 IPs..." -ForegroundColor Cyan
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            $remoteIP = $conn.RemoteAddress
            if ($remoteIP -in $allIPs) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $findings.Add([PSCustomObject]@{
                    Phase="7A-ActiveConn"; Severity="CRITICAL"
                    Item="$remoteIP`:$($conn.RemotePort)"
                    Detail="Process: $($proc.ProcessName) (PID $($conn.OwningProcess)) | State: $($conn.State)"
                    Reason="GLASSWORM ACTIVE: Connection to known C2/exfil IP"
                }) | Out-Null
            }
        }

        # Check for suspicious listening ports from user-space processes
        # Allowlist known-good applications that legitimately listen from AppData
        $knownGoodListeners = @(
            "Antigravity", "language_server_windows_x64",
            "Discord", "Spotify", "Slack", "Teams",
            "chrome", "msedge", "brave", "Code",
            "OneDrive", "GitHubDesktop", "1Password"
        )
        $listeners = $connections | Where-Object { $_.State -eq "Listen" -and $_.LocalPort -gt 1024 }
        foreach ($l in $listeners) {
            $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.Path -and $proc.Path -match "AppData|Temp") {
                $isKnownGood = $knownGoodListeners | Where-Object { $proc.ProcessName -match $_ }
                if (-not $isKnownGood) {
                    $findings.Add([PSCustomObject]@{
                        Phase="7A-ActiveConn"; Severity="HIGH"
                        Item="Listening :$($l.LocalPort)"
                        Detail="Process: $($proc.ProcessName) at $($proc.Path)"
                        Reason="User-space process listening on port - possible SOCKS proxy or RAT"
                    }) | Out-Null
                }
            }
        }

        # Check for node.exe with unexpected outbound connections
        # Exclude localhost connections and known dev tools (playwright, electron, nvm)
        $knownNodePaths = @("playwright", "electron", "nvm", "Antigravity")
        $nodeConns = $connections | Where-Object { $_.State -eq "Established" } | ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($p -and $p.ProcessName -eq "node" -and $p.Path -match "AppData") {
                [PSCustomObject]@{Conn=$_; Proc=$p}
            }
        } | Where-Object { $_ }
        foreach ($nc in $nodeConns) {
            $remoteAddr = $nc.Conn.RemoteAddress
            # Skip localhost connections
            if ($remoteAddr -in @("127.0.0.1", "::1", "0.0.0.0")) { continue }
            # Skip known dev tool paths
            $isKnownNode = $knownNodePaths | Where-Object { $nc.Proc.Path -match $_ }
            if ($isKnownNode) { continue }

            $findings.Add([PSCustomObject]@{
                Phase="7A-ActiveConn"; Severity="HIGH"
                Item="node.exe -> $($remoteAddr):$($nc.Conn.RemotePort)"
                Detail="Path: $($nc.Proc.Path) | Remote: $($remoteAddr):$($nc.Conn.RemotePort)"
                Reason="Node.js from AppData making outbound connection - possible ZOMBI RAT"
            }) | Out-Null
        }
    } catch {
        $findings.Add([PSCustomObject]@{
            Phase="7A-ActiveConn"; Severity="INFO"; Item="NetTCP"
            Detail="Could not query connections: $($_.Exception.Message)"
            Reason="May require elevation"
        }) | Out-Null
    }

    if (-not ($findings | Where-Object { $_.Phase -eq "7A-ActiveConn" -and $_.Severity -ne "INFO" })) {
        $findings.Add([PSCustomObject]@{
            Phase="7A-ActiveConn"; Severity="INFO"; Item="Active Connections"
            Detail="No connections to known C2 IPs detected"
            Reason="Network connections clean"
        }) | Out-Null
    }

    # --- 7B: DNS Cache ---
    Write-Host "  [7B] Analyzing DNS cache..." -ForegroundColor Cyan
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($entry in $dnsCache) {
            # Check for Solana RPC domains
            foreach ($rpc in $c2Data.solana.rpc_domains) {
                if ($entry.Entry -match [regex]::Escape($rpc)) {
                    $findings.Add([PSCustomObject]@{
                        Phase="7B-DNS"; Severity="HIGH"
                        Item=$entry.Entry; Detail="Type: $($entry.Type) | Data: $($entry.Data)"
                        Reason="Solana RPC domain in DNS cache — possible blockchain C2 resolution"
                    }) | Out-Null
                }
            }
            # Check for C2 IPs in DNS resolution
            foreach ($ip in $allIPs) {
                if ($entry.Data -eq $ip) {
                    $findings.Add([PSCustomObject]@{
                        Phase="7B-DNS"; Severity="CRITICAL"
                        Item=$entry.Entry; Detail="Resolved to known C2 IP: $ip"
                        Reason="GLASSWORM: DNS cache contains resolution to known C2 IP"
                    }) | Out-Null
                }
            }
        }
    } catch {
        $findings.Add([PSCustomObject]@{
            Phase="7B-DNS"; Severity="INFO"; Item="DNS Cache"
            Detail="Could not query DNS cache"; Reason="Non-critical"
        }) | Out-Null
    }

    return $findings
}
