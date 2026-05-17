function Scan-UnicodePayloads {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$ScanPaths, [int]$MaxFileSizeKB = 2048)
    $findings = @(); $totalScanned = 0; $totalInvis = 0
    $ranges = @(
        @{S=0xFE00;E=0xFE0F;C="VarSel";D="Variation Selectors (GlassWorm primary)"},
        @{S=0xE0100;E=0xE01EF;C="VarSelS";D="Variation Selectors Supplement"},
        @{S=0xE000;E=0xF8FF;C="PUA";D="Private Use Area"},
        @{S=0xF0000;E=0xFFFFF;C="PUA_A";D="Supplementary PUA-A"},
        @{S=0x100000;E=0x10FFFD;C="PUA_B";D="Supplementary PUA-B"},
        @{S=0x200B;E=0x200D;C="ZW";D="Zero-Width Characters"},
        @{S=0xFEFF;E=0xFEFF;C="BOM";D="Zero-Width No-Break Space"},
        @{S=0x202A;E=0x202E;C="BiDi";D="Bidirectional Controls"},
        @{S=0x2066;E=0x2069;C="BiDi";D="BiDi Isolates"}
    )
    $exts = @(".js",".ts",".jsx",".tsx",".json",".html",".mjs",".cjs")
    foreach ($sp in $ScanPaths) {
        if (-not (Test-Path $sp)) { continue }
        Write-Host "  [6] Unicode scan: $sp" -ForegroundColor Cyan
        $files = Get-ChildItem -Path $sp -Recurse -File -EA SilentlyContinue |
            Where-Object { $_.Extension -in $exts -and $_.Length -lt ($MaxFileSizeKB*1024) }
        foreach ($f in $files) {
            $totalScanned++
            try { $content = [IO.File]::ReadAllText($f.FullName, [Text.Encoding]::UTF8) } catch { continue }
            $hits = @(); $ln = 0
            foreach ($line in ($content -split "`n")) {
                $ln++; $chars = $line.ToCharArray()
                for ($i=0; $i -lt $chars.Length; $i++) {
                    $cp = [int]$chars[$i]
                    if ([char]::IsHighSurrogate($chars[$i]) -and ($i+1) -lt $chars.Length -and [char]::IsLowSurrogate($chars[$i+1])) {
                        $cp = [char]::ConvertToUtf32($chars[$i],$chars[$i+1]); $i++
                    }
                    foreach ($r in $ranges) {
                        if ($cp -ge $r.S -and $cp -le $r.E) {
                            if ($cp -eq 0xFEFF -and $ln -eq 1 -and $i -eq 0) { continue }
                            $hits += @{L=$ln;CP="U+$($cp.ToString('X4'))";C=$r.C}; $totalInvis++
                        }
                    }
                }
            }
            if ($hits.Count -gt 0) {
                $sev = if ($hits.Count -gt 50) {"CRITICAL"} elseif ($hits.Count -gt 10) {"HIGH"} else {"MEDIUM"}
                $hasVS = ($hits | Where-Object {$_.C -match "VarSel"}).Count -gt 0
                $hasPUA = ($hits | Where-Object {$_.C -match "PUA"}).Count -gt 0
                if ($hasVS -or $hasPUA) { $sev = "CRITICAL" }
                $catSum = $hits | Group-Object {$_.C} | ForEach-Object {"$($_.Name):$($_.Count)"}
                $reason = if ($hasVS) {"GLASSWORM SIGNATURE: Variation selectors — primary code hiding"} `
                    elseif ($hasPUA) {"GLASSWORM INDICATOR: PUA characters — hidden executable code"} `
                    else {"Suspicious invisible characters — review needed"}
                $findings += [PSCustomObject]@{Phase="6-Unicode";Severity=$sev;Item=$f.FullName;Detail="$($hits.Count) invisible chars | $($catSum -join ', ')";Reason=$reason}
            }
        }
    }
    $findings += [PSCustomObject]@{Phase="6-Unicode";Severity="INFO";Item="Summary";Detail="$totalScanned files, $totalInvis chars";Reason="Unicode scan complete"}
    return $findings
}
