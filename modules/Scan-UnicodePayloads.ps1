function Scan-UnicodePayloads {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$ScanPaths, [int]$MaxFileSizeKB = 2048)
    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $totalScanned = 0; $totalInvis = 0
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

    # Locales that legitimately use ZWJ/ZWNJ for correct text rendering
    $zwjLocales = @('ar','bn','fa','gu','he','hi','kn','ml','mr','or','pa','si','ta','te','ur',
                     'pt_BR','pt_PT','de','deu')

    # Cache for resolving Chrome extension IDs to human-readable names
    $extNameCache = @{}

    $exts = @(".js",".ts",".jsx",".tsx",".json",".html",".mjs",".cjs")
    foreach ($sp in $ScanPaths) {
        if (-not (Test-Path $sp)) { continue }
        Write-Host "  [6] Unicode scan: $sp" -ForegroundColor Cyan

        # Pre-populate extension name cache from manifest.json files in this scan path
        Get-ChildItem -Path $sp -Filter "manifest.json" -Recurse -Depth 2 -EA SilentlyContinue | ForEach-Object {
            try {
                $m = Get-Content $_.FullName -Raw -EA Stop | ConvertFrom-Json
                if ($m.name) {
                    $versionDir = $_.Directory.FullName
                    $extIdDir = Split-Path (Split-Path $versionDir -Parent) -Leaf
                    if ($extIdDir -and $extIdDir.Length -ge 20) {
                        $displayName = $m.name
                        # Resolve __MSG_*__ i18n placeholders from _locales/en/messages.json
                        if ($displayName -match '^__MSG_(\w+)__$') {
                            $msgKey = $Matches[1]
                            $localePath = Join-Path $versionDir "_locales\en\messages.json"
                            if (Test-Path $localePath) {
                                try {
                                    $msgs = Get-Content $localePath -Raw -EA Stop | ConvertFrom-Json
                                    $resolved = $msgs.$msgKey.message
                                    if (-not $resolved) {
                                        # Try case-insensitive match
                                        $resolvedProp = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $msgKey } | Select-Object -First 1
                                        if ($resolvedProp) { $resolved = $resolvedProp.Value.message }
                                    }
                                    if ($resolved) { $displayName = $resolved }
                                } catch { }
                            }
                        }
                        $extNameCache[$extIdDir] = $displayName
                    }
                }
            } catch { }
        }

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
                # --- Context-aware severity classification ---
                $isLocaleFile = $f.FullName -match '[/\\]_locales[/\\](\w+)[/\\]'
                $localeCode = if ($isLocaleFile) { $Matches[1] } else { $null }
                $isFilterList = $f.FullName -match '[/\\]rulesets[/\\]'
                $isCodeMirror = $f.FullName -match '(?i)codemirror'

                # Wrap in @() to force array context — single-item pipelines lack .Count in PS 5.1
                $vsCount = @($hits | Where-Object {$_.C -match "VarSel"}).Count
                $puaCount = @($hits | Where-Object {$_.C -match "PUA"}).Count
                $zwBidiCount = @($hits | Where-Object {$_.C -in @('ZW','BOM','BiDi')}).Count
                $hasVS = $vsCount -gt 0
                $hasPUA = $puaCount -gt 0
                $zwBidiOnly = ($vsCount + $puaCount) -eq 0
                $nonVsCount = $hits.Count - $vsCount

                $catSum = $hits | Group-Object {$_.C} | ForEach-Object {"$($_.Name):$($_.Count)"}

                # Default severity by count
                $sev = if ($hits.Count -gt 50) {"CRITICAL"} elseif ($hits.Count -gt 10) {"HIGH"} else {"MEDIUM"}

                # Context-based exemptions — check BEFORE VarSel/PUA escalation
                # These contexts legitimately contain both ZW chars and variation selectors
                if ($isLocaleFile -and $localeCode -in $zwjLocales) {
                    # Locale files for Indic/Arabic/Persian scripts — ZWJ/ZWNJ and VarSel are expected
                    $sev = "INFO"
                    $reason = "Zero-width chars expected in '$localeCode' locale (Indic/Arabic/Persian script ligatures)"
                } elseif ($isFilterList) {
                    # Ad-blocker filter rules — may contain ZW chars and VarSel in CSS selectors targeting page content
                    $sev = "INFO"
                    $reason = "Invisible chars in ad-blocker filter rules — filter patterns targeting page content, not payloads"
                } elseif ($isCodeMirror) {
                    # CodeMirror text editor bundles include BiDi controls + VarSel for Unicode rendering
                    $sev = "INFO"
                    $reason = "Invisible chars in CodeMirror text editor bundle — expected for full Unicode/RTL support"
                } elseif ($hasVS -and $vsCount -ge 3) {
                    # Multiple variation selectors in executable code — strong GlassWorm signal
                    $sev = "CRITICAL"
                    $reason = "GLASSWORM SIGNATURE: Multiple variation selectors ($vsCount) — primary code hiding technique"
                } elseif ($hasVS -and $vsCount -lt 3) {
                    # 1-2 variation selectors — likely emoji presentation selectors (e.g., ⚙️ vs ⚙)
                    $sev = "LOW"
                    $reason = "Low-count variation selectors ($vsCount) — likely emoji presentation, verify manually"
                } elseif ($hasPUA -and $puaCount -ge 3) {
                    # Multiple PUA chars in code — suspicious
                    $sev = "HIGH"
                    $reason = "GLASSWORM INDICATOR: Multiple PUA characters ($puaCount) — possible hidden executable code"
                } elseif ($hasPUA -and $puaCount -lt 3) {
                    # 1-2 PUA chars — likely icon font glyphs (Font Awesome, Material Icons)
                    $sev = "LOW"
                    $reason = "Low-count PUA characters ($puaCount) — likely icon font glyphs, verify manually"
                } else {
                    $reason = "Suspicious invisible characters — review needed"
                }

                # Build a friendly display name: [Extension Name] relative/path.js
                $displayItem = $f.FullName
                if ($f.FullName -match '[/\\]Extensions[/\\]([a-z]{20,})[/\\][^/\\]+[/\\](.+)$') {
                    $extId = $Matches[1]
                    $relPath = $Matches[2]
                    $extName = $extNameCache[$extId]
                    if ($extName) {
                        $displayItem = "[$extName] $relPath"
                    } else {
                        $displayItem = "[$extId] $relPath"
                    }
                }

                $findings.Add([PSCustomObject]@{Phase="6-Unicode";Severity=$sev;Item=$displayItem;Detail="$($hits.Count) invisible chars | $($catSum -join ', ')";Reason=$reason}) | Out-Null
            }
        }
    }
    $findings.Add([PSCustomObject]@{Phase="6-Unicode";Severity="INFO";Item="Summary";Detail="$totalScanned files, $totalInvis chars";Reason="Unicode scan complete"}) | Out-Null
    return $findings
}
