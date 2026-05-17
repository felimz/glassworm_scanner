# GlassWorm Backdoor Detection Scanner

A PowerShell-based threat detection toolkit that scans Windows systems for indicators of **GlassWorm** backdoor compromise — a self-propagating supply-chain worm targeting developer environments through trojanized VS Code extensions.

## What is GlassWorm?

GlassWorm (first documented October 2025) is a sophisticated malware campaign that:

- **Infects** developers through compromised VS Code / OpenVSX extensions and npm/PyPI packages
- **Hides** malicious JavaScript using invisible Unicode characters (variation selectors, PUA chars)
- **Resolves C2** via Solana blockchain transaction memos and Google Calendar event titles
- **Persists** through Windows Registry Run keys, scheduled tasks, and fake Chrome extensions
- **Deploys** a ZOMBI RAT with SOCKS proxy, HVNC, and cryptocurrency wallet theft capabilities
- **Propagates** by stealing npm/GitHub tokens and injecting itself into the victim's own packages

## Quick Start

```powershell
# Clone the repo
git clone https://github.com/felimz/glassworm_scanner.git
cd glassworm_scanner

# Basic scan (fast, skips deep Unicode analysis)
pwsh -ExecutionPolicy Bypass -File .\Scan-GlassWorm.ps1 -SkipUnicode

# Full scan with HTML report
pwsh -ExecutionPolicy Bypass -File .\Scan-GlassWorm.ps1 -HTMLReport

# Full scan as Administrator (enables hidden task detection + event logs)
Start-Process pwsh -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File .\Scan-GlassWorm.ps1 -HTMLReport'
```

## Scan Phases

| Phase | Module | What It Scans |
|-------|--------|---------------|
| 1 | Registry Audit | Run/RunOnce keys, Chrome extension force-install policies, browser shortcut hijacking |
| 2 | Scheduled Task Forensics | Visible task enumeration, hidden task detection (via TaskCache SD removal), Event ID 4698 correlation |
| 3 | Chrome Extension Forensics | Manifest permission analysis, fake "Google Docs Offline" detection, JS content scanning for C2 IOCs |
| 4 | Antigravity IDE Audit | MCP config integrity, implicit data store anomalies, extension verification *(optional, auto-skipped if not installed)* |
| 5 | VS Code Extension Audit | Known-bad extension matching (14+ confirmed IOCs), dependency chain poisoning, source code analysis |
| 6 | Invisible Unicode Scanner | Variation selectors, PUA characters, zero-width chars, BiDi controls in JS/TS/JSON files *(optional, use `-SkipUnicode` to skip)* |
| 7 | Network IOC Correlation | Active connections to known C2 IPs, SOCKS proxy listener detection, DNS cache analysis for Solana RPC domains |
| 8 | Credential Exposure | Token file presence/modification (npm, SSH, Git), environment variable exposure, crypto wallet software detection |

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SkipUnicode` | Switch | `$false` | Skip Phase 6 (Unicode payload scan). Faster but less thorough. |
| `-SkipAntigravity` | Switch | `$false` | Skip Phase 4 (Antigravity IDE audit). Use if Antigravity is not installed. |
| `-HTMLReport` | Switch | `$false` | Generate an HTML report in the `reports/` directory. |
| `-AntigravityDir` | String | `~\.gemini\antigravity` | Custom path to Antigravity data directory. |

## Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| **CRITICAL** | Direct GlassWorm IOC match | Known-bad extension installed, C2 IP connection active, attacker Solana wallet in code |
| **HIGH** | Strong behavioral indicator | Unsigned binary in Run key from AppData, suspicious node.exe outbound connection |
| **MEDIUM** | Suspicious but potentially benign | Unrecognized Run key entry, recently modified SSH key |
| **INFO** | Baseline inventory | Extension list, credential file presence, task count |

## Known IOCs Included

- **14 confirmed compromised VS Code extensions** with specific version numbers
- **6 known C2/exfiltration IP addresses**
- **Solana wallet address** used for C2 resolution (`28PKnu7R...`)
- **Google Calendar URL** used as fallback C2 dead drop
- **Registry value patterns** (e.g., `UpdateLedger` masquerading as Ledger Live)

## Requirements

- **Windows 10/11**
- **PowerShell 7+** (pwsh) — recommended for full compatibility
- **Optional:** Run as Administrator for hidden task detection and event log analysis

## Output

- **Console:** Color-coded severity summary with detailed findings
- **CSV:** Always exported to `reports/glassworm_scan_YYYY-MM-DD_HHMMSS.csv`
- **HTML:** Dark-themed report with `-HTMLReport` flag (see `reports/` directory)

> **Note:** Reports contain sensitive system information (registry entries, extension lists, credential file paths). The `reports/` directory is excluded from git via `.gitignore`.

## Project Structure

```
glassworm_scanner/
├── Scan-GlassWorm.ps1              # Main orchestrator
├── modules/
│   ├── Scan-Registry.ps1            # Phase 1: Registry analysis
│   ├── Scan-ScheduledTasks.ps1      # Phase 2: Task scheduler forensics
│   ├── Scan-ChromeExtensions.ps1    # Phase 3: Chrome extension audit
│   ├── Scan-AntigravityExtensions.ps1 # Phase 4: Antigravity IDE audit
│   ├── Scan-VSCodeExtensions.ps1    # Phase 5: VS Code extension audit
│   ├── Scan-UnicodePayloads.ps1     # Phase 6: Invisible character scan
│   ├── Scan-NetworkIOCs.ps1         # Phase 7: Network IOC correlation
│   └── Scan-CredentialExposure.ps1  # Phase 8: Credential exposure check
├── data/
│   ├── known_bad_extensions.json    # Compromised extension IDs + versions
│   ├── known_c2_ips.json            # C2/exfil IPs, Solana wallet, Calendar URL
│   └── suspicious_registry_values.json # Registry patterns + allowlist
├── reports/                         # Generated reports (gitignored)
├── README.md
├── LICENSE
└── .gitignore
```

## Disclaimer

This tool is for **defensive security purposes only**. It detects indicators of compromise based on publicly available threat intelligence. False positives are possible — always verify findings before taking remediation action. If you suspect active compromise, isolate the system and rotate all credentials immediately.

## License

MIT
