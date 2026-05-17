function Scan-ScheduledTasks {
    <#
    .SYNOPSIS
        Phase 2: Scheduled task forensics including hidden task detection.
    .DESCRIPTION
        Enumerates visible tasks for suspicious patterns, detects hidden tasks
        via TaskCache registry manipulation, and correlates Event Log entries.
    #>
    [CmdletBinding()]
    param()

    $findings = [System.Collections.Generic.List[PSObject]]::new()

    # --- 2A: Visible Task Enumeration ---
    Write-Host "  [2A] Enumerating scheduled tasks..." -ForegroundColor Cyan

    $suspiciousTaskPatterns = @("(?i)update.*ledger", "(?i)update.*app", "(?i)node.*sync", "(?i)sync.*node", "(?i)zombi", "(?i)wallet.*update", "(?i)system.*sync", "(?i)chrome.*updat")
    $suspiciousActions = @("node.exe", "powershell.*-enc", "powershell.*-e ", "powershell.*-[wW]indowStyle.*[hH]idden", "wscript", "cscript", "mshta", "AghzgY", "QtCvyfVWKH")
    # Use -like patterns instead of regex to avoid double-escaping issues
    $userWritablePaths = @("*\AppData\*", "*\Temp\*", "*\Downloads\*")

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    } catch {
        $findings.Add([PSCustomObject]@{
            Phase    = "2A-ScheduledTasks"
            Severity = "MEDIUM"
            Item     = "Task Enumeration"
            Detail   = "Failed to enumerate scheduled tasks: $($_.Exception.Message)"
            Reason   = "Could not query task scheduler — may require elevated privileges"
        }) | Out-Null
        return $findings
    }

    foreach ($task in $tasks) {
        $taskName = $task.TaskName
        $taskPath = $task.TaskPath
        $severity = $null
        $reasons = @()

        # Get task actions
        $actions = @()
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
            $actions = $task.Actions
        } catch { }

        foreach ($action in $actions) {
            $exe = $action.Execute
            $actionArgs = $action.Arguments
            $fullAction = "$exe $actionArgs"

            # Check task name against suspicious patterns
            foreach ($pat in $suspiciousTaskPatterns) {
                if ($taskName -match $pat) {
                    $severity = "HIGH"
                    $reasons += "Task name matches GlassWorm pattern: $pat"
                }
            }

            # Check action executable against suspicious patterns
            foreach ($sPat in $suspiciousActions) {
                if ($fullAction -match $sPat) {
                    $severity = if ($severity -eq "CRITICAL") { "CRITICAL" } else { "HIGH" }
                    $reasons += "Action matches suspicious pattern: $sPat"
                }
            }

            # Check if action targets user-writable paths (using -like to avoid regex escaping)
            foreach ($uwp in $userWritablePaths) {
                if ($fullAction -like $uwp) {
                    $sev = if ($severity) { $severity } else { "MEDIUM" }
                    $severity = $sev
                    $reasons += "Action targets user-writable path"
                }
            }

            # Check author — empty or null author is suspicious
            if ([string]::IsNullOrEmpty($task.Author)) {
                $severity = if ($severity) { $severity } else { "MEDIUM" }
                $reasons += "Task has empty Author field"
            }
        }

        if ($severity) {
            $findings.Add([PSCustomObject]@{
                Phase    = "2A-ScheduledTasks"
                Severity = $severity
                Item     = "$taskPath$taskName"
                Detail   = ($actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
                Reason   = $reasons -join " | "
            }) | Out-Null
        }
    }

    if (-not ($findings | Where-Object { $_.Phase -eq "2A-ScheduledTasks" -and $_.Severity -ne "INFO" })) {
        $findings.Add([PSCustomObject]@{
            Phase    = "2A-ScheduledTasks"
            Severity = "INFO"
            Item     = "All Tasks"
            Detail   = "$($tasks.Count) tasks enumerated"
            Reason   = "No suspicious task patterns detected"
        }) | Out-Null
    }

    # --- 2B: Hidden Task Detection ---
    Write-Host "  [2B] Detecting hidden scheduled tasks..." -ForegroundColor Cyan

    $taskCachePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    if (Test-Path $taskCachePath) {
        $registryTasks = @()
        try {
            Get-ChildItem -Path $taskCachePath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $regTask = $_.PSChildName
                $sdValue = Get-ItemProperty -Path $_.PSPath -Name "SD" -ErrorAction SilentlyContinue
                $registryTasks += [PSCustomObject]@{
                    Name   = $regTask
                    Path   = $_.PSPath
                    HasSD  = ($null -ne $sdValue)
                }
            }

            # Find tasks in registry but missing SD (potentially hidden)
            $hiddenTasks = $registryTasks | Where-Object { -not $_.HasSD }
            foreach ($ht in $hiddenTasks) {
                $findings.Add([PSCustomObject]@{
                    Phase    = "2B-HiddenTasks"
                    Severity = "HIGH"
                    Item     = $ht.Name
                    Detail   = $ht.Path
                    Reason   = "Task has NO Security Descriptor (SD) — may be hidden from Task Scheduler"
                }) | Out-Null
            }

            if ($hiddenTasks.Count -eq 0) {
                $findings.Add([PSCustomObject]@{
                    Phase    = "2B-HiddenTasks"
                    Severity = "INFO"
                    Item     = "TaskCache"
                    Detail   = "$($registryTasks.Count) tasks in registry"
                    Reason   = "No hidden tasks detected — all tasks have Security Descriptors"
                }) | Out-Null
            }
        } catch {
            $findings.Add([PSCustomObject]@{
                Phase    = "2B-HiddenTasks"
                Severity = "MEDIUM"
                Item     = "TaskCache"
                Detail   = $_.Exception.Message
                Reason   = "Could not read TaskCache — may require elevated privileges"
            }) | Out-Null
        }
    }

    # --- 2C: Event Log Correlation ---
    Write-Host "  [2C] Checking Event Logs for recent task creation..." -ForegroundColor Cyan

    try {
        $recentTaskEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id      = 4698
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        foreach ($evt in $recentTaskEvents) {
            $xml = [xml]$evt.ToXml()
            $taskContent = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TaskContent' } | Select-Object -ExpandProperty '#text'

            $isSuspicious = $false
            $suspReasons = @()

            if ($taskContent -match "AppData" -or $taskContent -match "\\Temp\\") {
                $isSuspicious = $true
                $suspReasons += "Task targets user-writable directory"
            }
            if ($taskContent -match "node\.exe" -or $taskContent -match "powershell.*-enc") {
                $isSuspicious = $true
                $suspReasons += "Task executes suspicious binary pattern"
            }

            if ($isSuspicious) {
                $findings.Add([PSCustomObject]@{
                    Phase    = "2C-EventLog"
                    Severity = "HIGH"
                    Item     = "Event 4698 at $($evt.TimeCreated)"
                    Detail   = $taskContent.Substring(0, [Math]::Min(200, $taskContent.Length))
                    Reason   = $suspReasons -join " | "
                }) | Out-Null
            }
        }
    } catch {
        $findings.Add([PSCustomObject]@{
            Phase    = "2C-EventLog"
            Severity = "INFO"
            Item     = "Event Log"
            Detail   = "Could not query Security event log (requires elevation or audit policy)"
            Reason   = "Non-critical — event log analysis skipped"
        }) | Out-Null
    }

    return $findings
}
