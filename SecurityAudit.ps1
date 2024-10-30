# Advanced System Security Audit Script
# This script performs comprehensive system security auditing and exports results to JSON
# Runs with minimal permissions

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "$env:USERPROFILE\SecurityAudit"
)

# Function to safely check WMI objects
function Get-SafeWmiObject {
    param (
        [string]$Class,
        [string]$Namespace = "root\cimv2"
    )
    try {
        return Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Start-SecurityAudit {
    $auditResults = @{
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        hostname = $env:COMPUTERNAME
        categories = @()
        summary = @{
            criticalIssues = 0
            warnings = 0
            passedChecks = 0
            totalChecks = 0
        }
    }

    # Collect all audit data
    $categories = @(
        Get-SystemInformation
        Get-SecuritySettings
        Get-NetworkSecurity
        Get-UpdateStatus
        Get-UserSecurity
        Get-FileSystemSecurity
        Get-RegistrySecurity
    )

    # Calculate summary
    foreach ($category in $categories) {
        foreach ($item in $category.items) {
            $auditResults.summary.totalChecks++
            switch ($item.status) {
                "critical" { $auditResults.summary.criticalIssues++ }
                "warning" { $auditResults.summary.warnings++ }
                "good" { $auditResults.summary.passedChecks++ }
            }
        }
    }

    $auditResults.categories = $categories
    return $auditResults
}

function Get-SystemInformation {
    $os = Get-SafeWmiObject -Class Win32_OperatingSystem
    $cs = Get-SafeWmiObject -Class Win32_ComputerSystem
    
    # Safely get CPU usage without using performance counters
    $cpuUsage = try {
        $cpu = (Get-SafeWmiObject -Class Win32_Processor).LoadPercentage
        if ($cpu) { "$cpu%" } else { "N/A" }
    } catch {
        "N/A"
    }

    # Calculate memory usage safely
    $memoryUsage = if ($os) {
        try {
            "$([math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 2))%"
        } catch {
            "N/A"
        }
    } else {
        "N/A"
    }

    return @{
        name = "System Information"
        items = @(
            @{
                name = "Operating System"
                value = if ($os) { $os.Caption } else { "Unknown" }
                status = "info"
                details = if ($os) { "Version $($os.Version)" } else { "Could not determine OS version" }
            }
            @{
                name = "System Uptime"
                value = if ($os) { 
                    try {
                        $bootTime = $os.LastBootUpTime
                        $uptime = (Get-Date) - [Management.ManagementDateTimeConverter]::ToDateTime($bootTime)
                        "$([math]::Round($uptime.TotalHours, 2)) hours"
                    } catch {
                        "Unknown"
                    }
                } else { "Unknown" }
                status = "info"
                details = "Last boot time information"
            }
            @{
                name = "CPU Usage"
                value = $cpuUsage
                status = "info"
                details = "Current processor utilization"
            }
            @{
                name = "Memory Usage"
                value = $memoryUsage
                status = "info"
                details = if ($cs) { "Total Memory: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB" } else { "Memory information unavailable" }
            }
        )
    }
}

function Get-SecuritySettings {
    # Safely check Windows Defender status
    $defenderStatus = try {
        Get-MpComputerStatus -ErrorAction Stop
    } catch {
        $null
    }

    # Safely check firewall status
    $firewallStatus = try {
        Get-NetFirewallProfile -ErrorAction Stop
    } catch {
        @()
    }

    $items = @(
        @{
            name = "Windows Defender Status"
            value = if ($defenderStatus) { 
                if ($defenderStatus.AntivirusEnabled) { "Enabled" } else { "Disabled" }
            } else { "Unknown" }
            status = if ($defenderStatus -and $defenderStatus.AntivirusEnabled) { "good" } else { "warning" }
            details = "Security status of Windows Defender"
        }
        @{
            name = "Real-time Protection"
            value = if ($defenderStatus) {
                if ($defenderStatus.RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" }
            } else { "Unknown" }
            status = if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) { "good" } else { "warning" }
            details = "Real-time protection status"
        }
    )

    # Add firewall status for each profile
    foreach ($profile in $firewallStatus) {
        $items += @{
            name = "Firewall ($($profile.Name))"
            value = if ($profile.Enabled) { "Enabled" } else { "Disabled" }
            status = if ($profile.Enabled) { "good" } else { "warning" }
            details = "Firewall profile status"
        }
    }

    return @{
        name = "Security Settings"
        items = $items
    }
}

function Get-NetworkSecurity {
    # Safely get network connections
    $connections = try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop
    } catch {
        @()
    }

    return @{
        name = "Network Security"
        items = @(
            @{
                name = "Open Ports"
                value = $connections.Count
                status = if ($connections.Count -gt 20) { "warning" } else { "info" }
                details = "Number of open TCP ports"
            }
            @{
                name = "Network Adapters"
                value = (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }).Count
                status = "info"
                details = "Active network adapters"
            }
        )
    }
}

function Get-UpdateStatus {
    $updates = try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Search("IsInstalled=0").Updates
    } catch {
        $null
    }

    return @{
        name = "Windows Updates"
        items = @(
            @{
                name = "Pending Updates"
                value = if ($updates) { $updates.Count } else { "Unknown" }
                status = if ($updates -and $updates.Count -gt 0) { "warning" } else { "good" }
                details = "System update status"
            }
        )
    }
}

function Get-UserSecurity {
    $users = try {
        Get-LocalUser -ErrorAction Stop
    } catch {
        @()
    }

    $admins = try {
        Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    } catch {
        @()
    }

    return @{
        name = "User Security"
        items = @(
            @{
                name = "Admin Accounts"
                value = $admins.Count
                status = if ($admins.Count -gt 2) { "warning" } else { "info" }
                details = "Number of administrator accounts"
            }
            @{
                name = "User Accounts"
                value = $users.Count
                status = "info"
                details = "Total local user accounts"
            }
        )
    }
}

function Get-FileSystemSecurity {
    return @{
        name = "File System Security"
        items = @(
            @{
                name = "User Directory Permissions"
                value = if (Test-Path $env:USERPROFILE) { "Accessible" } else { "Error" }
                status = "info"
                details = "Access to user directory"
            }
            @{
                name = "Temp Directory Access"
                value = if (Test-Path $env:TEMP) { "Accessible" } else { "Error" }
                status = "info"
                details = "Access to temporary files"
            }
        )
    }
}

function Get-RegistrySecurity {
    return @{
        name = "Registry Security"
        items = @(
            @{
                name = "User Registry Access"
                value = if (Test-Path "HKCU:\") { "Accessible" } else { "Error" }
                status = "info"
                details = "Access to user registry hive"
            }
            @{
                name = "Software Settings"
                value = if (Test-Path "HKCU:\Software") { "Accessible" } else { "Error" }
                status = "info"
                details = "Access to software settings"
            }
        )
    }
}

# Create simple HTTP server using .NET without admin rights
$port = 3000
$endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $port)
$listener = [System.Net.Sockets.TcpListener]::new($endpoint)

try {
    $listener.Start()
    Write-Host "Server started at http://localhost:$port/"

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    }

    while ($true) {
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $writer = [System.IO.StreamWriter]::new($stream)

        # Read the HTTP request
        $request = ""
        while (($line = $reader.ReadLine()) -ne "") {
            $request += "$line`n"
        }

        # Parse the request
        $requestLines = $request -split "`n"
        $method = ($requestLines[0] -split " ")[0]
        $path = ($requestLines[0] -split " ")[1]

        # Set CORS headers
        $headers = "HTTP/1.1 200 OK`r`n"
        $headers += "Content-Type: application/json`r`n"
        $headers += "Access-Control-Allow-Origin: *`r`n"
        $headers += "Access-Control-Allow-Methods: GET, POST, OPTIONS`r`n"
        $headers += "Access-Control-Allow-Headers: Content-Type`r`n"
        
        if ($method -eq "OPTIONS") {
            $writer.WriteLine($headers)
            $writer.WriteLine("")
            $writer.Flush()
        }
        elseif ($path -eq "/api/audit") {
            $results = Start-SecurityAudit
            $json = $results | ConvertTo-Json -Depth 10 -Compress
            
            $writer.WriteLine($headers)
            $writer.WriteLine("")
            $writer.WriteLine($json)
            $writer.Flush()
            
            # Save results to file
            $json | Out-File "$OutputPath\audit_results.json" -Force
        }

        $client.Close()
    }
}
finally {
    if ($listener) {
        $listener.Stop()
    }
}