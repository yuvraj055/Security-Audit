const express = require('express');
const cors = require('cors');
const si = require('systeminformation');
const os = require('os');
const fs = require('fs').promises;
const { exec } = require('child_process');
const util = require('util');
const crypto = require('crypto');
const execPromise = util.promisify(exec);

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// Enhanced Windows Defender status check
async function getWindowsDefenderStatus() {
    if (process.platform !== 'win32') return null;
    try {
        const { stdout } = await execPromise('powershell.exe Get-MpComputerStatus | ConvertTo-Json');
        const status = JSON.parse(stdout);
        return {
            AntivirusEnabled: status.AntivirusEnabled,
            RealTimeProtectionEnabled: status.RealTimeProtectionEnabled,
            BehaviorMonitorEnabled: status.BehaviorMonitorEnabled,
            IoavProtectionEnabled: status.IoavProtectionEnabled,
            NISEnabled: status.NISEnabled,
            QuickScanSignatureAge: status.QuickScanSignatureAge,
            AntivirusSignatureAge: status.AntivirusSignatureAge
        };
    } catch (error) {
        return null;
    }
}

// Enhanced firewall status check
async function getFirewallStatus() {
    if (process.platform === 'win32') {
        try {
            const { stdout } = await execPromise('powershell.exe Get-NetFirewallProfile | ConvertTo-Json');
            const profiles = JSON.parse(stdout);
            return Array.isArray(profiles) ? profiles : [profiles];
        } catch (error) {
            return [];
        }
    }
    return [];
}

// New: Check for suspicious processes
async function checkSuspiciousProcesses() {
    try {
        const processes = await si.processes();
        const suspiciousPatterns = [
            'crypto', 'miner', 'hack', 'keylog', 'trojan', 
            'botnet', 'backdoor', 'spyware', 'malware'
        ];
        
        return processes.list.filter(proc => 
            suspiciousPatterns.some(pattern => 
                proc.name.toLowerCase().includes(pattern) ||
                (proc.command && proc.command.toLowerCase().includes(pattern))
            )
        );
    } catch (error) {
        return [];
    }
}

// New: Check system ports
async function checkOpenPorts() {
    try {
        const connections = await si.networkConnections();
        const openPorts = connections
            .filter(conn => conn.state === 'LISTEN')
            .map(conn => conn.localport);
        
        const commonPorts = new Set([80, 443, 22, 3389, 3306, 5432]);
        const suspiciousPorts = openPorts.filter(port => !commonPorts.has(port));
        
        return {
            total: openPorts.length,
            suspicious: suspiciousPorts
        };
    } catch (error) {
        return { total: 0, suspicious: [] };
    }
}

// New: Check disk encryption status (Windows)
async function checkDiskEncryption() {
    if (process.platform === 'win32') {
        try {
            const { stdout } = await execPromise('manage-bde -status');
            return {
                enabled: stdout.includes('Protection On'),
                details: stdout
            };
        } catch (error) {
            return { enabled: false, details: 'Unable to determine encryption status' };
        }
    }
    return { enabled: false, details: 'Not supported on this platform' };
}

// New: Check system updates
async function checkSystemUpdates() {
    if (process.platform === 'win32') {
        try {
            const { stdout } = await execPromise('powershell.exe Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1 | ConvertTo-Json');
            const lastUpdate = JSON.parse(stdout);
            const daysSinceUpdate = Math.floor((new Date() - new Date(lastUpdate.InstalledOn)) / (1000 * 60 * 60 * 24));
            
            return {
                lastUpdate: lastUpdate.InstalledOn,
                daysSinceUpdate,
                status: daysSinceUpdate > 30 ? 'critical' : daysSinceUpdate > 14 ? 'warning' : 'good'
            };
        } catch (error) {
            return { status: 'unknown', daysSinceUpdate: null };
        }
    }
    return { status: 'unknown', daysSinceUpdate: null };
}

// New: Check password policies
async function checkPasswordPolicies() {
    if (process.platform === 'win32') {
        try {
            const { stdout } = await execPromise('powershell.exe Get-LocalUser | ConvertTo-Json');
            const users = JSON.parse(stdout);
            const weakPasswords = users.filter(user => !user.PasswordRequired);
            
            return {
                totalUsers: users.length,
                weakPasswords: weakPasswords.length,
                passwordNeverExpires: users.filter(user => user.PasswordNeverExpires).length
            };
        } catch (error) {
            return null;
        }
    }
    return null;
}

// New: Check installed software
async function checkInstalledSoftware() {
    if (process.platform === 'win32') {
        try {
            const { stdout } = await execPromise('powershell.exe Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher | ConvertTo-Json');
            return JSON.parse(stdout);
        } catch (error) {
            return [];
        }
    }
    return [];
}

// Enhanced audit endpoint
app.post('/api/audit', async (req, res) => {
    try {
        // Collect basic system information
        const [cpu, mem, osInfo, networkInterfaces, diskLayout] = await Promise.all([
            si.currentLoad(),
            si.mem(),
            si.osInfo(),
            si.networkInterfaces(),
            si.diskLayout()
        ]);

        // Collect security-related information
        const [
            defenderStatus,
            firewallProfiles,
            suspiciousProcesses,
            portInfo,
            diskEncryption,
            updateStatus,
            passwordPolicies,
            installedSoftware
        ] = await Promise.all([
            getWindowsDefenderStatus(),
            getFirewallStatus(),
            checkSuspiciousProcesses(),
            checkOpenPorts(),
            checkDiskEncryption(),
            checkSystemUpdates(),
            checkPasswordPolicies(),
            checkInstalledSoftware()
        ]);

        // Initialize counters
        let criticalIssues = 0;
        let warnings = 0;
        let passedChecks = 0;

        const updateCounts = (status) => {
            switch (status) {
                case 'critical': criticalIssues++; break;
                case 'warning': warnings++; break;
                case 'good': passedChecks++; break;
            }
        };

        // Enhanced categories with new checks
        const categories = [
            {
                name: "System Information",
                checks: [
                    {
                        name: "Operating System",
                        description: `${osInfo.platform} ${osInfo.release} (${osInfo.arch})`,
                        status: "info"
                    },
                    {
                        name: "CPU Usage",
                        description: `Current CPU load: ${Math.round(cpu.currentLoad)}%`,
                        status: cpu.currentLoad > 90 ? "critical" : cpu.currentLoad > 70 ? "warning" : "good"
                    },
                    {
                        name: "Memory Usage",
                        description: `Used: ${Math.round(mem.used / 1024 / 1024 / 1024)}GB of ${Math.round(mem.total / 1024 / 1024 / 1024)}GB`,
                        status: (mem.used / mem.total) > 0.9 ? "critical" : (mem.used / mem.total) > 0.7 ? "warning" : "good"
                    },
                    {
                        name: "System Updates",
                        description: updateStatus.daysSinceUpdate ? 
                            `Last update: ${updateStatus.daysSinceUpdate} days ago` : 
                            'Unable to determine update status',
                        status: updateStatus.status
                    }
                ]
            },
            {
                name: "Security Settings",
                checks: [
                    {
                        name: "Windows Defender Status",
                        description: defenderStatus ? 
                            `Antivirus: ${defenderStatus.AntivirusEnabled ? 'Enabled' : 'Disabled'}, Real-time protection: ${defenderStatus.RealTimeProtectionEnabled ? 'Enabled' : 'Disabled'}` : 
                            "Unable to determine Windows Defender status",
                        status: defenderStatus?.AntivirusEnabled && defenderStatus?.RealTimeProtectionEnabled ? "good" : "critical"
                    },
                    {
                        name: "Defender Signatures",
                        description: defenderStatus ? 
                            `Signature age: ${defenderStatus.AntivirusSignatureAge} days` : 
                            "Unable to check signatures",
                        status: defenderStatus?.AntivirusSignatureAge > 7 ? "warning" : "good"
                    },
                    {
                        name: "Firewall Profiles",
                        description: `${firewallProfiles.length} profiles configured`,
                        status: firewallProfiles.every(p => p.Enabled) ? "good" : "critical"
                    },
                    {
                        name: "Disk Encryption",
                        description: diskEncryption.details,
                        status: diskEncryption.enabled ? "good" : "warning"
                    }
                ]
            },
            {
                name: "Network Security",
                checks: [
                    {
                        name: "Open Ports",
                        description: `Total: ${portInfo.total}, Suspicious: ${portInfo.suspicious.length}`,
                        status: portInfo.suspicious.length > 0 ? "warning" : "good"
                    },
                    {
                        name: "Network Interfaces",
                        description: `Active interfaces: ${networkInterfaces.length}`,
                        status: "info"
                    }
                ]
            },
            {
                name: "Process Security",
                checks: [
                    {
                        name: "Suspicious Processes",
                        description: `Found ${suspiciousProcesses.length} potentially suspicious processes`,
                        status: suspiciousProcesses.length > 0 ? "warning" : "good"
                    }
                ]
            },
            {
                name: "User Security",
                checks: [
                    {
                        name: "Password Policies",
                        description: passwordPolicies ? 
                            `Users with weak passwords: ${passwordPolicies.weakPasswords}, Never expires: ${passwordPolicies.passwordNeverExpires}` :
                            "Unable to check password policies",
                        status: passwordPolicies?.weakPasswords > 0 ? "critical" : "good"
                    },
                    {
                        name: "User Accounts",
                        description: `Total accounts: ${passwordPolicies?.totalUsers || 'Unknown'}`,
                        status: "info"
                    }
                ]
            },
            {
                name: "Software Security",
                checks: [
                    {
                        name: "Installed Software",
                        description: `Total applications: ${installedSoftware.length}`,
                        status: "info"
                    }
                ]
            }
        ];

        // Calculate summary
        categories.forEach(category => {
            category.checks.forEach(check => {
                updateCounts(check.status);
            });
        });

        const auditResults = {
            timestamp: new Date().toISOString(),
            hostname: os.hostname(),
            categories: categories,
            summary: {
                criticalIssues,
                warnings,
                passedChecks,
                totalChecks: criticalIssues + warnings + passedChecks
            },
            details: {
                suspiciousProcesses,
                openPorts: portInfo,
                installedSoftware
            }
        };

        res.json(auditResults);
    } catch (error) {
        console.error('Audit error:', error);
        res.status(500).json({ error: 'Failed to perform security audit' });
    }
});

app.listen(port, () => {
    console.log(`Enhanced security audit server running at http://localhost:${port}`);
});