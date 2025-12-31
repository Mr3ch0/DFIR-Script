# DFIR-Script.ps1

**Windows Digital Forensics and Incident Response Artifact Collection Tool**

Version: 4.0.0

A comprehensive PowerShell script for collecting forensic artifacts from Windows systems during incident response. Designed for use by DFIR professionals, SOC analysts, and incident responders.

## Features

- **Memory Acquisition** - Optional RAM dump via winpmem integration
- **Order of Volatility** - Collects most volatile data first (RFC 3227 compliant)
- **Evidence Integrity** - SHA256 hashing of all collected artifacts
- **Chain of Custody** - Built-in documentation with case/examiner tracking
- **60+ Artifact Types** - Comprehensive collection across all forensic categories
- **30+ Event Log Channels** - Security-relevant Windows event logs
- **MITRE ATT&CK Aligned** - Persistence detection mapped to techniques
- **Credential Theft Detection** - Kerberoasting, DCSync, LSASS dump indicators
- **Timeline Generation** - Consolidated forensic timeline in CSV format
- **SIEM-Ready Output** - All artifacts exported as properly formatted CSV

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell Core 7+
- **Administrator privileges recommended** for full artifact collection
- Optional: [WinPmem](https://github.com/Velocidex/WinPmem) for memory acquisition

## Quick Start

```powershell
# Basic collection (run as Administrator)
.\DFIR-Script.ps1

# With case documentation
.\DFIR-Script.ps1 -CaseName "INC-2024-001" -ExaminerName "John Doe"

# Extended event log lookback (30 days)
.\DFIR-Script.ps1 -SearchWindowDays 30

# With memory acquisition
.\DFIR-Script.ps1 -MemoryDumpPath "C:\Tools\winpmem.exe"

# Output to network share
.\DFIR-Script.ps1 -OutputPath "\\server\evidence$" -CaseName "INC-2024-001"
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SearchWindowDays` | Int | 7 | Days to look back for event logs (1-365) |
| `-OutputPath` | String | Current directory | Output location (supports UNC paths) |
| `-CaseName` | String | Auto-generated | Case identifier for chain of custody |
| `-ExaminerName` | String | Current user | Examiner name for chain of custody |
| `-MemoryDumpPath` | String | Auto-detect | Path to winpmem.exe |
| `-SkipVolatile` | Switch | False | Skip volatile artifact collection |
| `-SkipMemory` | Switch | False | Skip memory acquisition |
| `-CollectBrowsers` | Bool | True | Collect browser artifacts |
| `-MaxEventLogSize` | Int | 50000 | Maximum events per log (1000-500000) |

## Artifacts Collected

### Phase 0: Memory Acquisition
- RAM dump via winpmem (if available)

### Phase 1: Volatile Data
- System date/time (local + UTC)
- Network state (ARP cache, routing table, TCP/UDP connections)
- Running processes with hashes and command lines
- Loaded DLLs per process
- Named pipes
- Open file handles

### Phase 2: User Information
- Local user accounts and groups
- Group memberships
- User profile list
- Active logon sessions

### Phase 3: Services and Drivers
- All services with binary hashes
- Installed drivers with hashes
- Scheduled tasks with actions and run history

### Phase 4: Persistence Mechanisms
- Registry Run keys (8 locations)
- Startup folders
- IFEO debugger hijacking (T1546.012)
- AppInit_DLLs (T1546.010)
- Security Support Providers (T1547.005)
- Print Monitors (T1547.010)
- WMI Event Subscriptions (T1546.003)
- Winlogon keys (T1547.001)
- Authentication Packages (T1547.002)
- Netsh Helper DLLs (T1546.007)
- Active Setup (T1547.014)
- Boot Execute (T1547.004)
- COM Hijacking detection (T1546.015)

### Phase 5: Security Configuration
- Windows Defender configuration and exclusions
- Defender threat detection history
- Firewall rules (enabled)
- Audit policy
- UAC settings
- BitLocker status
- LSASS protection status

### Phase 6: Execution Artifacts
- Prefetch files (.pf)
- Amcache.hve
- ShimCache (AppCompatCache)
- RecentFileCache.bcf
- SRUM database (SRUDB.dat)
- BITS jobs and qmgr.db
- USN Journal records
- MFT/NTFS info

### Phase 7: User Activity
- Jump Lists (automatic and custom destinations)
- LNK files (parsed with targets)
- RDP Bitmap Cache
- PowerShell history (all users)
- Email artifact locations (.ost/.pst)
- Browser artifacts (Chrome, Edge, Brave, Firefox)

### Phase 8: Network and Devices
- Connected PnP devices
- USB device history
- SMB shares, sessions, and open files
- RDP configuration
- Hosts file

### Phase 9: Event Logs
Copies 30+ security-relevant event log channels:
- Core: Application, Security, System
- Sysmon (if installed)
- PowerShell Operational
- Task Scheduler
- WMI-Activity
- Terminal Services (RDP)
- Windows Defender
- BITS Client
- WinRM
- NTLM
- DNS Client
- AppLocker
- Code Integrity
- Firewall
- SMB Client/Server
- Kerberos
- LSA
- And more...

### Phase 10: Credential Theft Detection
- Crash dumps with LSASS indicator detection
- LSASS protection status (RunAsPPL, Credential Guard)
- Kerberos RC4 ticket requests (Kerberoasting)
- DCSync indicators (Event 4662 with replication GUIDs)
- AMSI bypass detection in script blocks

### Phase 11: Additional Artifacts
- Alternate Data Streams (with Zone.Identifier)
- Installed software
- Certificate stores
- Environment variables
- Shadow copies

### LOLBin Artifact Collection
- CertUtil URL cache
- BITS job history from events
- MSHTA/Regsvr32 prefetch detection

## Output Structure

```
DFIR-HOSTNAME-2024-12-31_120000/
├── CSV_Results/                    # 60+ CSV files for SIEM import
│   ├── RunningProcesses.csv
│   ├── TCPConnections.csv
│   ├── SecurityEvents.csv
│   ├── AdvancedPersistence.csv
│   ├── ForensicTimeline.csv
│   └── ...
├── Memory/                         # RAM dump (if collected)
│   └── memory_HOSTNAME.raw
├── EventLogs/                      # Raw .evtx files
│   ├── Security.evtx
│   ├── Microsoft-Windows-Sysmon-Operational.evtx
│   └── ...
├── ExecutionArtifacts/
│   ├── Amcache.hve
│   ├── AppCompatCache.bin
│   └── RecentFileCache.bcf
├── Prefetch/                       # .pf files
├── SRUM/                           # SRUDB.dat
├── BITS/                           # qmgr.db
├── USNJournal/                     # USN records
├── JumpLists/                      # Per-user
├── RDPCache/                       # Bitmap cache per-user
├── Browsers/                       # Per-user/browser profiles
├── PowerShellHistory/              # Per-user PSReadLine history
├── DefenderLogs/                   # Defender support logs
├── NetworkConfig/                  # hosts file
├── Collection.log                  # Detailed execution log
├── CollectionMetadata.json         # System and collection info
├── CollectionMetadata.xml          # System and collection info
├── EvidenceManifest.csv            # SHA256 hashes of all files
├── CHAIN_OF_CUSTODY.txt            # Legal documentation
└── CollectionStatistics.csv        # Success/failure counts
```

A ZIP archive is automatically created at completion.

## Security Event Analysis

The script specifically collects and analyzes these security events:

| Event ID | Description |
|----------|-------------|
| 4624/4625 | Successful/Failed Logon |
| 4648 | Explicit Credentials Logon |
| 4672 | Special Privileges Assigned |
| 4688/4689 | Process Creation/Termination |
| 4720-4743 | Account Management |
| 4768/4769/4771 | Kerberos Authentication |
| 4697/7045 | Service Installation |
| 4698-4702 | Scheduled Task Activity |
| 4662 | Directory Service Access (DCSync) |
| 1102 | Audit Log Cleared |

## Alerts

The script will generate alerts (logged and displayed) for:
- Suspicious crash dumps (possible LSASS dumps)
- DCSync activity indicators
- Suspicious PowerShell script blocks (AMSI bypass, encoded commands)

## Integration

### Defender for Endpoint Live Response
This script is compatible with Microsoft Defender for Endpoint Live Response sessions.

### SIEM Import
All CSV files use proper formatting with UTF-8 encoding for direct import into:
- Splunk
- Microsoft Sentinel
- Elastic SIEM
- QRadar
- Any CSV-compatible SIEM

## Limitations

- **Memory acquisition** requires winpmem.exe (not included)
- **Full $MFT copy** requires raw disk access (only metadata collected)
- **Some artifacts** require Administrator privileges
- **Locked files** (Amcache, SRUM) may require service stops or VSS

## Best Practices

1. **Run as Administrator** for complete collection
2. **Use network output path** to avoid writing to evidence drive
3. **Document case information** with `-CaseName` and `-ExaminerName`
4. **Verify evidence integrity** using EvidenceManifest.csv
5. **Review Collection.log** for any errors or skipped artifacts
6. **Check for alerts** indicating suspicious activity

## Example Workflows

### Standard Incident Response
```powershell
.\DFIR-Script.ps1 `
    -CaseName "INC-2024-001" `
    -ExaminerName "Jane Smith" `
    -SearchWindowDays 14 `
    -OutputPath "E:\Evidence"
```

### Quick Triage (Skip Memory)
```powershell
.\DFIR-Script.ps1 -SkipMemory -SearchWindowDays 3
```

### Full Collection with Memory
```powershell
.\DFIR-Script.ps1 `
    -MemoryDumpPath "C:\Tools\winpmem_mini_x64.exe" `
    -CaseName "RANSOM-2024-042" `
    -ExaminerName "IR Team" `
    -SearchWindowDays 30 `
    -OutputPath "\\forensics\cases$"
```

### Remote Collection via PsExec
```powershell
psexec \\TARGET -s -c DFIR-Script.ps1 -accepteula
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 4.0.0 | 2024-12-31 | Complete rewrite with 60+ artifacts, evidence integrity, timeline |
| 2.2.0 | 2024-08-27 | Original version |

## Contributing

Suggestions for additional artifacts or improvements are welcome.

## License

For authorized security testing and incident response use only.

## Acknowledgments

- SANS DFIR
- MITRE ATT&CK Framework
- Velocidex (WinPmem)
