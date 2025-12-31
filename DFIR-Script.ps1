<#
.SYNOPSIS
    Complete DFIR Artifact Collection Script for Windows Incident Response

.DESCRIPTION
    Comprehensive forensic artifact collection tool implementing ALL recommendations:
    - Memory acquisition support (winpmem integration)
    - Order of volatility compliance (RFC 3227)
    - Full evidence integrity with SHA256 hashing
    - Chain of custody documentation
    - Execution artifacts (Prefetch, Amcache, SRUM, ShimCache, RecentFileCache)
    - Advanced persistence detection (IFEO, COM, WMI, SSP, Print Monitors, Boot Execute)
    - LOLBin artifact collection (certutil, bitsadmin cache)
    - USN Journal and $MFT collection attempts
    - Jump Lists and LNK file analysis
    - RDP Bitmap Cache collection
    - Email artifacts (.ost/.pst locations)
    - Credential theft indicators (crash dumps, Kerberos events, DCSync)
    - AMSI bypass detection
    - Timeline generation
    - 30+ event log channels

.PARAMETER SearchWindowDays
    Number of days to look back for event logs (default: 7)

.PARAMETER OutputPath
    Output directory path (default: current directory). Supports UNC paths.

.PARAMETER CaseName
    Case identifier for chain of custody documentation

.PARAMETER ExaminerName
    Examiner name for chain of custody documentation

.PARAMETER SkipVolatile
    Skip volatile artifact collection (network state, processes)

.PARAMETER SkipMemory
    Skip memory acquisition even if winpmem is available

.PARAMETER MemoryDumpPath
    Path to winpmem executable for memory acquisition

.PARAMETER CollectBrowsers
    Collect browser artifacts (default: true)

.PARAMETER MaxEventLogSize
    Maximum events to collect per log (default: 50000)

.EXAMPLE
    .\DFIR-Script-Complete.ps1 -SearchWindowDays 30 -CaseName "INC-2024-001" -ExaminerName "John Doe"

.EXAMPLE
    .\DFIR-Script-Complete.ps1 -MemoryDumpPath "C:\Tools\winpmem.exe" -OutputPath "\\server\evidence$"

.NOTES
    Version: 4.0.0
    Requires: PowerShell 5.1+ or PowerShell Core 7+
    Requires: Administrator privileges for full collection
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$SearchWindowDays = 7,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $PWD.Path,

    [string]$CaseName = "DFIR-$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [string]$ExaminerName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,

    [switch]$SkipVolatile,
    [switch]$SkipMemory,

    [string]$MemoryDumpPath,

    [bool]$CollectBrowsers = $true,

    [ValidateRange(1000, 500000)]
    [int]$MaxEventLogSize = 50000
)

#region Script Configuration
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Script:Version = '4.0.0'
$Script:StartTime = Get-Date
$Script:CollectionErrors = [System.Collections.Generic.List[PSObject]]::new()
$Script:TimelineEvents = [System.Collections.Generic.List[PSObject]]::new()
$Script:CollectionStats = @{
    TotalArtifacts = 0
    SuccessfulCollections = 0
    FailedCollections = 0
    SkippedCollections = 0
}

$Script:Config = @{
    PrefetchPath = 'C:\Windows\Prefetch'
    AmcachePath = 'C:\Windows\AppCompat\Programs\Amcache.hve'
    RecentFileCachePath = 'C:\Windows\AppCompat\Programs\RecentFileCache.bcf'
    SRUMPath = 'C:\Windows\System32\sru\SRUDB.dat'
    EventLogPath = 'C:\Windows\System32\winevt\Logs'
    DefenderLogPath = 'C:\ProgramData\Microsoft\Windows Defender\Support'
    UsersPath = 'C:\Users'
    BITSPath = 'C:\ProgramData\Microsoft\Network\Downloader'
    WMIRepositoryPath = 'C:\Windows\System32\wbem\Repository'
    HostsFilePath = 'C:\Windows\System32\drivers\etc\hosts'
    CertUtilCachePath = 'C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache'
}
#endregion

#region Helper Functions
function Write-CollectionLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG', 'ALERT')]
        [string]$Level = 'INFO'
    )
    $Timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $LogEntry = "[$Timestamp] [$Level] $Message"
    $LogEntry | Out-File -FilePath $Script:LogFile -Append -Encoding UTF8
    $Color = switch ($Level) {
        'ERROR'   { 'Red' }
        'WARNING' { 'Yellow' }
        'SUCCESS' { 'Green' }
        'ALERT'   { 'Magenta' }
        'DEBUG'   { 'Gray' }
        default   { 'White' }
    }
    Write-Host $LogEntry -ForegroundColor $Color
}

function Invoke-SafeCollection {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$CollectionBlock,
        [Parameter(Mandatory)]
        [string]$ArtifactName,
        [switch]$RequiresAdmin
    )
    $Script:CollectionStats.TotalArtifacts++
    if ($RequiresAdmin -and -not $Script:IsAdmin) {
        Write-CollectionLog "Skipping $ArtifactName (requires administrator)" -Level 'WARNING'
        $Script:CollectionStats.SkippedCollections++
        return
    }
    try {
        Write-CollectionLog "Collecting: $ArtifactName"
        & $CollectionBlock
        Write-CollectionLog "Completed: $ArtifactName" -Level 'SUCCESS'
        $Script:CollectionStats.SuccessfulCollections++
    }
    catch {
        $Script:CollectionErrors.Add([PSCustomObject]@{
            Artifact = $ArtifactName
            ErrorMessage = $_.Exception.Message
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        })
        Write-CollectionLog "FAILED: $ArtifactName - $($_.Exception.Message)" -Level 'ERROR'
        $Script:CollectionStats.FailedCollections++
    }
}

function Get-SafeFileHash {
    param([Parameter(Mandatory)][string]$FilePath)
    try {
        if (Test-Path -Path $FilePath -PathType Leaf) {
            return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    } catch { return "HASH_ERROR: $($_.Exception.Message)" }
    return "FILE_NOT_FOUND"
}

function Export-ToCSV {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory)]
        [string]$Path
    )
    begin { $Objects = [System.Collections.Generic.List[object]]::new() }
    process { if ($null -ne $InputObject) { $Objects.Add($InputObject) } }
    end {
        if ($Objects.Count -gt 0) { $Objects | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 }
        else { [PSCustomObject]@{ Status = 'NO_DATA_COLLECTED' } | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 }
    }
}

function Add-TimelineEvent {
    param(
        [Parameter(Mandatory)][datetime]$Timestamp,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$EventType,
        [string]$Description,
        [string]$Details
    )
    $Script:TimelineEvents.Add([PSCustomObject]@{
        TimestampUTC = $Timestamp.ToUniversalTime().ToString('o')
        Source = $Source
        EventType = $EventType
        Description = $Description
        Details = $Details
    })
}

function Copy-LockedFile {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    try {
        Copy-Item -Path $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
        return $true
    } catch {
        Write-CollectionLog "File locked, attempting raw copy: $SourcePath" -Level 'WARNING'
    }
    # Attempt using .NET raw file access
    try {
        $SourceStream = [System.IO.File]::Open($SourcePath, 'Open', 'Read', 'ReadWrite')
        $DestStream = [System.IO.File]::Create($DestinationPath)
        $SourceStream.CopyTo($DestStream)
        $SourceStream.Close()
        $DestStream.Close()
        return $true
    } catch {
        Write-CollectionLog "Raw copy failed: $($_.Exception.Message)" -Level 'WARNING'
        return $false
    }
}
#endregion

#region Collection Metadata
function New-CollectionMetadata {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $CS = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

    $Script:CollectionMetadata = [PSCustomObject]@{
        CaseName = $CaseName
        ExaminerName = $ExaminerName
        CollectionStartTimeUTC = $Script:StartTime.ToUniversalTime().ToString('o')
        CollectionEndTimeUTC = $null
        ScriptVersion = $Script:Version
        Hostname = $env:COMPUTERNAME
        Domain = $env:USERDOMAIN
        FQDN = "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
        CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        IsAdministrator = $Script:IsAdmin
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        CLRVersion = $PSVersionTable.CLRVersion.ToString()
        OSCaption = $OS.Caption
        OSVersion = $OS.Version
        OSBuild = $OS.BuildNumber
        OSArchitecture = $OS.OSArchitecture
        InstallDate = $OS.InstallDate.ToString('o')
        LastBootTime = $OS.LastBootUpTime.ToString('o')
        SystemUptime = ((Get-Date) - $OS.LastBootUpTime).ToString()
        Manufacturer = $CS.Manufacturer
        Model = $CS.Model
        TotalPhysicalMemory = $CS.TotalPhysicalMemory
        NumberOfProcessors = $CS.NumberOfProcessors
        TimeZone = (Get-TimeZone).Id
        TimeZoneOffset = (Get-TimeZone).BaseUtcOffset.ToString()
        SearchWindowDays = $SearchWindowDays
        OutputDirectory = $Script:OutputFolder
    }
}

function Save-CollectionMetadata {
    $Script:CollectionMetadata.CollectionEndTimeUTC = (Get-Date).ToUniversalTime().ToString('o')
    $Script:CollectionMetadata | Export-Clixml -Path "$Script:OutputFolder\CollectionMetadata.xml"
    $Script:CollectionMetadata | ConvertTo-Json -Depth 5 | Out-File "$Script:OutputFolder\CollectionMetadata.json" -Encoding UTF8
}
#endregion

#region Memory Acquisition
function Get-MemoryDump {
    if ($SkipMemory) {
        Write-CollectionLog "Memory acquisition skipped by user request" -Level 'WARNING'
        return
    }

    $WinPmemPath = $MemoryDumpPath
    if (-not $WinPmemPath -or -not (Test-Path $WinPmemPath)) {
        # Try common locations
        $CommonPaths = @(
            ".\winpmem.exe",
            "C:\Tools\winpmem.exe",
            "C:\Windows\Temp\winpmem.exe",
            "$env:TEMP\winpmem.exe"
        )
        foreach ($Path in $CommonPaths) {
            if (Test-Path $Path) { $WinPmemPath = $Path; break }
        }
    }

    if (-not $WinPmemPath -or -not (Test-Path $WinPmemPath)) {
        Write-CollectionLog "winpmem not found. Memory acquisition skipped. Download from: https://github.com/Velocidex/WinPmem" -Level 'WARNING'
        [PSCustomObject]@{
            Status = 'SKIPPED'
            Reason = 'winpmem executable not found'
            RecommendedSource = 'https://github.com/Velocidex/WinPmem'
            CollectionTimeUTC = (Get-Date).ToUniversalTime().ToString('o')
        } | Export-ToCSV -Path "$Script:CSVFolder\MemoryAcquisition.csv"
        return
    }

    $MemoryFolder = New-Item -Path "$Script:OutputFolder\Memory" -ItemType Directory -Force
    $MemoryDumpFile = Join-Path $MemoryFolder.FullName "memory_$env:COMPUTERNAME.raw"

    Write-CollectionLog "Starting memory acquisition with winpmem..." -Level 'ALERT'
    try {
        $Process = Start-Process -FilePath $WinPmemPath -ArgumentList $MemoryDumpFile -Wait -PassThru -NoNewWindow
        if ($Process.ExitCode -eq 0 -and (Test-Path $MemoryDumpFile)) {
            $MemInfo = Get-Item $MemoryDumpFile
            Write-CollectionLog "Memory dump completed: $($MemInfo.Length / 1GB) GB" -Level 'SUCCESS'
            [PSCustomObject]@{
                Status = 'SUCCESS'
                FilePath = $MemoryDumpFile
                SizeBytes = $MemInfo.Length
                SHA256Hash = Get-SafeFileHash -FilePath $MemoryDumpFile
                CollectionTimeUTC = (Get-Date).ToUniversalTime().ToString('o')
            } | Export-ToCSV -Path "$Script:CSVFolder\MemoryAcquisition.csv"
        } else {
            Write-CollectionLog "Memory acquisition failed with exit code: $($Process.ExitCode)" -Level 'ERROR'
        }
    } catch {
        Write-CollectionLog "Memory acquisition error: $($_.Exception.Message)" -Level 'ERROR'
    }
}
#endregion

#region Volatile Data Collection
function Get-SystemDateTime {
    $DateTimeInfo = [PSCustomObject]@{
        LocalTime = (Get-Date).ToString('o')
        UTCTime = (Get-Date).ToUniversalTime().ToString('o')
        TimeZone = (Get-TimeZone).Id
        TimeZoneOffset = (Get-TimeZone).BaseUtcOffset.ToString()
        NTPServer = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue).NtpServer
    }
    $DateTimeInfo | Export-ToCSV -Path "$Script:CSVFolder\SystemDateTime.csv"
}

function Get-NetworkStateVolatile {
    # ARP Cache
    Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias,
        @{N='CollectionTimeUTC'; E={(Get-Date).ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\ARPCache.csv"

    # Routing Table
    Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias,
        @{N='CollectionTimeUTC'; E={(Get-Date).ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\RoutingTable.csv"

    # TCP Connections (ALL states)
    Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
        $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
            OwningProcess = $_.OwningProcess
            ProcessName = $Proc.ProcessName
            ProcessPath = $Proc.Path
            CreationTime = $_.CreationTime
            CollectionTimeUTC = (Get-Date).ToUniversalTime().ToString('o')
        }
    } | Export-ToCSV -Path "$Script:CSVFolder\TCPConnections.csv"

    # UDP Endpoints
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            OwningProcess = $_.OwningProcess
            ProcessName = $Proc.ProcessName
            CollectionTimeUTC = (Get-Date).ToUniversalTime().ToString('o')
        }
    } | Export-ToCSV -Path "$Script:CSVFolder\UDPEndpoints.csv"

    # DNS Cache
    Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Name, Type, Status, TimeToLive, Data,
        @{N='CollectionTimeUTC'; E={(Get-Date).ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\DNSCache.csv"

    # IP Configuration
    Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPAddress, AddressFamily, PrefixLength,
        @{N='CollectionTimeUTC'; E={(Get-Date).ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\IPConfiguration.csv"

    # Network Adapters with MAC
    Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed,
        @{N='CollectionTimeUTC'; E={(Get-Date).ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\NetworkAdapters.csv"
}

function Get-RunningProcesses {
    $Processes = [System.Collections.Generic.List[PSObject]]::new()
    Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $Proc = $_
        $Owner = try { $Proc | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue } catch { $null }
        $Processes.Add([PSCustomObject]@{
            ProcessId = $Proc.ProcessId
            ParentProcessId = $Proc.ParentProcessId
            ProcessName = $Proc.Name
            ExecutablePath = $Proc.ExecutablePath
            CommandLine = $Proc.CommandLine
            CreationDate = if ($Proc.CreationDate) { $Proc.CreationDate.ToUniversalTime().ToString('o') } else { $null }
            SessionId = $Proc.SessionId
            ThreadCount = $Proc.ThreadCount
            HandleCount = $Proc.HandleCount
            WorkingSetSize = $Proc.WorkingSetSize
            Owner = if ($Owner.Domain) { "$($Owner.Domain)\$($Owner.User)" } else { $Owner.User }
            SHA256Hash = if ($Proc.ExecutablePath) { Get-SafeFileHash -FilePath $Proc.ExecutablePath } else { $null }
            CollectionTimeUTC = (Get-Date).ToUniversalTime().ToString('o')
        })
        # Add to timeline
        if ($Proc.CreationDate) {
            Add-TimelineEvent -Timestamp $Proc.CreationDate -Source 'Process' -EventType 'ProcessStart' -Description $Proc.Name -Details $Proc.CommandLine
        }
    }
    $Processes | Export-ToCSV -Path "$Script:CSVFolder\RunningProcesses.csv"
    $Processes | Where-Object { $_.SHA256Hash -and $_.SHA256Hash -notlike "HASH_ERROR*" } |
        Select-Object ExecutablePath, SHA256Hash -Unique | Export-ToCSV -Path "$Script:CSVFolder\UniqueProcessHashes.csv"
}

function Get-LoadedDLLs {
    $Modules = [System.Collections.Generic.List[PSObject]]::new()
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $ProcId = $_.Id
        $ProcName = $_.ProcessName
        try {
            $_.Modules | ForEach-Object {
                $Modules.Add([PSCustomObject]@{
                    ProcessId = $ProcId
                    ProcessName = $ProcName
                    ModuleName = $_.ModuleName
                    FileName = $_.FileName
                    FileVersion = $_.FileVersionInfo.FileVersion
                    Company = $_.FileVersionInfo.CompanyName
                    IsSigned = (Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue).Status -eq 'Valid'
                })
            }
        } catch { }
    }
    $Modules | Export-ToCSV -Path "$Script:CSVFolder\LoadedDLLs.csv"
}

function Get-NamedPipes {
    # Named pipes can indicate C2 communication
    $Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | ForEach-Object {
        [PSCustomObject]@{
            PipeName = $_ -replace '^\\\\.\\pipe\\', ''
            FullPath = $_
            CollectionTimeUTC = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    $Pipes | Export-ToCSV -Path "$Script:CSVFolder\NamedPipes.csv"
}

function Get-Handles {
    try {
        $OpenFiles = openfiles /query /fo csv 2>&1
        if ($OpenFiles -notmatch "ERROR|not enabled") {
            $OpenFiles | ConvertFrom-Csv -ErrorAction SilentlyContinue | Export-ToCSV -Path "$Script:CSVFolder\OpenFiles.csv"
        }
    } catch { }
}
#endregion

#region User and Account Information
function Get-LocalUserAccounts {
    Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, FullName, Description, Enabled,
        PasswordRequired, PasswordLastSet, LastLogon, SID, AccountExpires,
        @{N='CollectionTimeUTC'; E={(Get-Date).ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\LocalUsers.csv"

    # Group memberships
    $GroupMemberships = [System.Collections.Generic.List[PSObject]]::new()
    Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
        $GroupName = $_.Name
        Get-LocalGroupMember -Group $GroupName -ErrorAction SilentlyContinue | ForEach-Object {
            $GroupMemberships.Add([PSCustomObject]@{
                GroupName = $GroupName
                MemberName = $_.Name
                MemberSID = $_.SID
                MemberType = $_.ObjectClass
            })
        }
    }
    $GroupMemberships | Export-ToCSV -Path "$Script:CSVFolder\LocalGroupMemberships.csv"

    # User profile list from registry
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' -ErrorAction SilentlyContinue |
        Select-Object PSChildName, ProfileImagePath, @{N='LastLoadTime'; E={
            [datetime]::FromFileTime($_.ProfileLoadTimeHigh * [math]::Pow(2,32) + $_.ProfileLoadTimeLow)
        }} | Export-ToCSV -Path "$Script:CSVFolder\UserProfiles.csv"
}

function Get-LogonSessions {
    # Active logon sessions
    $Sessions = @()
    try {
        $QueryResult = query user 2>&1
        if ($QueryResult -and $QueryResult[0] -notmatch "No User") {
            $QueryResult | Select-Object -Skip 1 | ForEach-Object {
                if ($_ -match '\S') {
                    $Parts = ($_ -replace '\s{2,}', '|').Split('|')
                    $Sessions += [PSCustomObject]@{
                        Username = $Parts[0].Trim()
                        SessionName = $Parts[1]
                        Id = $Parts[2]
                        State = $Parts[3]
                        IdleTime = $Parts[4]
                        LogonTime = $Parts[5]
                    }
                }
            }
        }
    } catch { }
    if ($Sessions.Count -gt 0) { $Sessions | Export-ToCSV -Path "$Script:CSVFolder\LogonSessions.csv" }
}
#endregion

#region Services and Drivers
function Get-ServicesDetailed {
    Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $SvcPath = ($_.PathName -replace '"','').Split(' ')[0]
        [PSCustomObject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            State = $_.State
            StartMode = $_.StartMode
            PathName = $_.PathName
            StartName = $_.StartName
            ProcessId = $_.ProcessId
            Description = $_.Description
            SHA256Hash = Get-SafeFileHash -FilePath $SvcPath
            IsSigned = (Get-AuthenticodeSignature $SvcPath -ErrorAction SilentlyContinue).Status -eq 'Valid'
        }
    } | Export-ToCSV -Path "$Script:CSVFolder\Services.csv"
}

function Get-DriversDetailed {
    Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            PathName = $_.PathName
            State = $_.State
            StartMode = $_.StartMode
            SHA256Hash = Get-SafeFileHash -FilePath $_.PathName
        }
    } | Export-ToCSV -Path "$Script:CSVFolder\Drivers.csv"
}
#endregion

#region Scheduled Tasks
function Get-ScheduledTasksComplete {
    $Tasks = [System.Collections.Generic.List[PSObject]]::new()
    Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
        $TaskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
        foreach ($Action in $_.Actions) {
            $Tasks.Add([PSCustomObject]@{
                TaskName = $_.TaskName
                TaskPath = $_.TaskPath
                State = $_.State.ToString()
                Author = $_.Author
                Description = $_.Description
                ActionType = $Action.CimClass.CimClassName
                Execute = $Action.Execute
                Arguments = $Action.Arguments
                WorkingDirectory = $Action.WorkingDirectory
                LastRunTime = $TaskInfo.LastRunTime
                NextRunTime = $TaskInfo.NextRunTime
                LastTaskResult = $TaskInfo.LastTaskResult
            })
            # Add to timeline
            if ($TaskInfo.LastRunTime) {
                Add-TimelineEvent -Timestamp $TaskInfo.LastRunTime -Source 'ScheduledTask' -EventType 'TaskRun' -Description $_.TaskName -Details $Action.Execute
            }
        }
    }
    $Tasks | Export-ToCSV -Path "$Script:CSVFolder\ScheduledTasks.csv"
}
#endregion

#region Persistence - Basic
function Get-AutoRunsBasic {
    $AutoRuns = [System.Collections.Generic.List[PSObject]]::new()

    # Registry Run Keys
    $RunKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )

    foreach ($Key in $RunKeys) {
        if (Test-Path $Key) {
            $Props = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
            $Props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $AutoRuns.Add([PSCustomObject]@{
                    Type = 'RegistryRun'
                    Location = $Key
                    Name = $_.Name
                    Value = $_.Value
                })
            }
        }
    }

    # Startup Folders
    $StartupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($Folder in $StartupFolders) {
        if (Test-Path $Folder) {
            Get-ChildItem $Folder -ErrorAction SilentlyContinue | ForEach-Object {
                $AutoRuns.Add([PSCustomObject]@{
                    Type = 'StartupFolder'
                    Location = $Folder
                    Name = $_.Name
                    Value = $_.FullName
                })
            }
        }
    }

    $AutoRuns | Export-ToCSV -Path "$Script:CSVFolder\AutoRuns.csv"
}
#endregion

#region Persistence - Advanced (MITRE ATT&CK aligned)
function Get-AdvancedPersistence {
    $Persistence = [System.Collections.Generic.List[PSObject]]::new()

    # T1546.012 - Image File Execution Options
    $IFEOPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $IFEOPath) {
        Get-ChildItem $IFEOPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($Props.Debugger -or $Props.GlobalFlag) {
                $Persistence.Add([PSCustomObject]@{ Type = 'IFEO'; Target = $_.PSChildName; Value = $Props.Debugger; Technique = 'T1546.012' })
            }
        }
    }

    # T1546.010 - AppInit_DLLs
    $AppInitPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    if (Test-Path $AppInitPath) {
        $AppInit = Get-ItemProperty $AppInitPath -ErrorAction SilentlyContinue
        if ($AppInit.AppInit_DLLs) {
            $Persistence.Add([PSCustomObject]@{ Type = 'AppInit_DLLs'; Target = 'Global'; Value = $AppInit.AppInit_DLLs; Technique = 'T1546.010' })
        }
    }

    # T1547.005 - Security Support Provider
    $LSAPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (Test-Path $LSAPath) {
        $LSA = Get-ItemProperty $LSAPath -ErrorAction SilentlyContinue
        $Persistence.Add([PSCustomObject]@{ Type = 'SSP'; Target = 'LSA'; Value = ($LSA.'Security Packages' -join ','); Technique = 'T1547.005' })
    }

    # T1547.010 - Port Monitors
    $MonitorPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    if (Test-Path $MonitorPath) {
        Get-ChildItem $MonitorPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $Persistence.Add([PSCustomObject]@{ Type = 'PrintMonitor'; Target = $_.PSChildName; Value = $Props.Driver; Technique = 'T1547.010' })
        }
    }

    # T1546.003 - WMI Event Subscription
    try {
        Get-CimInstance -Namespace 'root/subscription' -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object {
            $Persistence.Add([PSCustomObject]@{ Type = 'WMI_Filter'; Target = $_.Name; Value = $_.Query; Technique = 'T1546.003' })
        }
        Get-CimInstance -Namespace 'root/subscription' -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
            $Persistence.Add([PSCustomObject]@{ Type = 'WMI_Consumer'; Target = $_.Name; Value = $_.CommandLineTemplate; Technique = 'T1546.003' })
        }
    } catch { }

    # T1547.001 - Winlogon Keys
    $WinlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path $WinlogonPath) {
        $Winlogon = Get-ItemProperty $WinlogonPath -ErrorAction SilentlyContinue
        @('Shell', 'Userinit', 'Taskman') | ForEach-Object {
            if ($Winlogon.$_) {
                $Persistence.Add([PSCustomObject]@{ Type = 'Winlogon'; Target = $_; Value = $Winlogon.$_; Technique = 'T1547.001' })
            }
        }
    }

    # T1547.002 - Authentication Packages
    if (Test-Path $LSAPath) {
        $LSA = Get-ItemProperty $LSAPath -ErrorAction SilentlyContinue
        $Persistence.Add([PSCustomObject]@{ Type = 'AuthPackages'; Target = 'LSA'; Value = ($LSA.'Authentication Packages' -join ','); Technique = 'T1547.002' })
    }

    # T1546.007 - Netsh Helper DLL
    $NetshPath = 'HKLM:\SOFTWARE\Microsoft\Netsh'
    if (Test-Path $NetshPath) {
        Get-ItemProperty $NetshPath -ErrorAction SilentlyContinue | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $Persistence.Add([PSCustomObject]@{ Type = 'NetshHelper'; Target = $_.Name; Value = $_.Value; Technique = 'T1546.007' })
            }
        }
    }

    # T1547.014 - Active Setup
    $ActiveSetupPath = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
    if (Test-Path $ActiveSetupPath) {
        Get-ChildItem $ActiveSetupPath -ErrorAction SilentlyContinue | ForEach-Object {
            $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($Props.StubPath) {
                $Persistence.Add([PSCustomObject]@{ Type = 'ActiveSetup'; Target = $_.PSChildName; Value = $Props.StubPath; Technique = 'T1547.014' })
            }
        }
    }

    # T1547.004 - Boot Execute
    $BootExecPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    if (Test-Path $BootExecPath) {
        $BootExec = Get-ItemProperty $BootExecPath -ErrorAction SilentlyContinue
        $Persistence.Add([PSCustomObject]@{ Type = 'BootExecute'; Target = 'SessionManager'; Value = ($BootExec.BootExecute -join ','); Technique = 'T1547.004' })
    }

    # T1546.015 - COM Hijacking (sample high-value CLSIDs)
    $COMPaths = @('HKCU:\SOFTWARE\Classes\CLSID', 'HKLM:\SOFTWARE\Classes\CLSID')
    foreach ($COMPath in $COMPaths) {
        if (Test-Path $COMPath) {
            Get-ChildItem $COMPath -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
                $InProc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
                if ($InProc.'(default)' -and $InProc.'(default)' -notmatch 'windows|system32') {
                    $Persistence.Add([PSCustomObject]@{ Type = 'COM_Hijack'; Target = $_.PSChildName; Value = $InProc.'(default)'; Technique = 'T1546.015' })
                }
            }
        }
    }

    $Persistence | Export-ToCSV -Path "$Script:CSVFolder\AdvancedPersistence.csv"
}
#endregion

#region Defender and Security Configuration
function Get-SecurityConfiguration {
    # Defender Configuration
    try {
        $Defender = Get-MpPreference -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            DisableRealtimeMonitoring = $Defender.DisableRealtimeMonitoring
            DisableBehaviorMonitoring = $Defender.DisableBehaviorMonitoring
            DisableScriptScanning = $Defender.DisableScriptScanning
            DisableIOAVProtection = $Defender.DisableIOAVProtection
            DisablePrivacyMode = $Defender.DisablePrivacyMode
            ExclusionPath = ($Defender.ExclusionPath -join '; ')
            ExclusionProcess = ($Defender.ExclusionProcess -join '; ')
            ExclusionExtension = ($Defender.ExclusionExtension -join '; ')
            ExclusionIpAddress = ($Defender.ExclusionIpAddress -join '; ')
            AttackSurfaceReductionRules_Ids = ($Defender.AttackSurfaceReductionRules_Ids -join '; ')
            AttackSurfaceReductionRules_Actions = ($Defender.AttackSurfaceReductionRules_Actions -join '; ')
        } | Export-ToCSV -Path "$Script:CSVFolder\DefenderConfiguration.csv"

        # Threat detections
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object ThreatID, ThreatName, ProcessName,
            DomainUser, DetectionSourceTypeID, Resources, InitialDetectionTime, LastThreatStatusChangeTime |
            Export-ToCSV -Path "$Script:CSVFolder\DefenderThreatHistory.csv"
    } catch { Write-CollectionLog "Defender collection failed" -Level 'WARNING' }

    # Firewall Rules (enabled only)
    Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Description,
        Direction, Action, Profile, Enabled | Export-ToCSV -Path "$Script:CSVFolder\FirewallRules.csv"

    # Audit Policy
    try {
        $AuditPolicy = auditpol /get /category:* /r 2>&1
        if ($AuditPolicy -notmatch "ERROR") {
            $AuditPolicy | ConvertFrom-Csv | Export-ToCSV -Path "$Script:CSVFolder\AuditPolicy.csv"
        }
    } catch { }

    # UAC Settings
    $UACPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if (Test-Path $UACPath) {
        Get-ItemProperty $UACPath -ErrorAction SilentlyContinue | Select-Object EnableLUA, ConsentPromptBehaviorAdmin,
            ConsentPromptBehaviorUser, FilterAdministratorToken | Export-ToCSV -Path "$Script:CSVFolder\UACSettings.csv"
    }

    # BitLocker Status
    try {
        Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, EncryptionMethod,
            VolumeStatus, ProtectionStatus, LockStatus | Export-ToCSV -Path "$Script:CSVFolder\BitLockerStatus.csv"
    } catch { }
}
#endregion

#region LOLBin Artifacts
function Get-LOLBinArtifacts {
    $LOLBins = [System.Collections.Generic.List[PSObject]]::new()

    # CertUtil URL Cache
    $CertUtilCache = $Script:Config.CertUtilCachePath
    if (Test-Path $CertUtilCache) {
        Get-ChildItem $CertUtilCache -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $LOLBins.Add([PSCustomObject]@{
                Type = 'CertUtilCache'
                Path = $_.FullName
                Name = $_.Name
                Size = $_.Length
                LastWriteTime = $_.LastWriteTimeUtc.ToString('o')
            })
        }
    }

    # User-level CertUtil cache
    Get-ChildItem "$($Script:Config.UsersPath)\*\AppData\LocalLow\Microsoft\CryptnetUrlCache" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $LOLBins.Add([PSCustomObject]@{
            Type = 'CertUtilUserCache'
            Path = $_.FullName
            Name = $_.Name
            Size = $_.Length
            LastWriteTime = $_.LastWriteTimeUtc.ToString('o')
        })
    }

    # BitsAdmin Jobs History (from event log)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Bits-Client/Operational'; Id=59,60,61} -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object {
            $LOLBins.Add([PSCustomObject]@{
                Type = 'BITSJob'
                TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
                EventId = $_.Id
                Message = $_.Message.Substring(0, [Math]::Min(500, $_.Message.Length))
            })
        }
    } catch { }

    # MSHTA execution from Prefetch
    Get-ChildItem "$($Script:Config.PrefetchPath)\MSHTA*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
        $LOLBins.Add([PSCustomObject]@{
            Type = 'MshtaPrefetch'
            Path = $_.FullName
            LastWriteTime = $_.LastWriteTimeUtc.ToString('o')
        })
    }

    # Regsvr32 from Prefetch
    Get-ChildItem "$($Script:Config.PrefetchPath)\REGSVR32*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
        $LOLBins.Add([PSCustomObject]@{
            Type = 'Regsvr32Prefetch'
            Path = $_.FullName
            LastWriteTime = $_.LastWriteTimeUtc.ToString('o')
        })
    }

    $LOLBins | Export-ToCSV -Path "$Script:CSVFolder\LOLBinArtifacts.csv"
}
#endregion

#region Execution Artifacts
function Get-PrefetchFiles {
    $PrefetchFolder = New-Item -Path "$Script:OutputFolder\Prefetch" -ItemType Directory -Force
    if (Test-Path $Script:Config.PrefetchPath) {
        Get-ChildItem "$($Script:Config.PrefetchPath)\*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName -Destination $PrefetchFolder.FullName -Force -ErrorAction SilentlyContinue
            Add-TimelineEvent -Timestamp $_.LastWriteTimeUtc -Source 'Prefetch' -EventType 'Execution' -Description $_.BaseName
        }
        Get-ChildItem "$($Script:Config.PrefetchPath)\*.pf" -ErrorAction SilentlyContinue | Select-Object Name,
            @{N='CreationTimeUTC'; E={$_.CreationTimeUtc.ToString('o')}},
            @{N='LastWriteTimeUTC'; E={$_.LastWriteTimeUtc.ToString('o')}},
            Length, @{N='SHA256Hash'; E={Get-SafeFileHash $_.FullName}} |
            Export-ToCSV -Path "$Script:CSVFolder\PrefetchListing.csv"
    }
}

function Get-AmcacheAndShimcache {
    $ExecFolder = New-Item -Path "$Script:OutputFolder\ExecutionArtifacts" -ItemType Directory -Force

    # Amcache
    if (Test-Path $Script:Config.AmcachePath) {
        Copy-LockedFile -SourcePath $Script:Config.AmcachePath -DestinationPath "$($ExecFolder.FullName)\Amcache.hve" | Out-Null
    }

    # RecentFileCache
    if (Test-Path $Script:Config.RecentFileCachePath) {
        Copy-Item $Script:Config.RecentFileCachePath -Destination $ExecFolder.FullName -Force -ErrorAction SilentlyContinue
    }

    # ShimCache (AppCompatCache)
    $ShimPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    if (Test-Path $ShimPath) {
        $ShimData = (Get-ItemProperty $ShimPath -ErrorAction SilentlyContinue).AppCompatCache
        if ($ShimData) {
            [System.IO.File]::WriteAllBytes("$($ExecFolder.FullName)\AppCompatCache.bin", $ShimData)
        }
    }
}

function Get-SRUMAndBITS {
    # SRUM
    if (Test-Path $Script:Config.SRUMPath) {
        $SRUMFolder = New-Item -Path "$Script:OutputFolder\SRUM" -ItemType Directory -Force
        try {
            Stop-Service -Name 'DPS' -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            Copy-LockedFile -SourcePath $Script:Config.SRUMPath -DestinationPath "$($SRUMFolder.FullName)\SRUDB.dat" | Out-Null
            Start-Service -Name 'DPS' -ErrorAction SilentlyContinue
        } catch { Write-CollectionLog "SRUM copy failed" -Level 'WARNING' }
    }

    # BITS
    Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName, JobId, JobState,
        TransferType, BytesTotal, BytesTransferred, FileList, OwnerAccount, CreationTime, ModificationTime |
        Export-ToCSV -Path "$Script:CSVFolder\BITSJobs.csv"

    $BITSDb = "$($Script:Config.BITSPath)\qmgr.db"
    if (Test-Path $BITSDb) {
        $BITSFolder = New-Item -Path "$Script:OutputFolder\BITS" -ItemType Directory -Force
        Copy-LockedFile -SourcePath $BITSDb -DestinationPath "$($BITSFolder.FullName)\qmgr.db" | Out-Null
    }
}

function Get-USNJournal {
    # Attempt to export USN Journal using fsutil
    $USNFolder = New-Item -Path "$Script:OutputFolder\USNJournal" -ItemType Directory -Force
    try {
        $USNInfo = fsutil usn queryjournal C: 2>&1
        $USNInfo | Out-File "$($USNFolder.FullName)\USNJournalInfo.txt" -Encoding UTF8

        # Get recent USN records (last 10000)
        $USNRecords = fsutil usn enumdata 1 0 10000 C: 2>&1
        $USNRecords | Out-File "$($USNFolder.FullName)\USNRecords.txt" -Encoding UTF8
        Write-CollectionLog "USN Journal info collected" -Level 'SUCCESS'
    } catch {
        Write-CollectionLog "USN Journal collection failed: $($_.Exception.Message)" -Level 'WARNING'
    }
}

function Get-MFTInfo {
    # Note: Full $MFT copy requires raw disk access, this collects metadata
    $MFTFolder = New-Item -Path "$Script:OutputFolder\MFT" -ItemType Directory -Force
    try {
        $MFTInfo = fsutil fsinfo ntfsinfo C: 2>&1
        $MFTInfo | Out-File "$($MFTFolder.FullName)\NTFSInfo.txt" -Encoding UTF8
    } catch { }
}
#endregion

#region User Activity Artifacts
function Get-JumpLists {
    $JumpListFolder = New-Item -Path "$Script:OutputFolder\JumpLists" -ItemType Directory -Force

    Get-ChildItem $Script:Config.UsersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $Username = $_.Name
        $AutoDest = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
        $CustomDest = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"

        if (Test-Path $AutoDest) {
            $UserFolder = New-Item -Path "$($JumpListFolder.FullName)\$Username\AutomaticDestinations" -ItemType Directory -Force
            Copy-Item "$AutoDest\*" -Destination $UserFolder.FullName -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $CustomDest) {
            $UserFolder = New-Item -Path "$($JumpListFolder.FullName)\$Username\CustomDestinations" -ItemType Directory -Force
            Copy-Item "$CustomDest\*" -Destination $UserFolder.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    # Create listing
    Get-ChildItem "$($JumpListFolder.FullName)" -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName, Name,
        @{N='LastWriteTimeUTC'; E={$_.LastWriteTimeUtc.ToString('o')}}, Length |
        Export-ToCSV -Path "$Script:CSVFolder\JumpListListing.csv"
}

function Get-LNKFiles {
    $LNKData = [System.Collections.Generic.List[PSObject]]::new()

    Get-ChildItem $Script:Config.UsersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $RecentPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Recent"
        if (Test-Path $RecentPath) {
            Get-ChildItem "$RecentPath\*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $Shell = New-Object -ComObject WScript.Shell
                    $LNK = $Shell.CreateShortcut($_.FullName)
                    $LNKData.Add([PSCustomObject]@{
                        LNKPath = $_.FullName
                        LNKName = $_.Name
                        TargetPath = $LNK.TargetPath
                        Arguments = $LNK.Arguments
                        WorkingDirectory = $LNK.WorkingDirectory
                        IconLocation = $LNK.IconLocation
                        CreationTimeUTC = $_.CreationTimeUtc.ToString('o')
                        LastWriteTimeUTC = $_.LastWriteTimeUtc.ToString('o')
                        LastAccessTimeUTC = $_.LastAccessTimeUtc.ToString('o')
                    })
                } catch { }
            }
        }
    }
    $LNKData | Export-ToCSV -Path "$Script:CSVFolder\LNKFiles.csv"
}

function Get-RDPBitmapCache {
    $RDPCacheFolder = New-Item -Path "$Script:OutputFolder\RDPCache" -ItemType Directory -Force

    Get-ChildItem $Script:Config.UsersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $CachePath = "$($_.FullName)\AppData\Local\Microsoft\Terminal Server Client\Cache"
        if (Test-Path $CachePath) {
            $UserFolder = New-Item -Path "$($RDPCacheFolder.FullName)\$($_.Name)" -ItemType Directory -Force
            Copy-Item "$CachePath\*" -Destination $UserFolder.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    # Listing
    Get-ChildItem $RDPCacheFolder.FullName -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName, Name, Length,
        @{N='LastWriteTimeUTC'; E={$_.LastWriteTimeUtc.ToString('o')}} | Export-ToCSV -Path "$Script:CSVFolder\RDPCacheListing.csv"
}

function Get-PowerShellHistory {
    $PSHistoryFolder = New-Item -Path "$Script:OutputFolder\PowerShellHistory" -ItemType Directory -Force

    # Current session
    Get-History -ErrorAction SilentlyContinue | Select-Object Id, CommandLine, ExecutionStatus,
        @{N='StartTimeUTC'; E={$_.StartExecutionTime.ToUniversalTime().ToString('o')}},
        @{N='EndTimeUTC'; E={$_.EndExecutionTime.ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\PowerShellSessionHistory.csv"

    # PSReadLine history for all users
    Get-ChildItem $Script:Config.UsersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $HistPath = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $HistPath) {
            $UserFolder = New-Item -Path "$($PSHistoryFolder.FullName)\$($_.Name)" -ItemType Directory -Force
            Copy-Item $HistPath -Destination $UserFolder.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-EmailArtifacts {
    # Locate .ost and .pst files
    $EmailFiles = [System.Collections.Generic.List[PSObject]]::new()

    Get-ChildItem $Script:Config.UsersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $OutlookPath = "$($_.FullName)\AppData\Local\Microsoft\Outlook"
        if (Test-Path $OutlookPath) {
            Get-ChildItem $OutlookPath -Include "*.ost", "*.pst" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $EmailFiles.Add([PSCustomObject]@{
                    Path = $_.FullName
                    Name = $_.Name
                    Type = $_.Extension.TrimStart('.')
                    SizeBytes = $_.Length
                    SizeMB = [math]::Round($_.Length / 1MB, 2)
                    LastWriteTimeUTC = $_.LastWriteTimeUtc.ToString('o')
                    User = ($_.FullName -split '\\Users\\')[1].Split('\')[0]
                })
            }
        }
    }

    # Also check common locations
    $CommonLocations = @(
        "C:\Users\*\Documents\Outlook Files",
        "C:\Users\*\AppData\Local\Microsoft\Outlook"
    )
    foreach ($Location in $CommonLocations) {
        Get-ChildItem $Location -Include "*.ost", "*.pst" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not ($EmailFiles | Where-Object { $_.Path -eq $_.FullName })) {
                $EmailFiles.Add([PSCustomObject]@{
                    Path = $_.FullName
                    Name = $_.Name
                    Type = $_.Extension.TrimStart('.')
                    SizeBytes = $_.Length
                    SizeMB = [math]::Round($_.Length / 1MB, 2)
                    LastWriteTimeUTC = $_.LastWriteTimeUtc.ToString('o')
                })
            }
        }
    }

    $EmailFiles | Export-ToCSV -Path "$Script:CSVFolder\EmailArtifacts.csv"
}

function Get-BrowserArtifacts {
    if (-not $CollectBrowsers) { return }

    $BrowserFolder = New-Item -Path "$Script:OutputFolder\Browsers" -ItemType Directory -Force

    Get-ChildItem $Script:Config.UsersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $Username = $_.Name
        $UserPath = $_.FullName

        # Chromium-based browsers
        $ChromiumPaths = @{
            'Chrome' = "$UserPath\AppData\Local\Google\Chrome\User Data"
            'Edge' = "$UserPath\AppData\Local\Microsoft\Edge\User Data"
            'Brave' = "$UserPath\AppData\Local\BraveSoftware\Brave-Browser\User Data"
        }

        foreach ($Browser in $ChromiumPaths.Keys) {
            $BrowserPath = $ChromiumPaths[$Browser]
            if (Test-Path $BrowserPath) {
                Get-ChildItem $BrowserPath -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^(Default|Profile \d+)$' } | ForEach-Object {
                    $ProfileFolder = New-Item -Path "$($BrowserFolder.FullName)\$Username\$Browser\$($_.Name)" -ItemType Directory -Force
                    @('History', 'Preferences', 'Bookmarks', 'Login Data', 'Web Data', 'Cookies', 'Extensions') | ForEach-Object {
                        $FilePath = Join-Path $_.FullName $_
                        if (Test-Path $FilePath) {
                            Copy-Item $FilePath -Destination $ProfileFolder.FullName -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }

        # Firefox
        $FirefoxPath = "$UserPath\AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $FirefoxPath) {
            Get-ChildItem $FirefoxPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $ProfileFolder = New-Item -Path "$($BrowserFolder.FullName)\$Username\Firefox\$($_.Name)" -ItemType Directory -Force
                @('places.sqlite', 'cookies.sqlite', 'formhistory.sqlite', 'logins.json', 'key4.db') | ForEach-Object {
                    $FilePath = Join-Path $_.FullName $_
                    if (Test-Path $FilePath) {
                        Copy-Item $FilePath -Destination $ProfileFolder.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}
#endregion

#region Connected Devices and Network
function Get-ConnectedDevices {
    Get-PnpDevice -ErrorAction SilentlyContinue | Select-Object Class, FriendlyName, InstanceId, Status, Present |
        Export-ToCSV -Path "$Script:CSVFolder\PnPDevices.csv"

    # USB History
    $USBHistory = [System.Collections.Generic.List[PSObject]]::new()
    $USBStorPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (Test-Path $USBStorPath) {
        Get-ChildItem $USBStorPath -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $USBHistory.Add([PSCustomObject]@{
                    DeviceID = $_.PSChildName
                    FriendlyName = $Props.FriendlyName
                    Mfg = $Props.Mfg
                    Service = $Props.Service
                    ContainerID = $Props.ContainerID
                })
            }
        }
    }
    $USBHistory | Export-ToCSV -Path "$Script:CSVFolder\USBHistory.csv"
}

function Get-NetworkSharesAndSMB {
    Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description, CurrentUsers, ShareState |
        Export-ToCSV -Path "$Script:CSVFolder\SMBShares.csv"

    Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists |
        Export-ToCSV -Path "$Script:CSVFolder\SMBSessions.csv"

    Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object FileId, Path, ClientComputerName, ClientUserName |
        Export-ToCSV -Path "$Script:CSVFolder\SMBOpenFiles.csv"
}

function Get-RDPConfiguration {
    # RDP Settings
    $RDPPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if (Test-Path $RDPPath) {
        Get-ItemProperty $RDPPath -ErrorAction SilentlyContinue | Select-Object fDenyTSConnections, fSingleSessionPerUser |
            Export-ToCSV -Path "$Script:CSVFolder\RDPConfiguration.csv"
    }

    # RDP Sessions
    $RDPSessions = @()
    try {
        $QWinsta = qwinsta /server:localhost 2>&1
        if ($QWinsta -notmatch "Error") {
            $QWinsta | Select-Object -Skip 1 | ForEach-Object {
                if ($_ -match '\S') {
                    $Parts = ($_ -replace '\s{2,}', '|').Split('|')
                    $RDPSessions += [PSCustomObject]@{
                        SessionName = $Parts[0].Trim()
                        Username = $Parts[1]
                        Id = $Parts[2]
                        State = $Parts[3]
                    }
                }
            }
        }
    } catch { }
    if ($RDPSessions.Count -gt 0) { $RDPSessions | Export-ToCSV -Path "$Script:CSVFolder\RDPSessions.csv" }
}

function Get-HostsFile {
    $HostsPath = $Script:Config.HostsFilePath
    if (Test-Path $HostsPath) {
        $HostsFolder = New-Item -Path "$Script:OutputFolder\NetworkConfig" -ItemType Directory -Force
        Copy-Item $HostsPath -Destination $HostsFolder.FullName -Force -ErrorAction SilentlyContinue

        # Parse hosts file
        Get-Content $HostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
            $Parts = $_ -split '\s+', 2
            [PSCustomObject]@{
                IPAddress = $Parts[0]
                Hostname = $Parts[1]
            }
        } | Export-ToCSV -Path "$Script:CSVFolder\HostsFileEntries.csv"
    }
}
#endregion

#region Event Logs
function Get-ComprehensiveEventLogs {
    $EventLogFolder = New-Item -Path "$Script:OutputFolder\EventLogs" -ItemType Directory -Force

    # Complete list of security-relevant event logs
    $EventLogs = @(
        'Application', 'Security', 'System',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-PowerShell/Operational',
        'Windows PowerShell',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RDPClient/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-Bits-Client/Operational',
        'Microsoft-Windows-WinRM/Operational',
        'Microsoft-Windows-NTLM/Operational',
        'Microsoft-Windows-DNS-Client/Operational',
        'Microsoft-Windows-AppLocker/EXE and DLL',
        'Microsoft-Windows-AppLocker/MSI and Script',
        'Microsoft-Windows-CodeIntegrity/Operational',
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
        'Microsoft-Windows-Security-Mitigations/KernelMode',
        'Microsoft-Windows-Security-Mitigations/UserMode',
        'Microsoft-Windows-SMBClient/Security',
        'Microsoft-Windows-SMBServer/Security',
        'Microsoft-Windows-CAPI2/Operational',
        'Microsoft-Windows-LSA/Operational',
        'Microsoft-Windows-LDAP-Client/Debug',
        'Microsoft-Windows-Kerberos/Operational',
        'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational',
        'Microsoft-Windows-PrintService/Operational'
    )

    foreach ($LogName in $EventLogs) {
        $SafeName = $LogName -replace '[/\\]', '-'
        $SourcePath = Join-Path $Script:Config.EventLogPath "$($LogName -replace '/', '%4').evtx"
        if (Test-Path $SourcePath) {
            Copy-Item $SourcePath -Destination "$($EventLogFolder.FullName)\$SafeName.evtx" -Force -ErrorAction SilentlyContinue
        }
    }

    # Copy Defender logs
    if (Test-Path $Script:Config.DefenderLogPath) {
        $DefenderFolder = New-Item -Path "$Script:OutputFolder\DefenderLogs" -ItemType Directory -Force
        Get-ChildItem $Script:Config.DefenderLogPath -Filter '*.log' -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item $_.FullName -Destination $DefenderFolder.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-SecurityEventAnalysis {
    $StartDate = (Get-Date).AddDays(-$SearchWindowDays)

    # Critical Security Event IDs
    $SecurityEvents = @{
        # Logon Events
        4624 = 'Successful Logon'
        4625 = 'Failed Logon'
        4634 = 'Logoff'
        4647 = 'User Initiated Logoff'
        4648 = 'Explicit Credentials Logon'
        4672 = 'Special Privileges Assigned'

        # Account Management
        4720 = 'User Account Created'
        4722 = 'User Account Enabled'
        4724 = 'Password Reset Attempt'
        4725 = 'User Account Disabled'
        4726 = 'User Account Deleted'
        4728 = 'User Added to Security Group'
        4732 = 'User Added to Local Group'
        4756 = 'User Added to Universal Group'

        # Kerberos
        4768 = 'Kerberos TGT Request'
        4769 = 'Kerberos Service Ticket'
        4771 = 'Kerberos Pre-Auth Failed'

        # Process
        4688 = 'Process Creation'
        4689 = 'Process Termination'

        # Scheduled Tasks
        4698 = 'Scheduled Task Created'
        4699 = 'Scheduled Task Deleted'
        4700 = 'Scheduled Task Enabled'
        4702 = 'Scheduled Task Updated'

        # Object Access
        4656 = 'Handle Requested'
        4663 = 'Object Access Attempt'
        4670 = 'Permissions Changed'

        # Policy
        1102 = 'Audit Log Cleared'
        4719 = 'Audit Policy Changed'

        # Services
        4697 = 'Service Installed'
        7045 = 'Service Installed (System Log)'

        # Credential Access
        4662 = 'Directory Service Access (DCSync)'
        4742 = 'Computer Account Changed'
    }

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            StartTime = $StartDate
            Id = $SecurityEvents.Keys
        } -MaxEvents $MaxEventLogSize -ErrorAction SilentlyContinue | ForEach-Object {
            $Evt = $_
            [PSCustomObject]@{
                TimeCreatedUTC = $Evt.TimeCreated.ToUniversalTime().ToString('o')
                EventId = $Evt.Id
                EventDescription = $SecurityEvents[$Evt.Id]
                LevelDisplayName = $Evt.LevelDisplayName
                MachineName = $Evt.MachineName
                UserId = $Evt.UserId
                Message = $Evt.Message.Substring(0, [Math]::Min(1000, $Evt.Message.Length))
            }
            # Add significant events to timeline
            if ($Evt.Id -in @(4624, 4625, 4720, 4726, 4728, 4732, 4688, 4698, 1102, 4697)) {
                Add-TimelineEvent -Timestamp $Evt.TimeCreated -Source 'Security' -EventType $SecurityEvents[$Evt.Id] -Description "Event $($Evt.Id)" -Details $Evt.Message.Substring(0, [Math]::Min(200, $Evt.Message.Length))
            }
        }
        $Events | Export-ToCSV -Path "$Script:CSVFolder\SecurityEvents.csv"

        # Summary
        $Events | Group-Object EventId | Select-Object @{N='EventId'; E={$_.Name}}, Count,
            @{N='Description'; E={$SecurityEvents[[int]$_.Name]}} | Sort-Object Count -Descending |
            Export-ToCSV -Path "$Script:CSVFolder\SecurityEventSummary.csv"

    } catch { Write-CollectionLog "Security event collection failed: $($_.Exception.Message)" -Level 'WARNING' }
}

function Get-KerberosAndDCSyncEvents {
    $StartDate = (Get-Date).AddDays(-$SearchWindowDays)

    # Kerberos anomalies
    try {
        # RC4 TGS requests (Kerberoasting indicator)
        $KerberosEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4769
            StartTime = $StartDate
        } -MaxEvents 10000 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match 'Ticket Encryption Type:\s+0x17' # RC4
        } | Select-Object TimeCreated, Id, Message
        $KerberosEvents | Export-ToCSV -Path "$Script:CSVFolder\KerberosRC4Requests.csv"

        # DCSync indicators (4662 with specific GUIDs)
        $DCSyncEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4662
            StartTime = $StartDate
        } -MaxEvents 5000 -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c'
        } | Select-Object TimeCreated, Id, Message
        if ($DCSyncEvents) {
            Write-CollectionLog "ALERT: Potential DCSync activity detected!" -Level 'ALERT'
            $DCSyncEvents | Export-ToCSV -Path "$Script:CSVFolder\DCSyncIndicators.csv"
        }
    } catch { }
}

function Get-AMSIEvents {
    $StartDate = (Get-Date).AddDays(-$SearchWindowDays)

    try {
        # AMSI/Script Block Logging (PowerShell 4104)
        $AMSIEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            Id = 4104
            StartTime = $StartDate
        } -MaxEvents 5000 -ErrorAction SilentlyContinue | Where-Object {
            # Look for suspicious patterns
            $_.Message -match 'AmsiUtils|AmsiInitFailed|amsiContext|SetValue.*Signature|Reflection.*Assembly|FromBase64String|IEX|Invoke-Expression|downloadstring|webclient|bitstransfer|-enc|-e\s+-|bypass'
        } | Select-Object TimeCreated, Id, @{N='ScriptBlock'; E={$_.Message.Substring(0, [Math]::Min(2000, $_.Message.Length))}}

        if ($AMSIEvents) {
            Write-CollectionLog "ALERT: Suspicious PowerShell activity detected in Script Block logs" -Level 'ALERT'
            $AMSIEvents | Export-ToCSV -Path "$Script:CSVFolder\SuspiciousPowerShellScriptBlocks.csv"
        }
    } catch { }
}
#endregion

#region Credential Theft Indicators
function Get-CrashDumps {
    $DumpLocations = @(
        'C:\Windows\MEMORY.DMP',
        'C:\Windows\Minidump',
        'C:\Windows\Temp',
        'C:\Windows\LiveKernelReports'
    )
    Get-ChildItem $Script:Config.UsersPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $DumpLocations += "$($_.FullName)\AppData\Local\Temp"
        $DumpLocations += "$($_.FullName)\AppData\Local\CrashDumps"
    }

    $DumpFiles = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($Location in $DumpLocations) {
        if (Test-Path $Location) {
            Get-ChildItem $Location -Filter '*.dmp' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $IsSuspicious = $_.Name -match 'lsass|procdump|mimikatz|comsvcs|sqldump'
                $DumpFiles.Add([PSCustomObject]@{
                    Path = $_.FullName
                    Name = $_.Name
                    SizeBytes = $_.Length
                    SizeMB = [math]::Round($_.Length / 1MB, 2)
                    CreationTimeUTC = $_.CreationTimeUtc.ToString('o')
                    LastWriteTimeUTC = $_.LastWriteTimeUtc.ToString('o')
                    PossibleCredentialTheft = $IsSuspicious
                })
                if ($IsSuspicious) {
                    Write-CollectionLog "ALERT: Suspicious dump file found: $($_.FullName)" -Level 'ALERT'
                }
            }
        }
    }
    $DumpFiles | Export-ToCSV -Path "$Script:CSVFolder\CrashDumps.csv"
}

function Get-LSASSProtection {
    # Check LSASS protection settings
    $LSASSConfig = @{}

    # RunAsPPL
    $LSAPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (Test-Path $LSAPath) {
        $LSA = Get-ItemProperty $LSAPath -ErrorAction SilentlyContinue
        $LSASSConfig['RunAsPPL'] = $LSA.RunAsPPL
    }

    # Credential Guard
    $DevGuardPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    if (Test-Path $DevGuardPath) {
        $DevGuard = Get-ItemProperty $DevGuardPath -ErrorAction SilentlyContinue
        $LSASSConfig['CredentialGuardEnabled'] = $DevGuard.EnableVirtualizationBasedSecurity
        $LSASSConfig['LsaCfgFlags'] = $DevGuard.LsaCfgFlags
    }

    [PSCustomObject]$LSASSConfig | Export-ToCSV -Path "$Script:CSVFolder\LSASSProtection.csv"
}
#endregion

#region Alternate Data Streams
function Get-AlternateDataStreams {
    $ADSData = [System.Collections.Generic.List[PSObject]]::new()

    # Check common download locations for ADS
    $Locations = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:TEMP",
        "C:\Windows\Temp"
    )

    foreach ($Location in $Locations) {
        if (Test-Path $Location) {
            Get-ChildItem $Location -File -ErrorAction SilentlyContinue | ForEach-Object {
                $Streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }
                foreach ($Stream in $Streams) {
                    $ADSData.Add([PSCustomObject]@{
                        FilePath = $_.FullName
                        StreamName = $Stream.Stream
                        StreamSize = $Stream.Length
                    })
                }
            }
        }
    }

    # Zone.Identifier streams (download origin)
    Get-ChildItem "$env:USERPROFILE\Downloads" -File -ErrorAction SilentlyContinue | ForEach-Object {
        $ZoneStream = Get-Content "$($_.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
        if ($ZoneStream) {
            $ADSData.Add([PSCustomObject]@{
                FilePath = $_.FullName
                StreamName = 'Zone.Identifier'
                StreamContent = ($ZoneStream -join ' | ')
            })
        }
    }

    $ADSData | Export-ToCSV -Path "$Script:CSVFolder\AlternateDataStreams.csv"
}
#endregion

#region Installed Software
function Get-InstalledSoftware {
    $Software = [System.Collections.Generic.List[PSObject]]::new()

    $UninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($Key in $UninstallKeys) {
        Get-ItemProperty $Key -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
            $Software.Add([PSCustomObject]@{
                DisplayName = $_.DisplayName
                DisplayVersion = $_.DisplayVersion
                Publisher = $_.Publisher
                InstallDate = $_.InstallDate
                InstallLocation = $_.InstallLocation
                Source = ($Key -replace '\\\*$', '')
            })
        }
    }

    $Software | Export-ToCSV -Path "$Script:CSVFolder\InstalledSoftware.csv"
}
#endregion

#region Certificate Store
function Get-CertificateStore {
    $Certs = [System.Collections.Generic.List[PSObject]]::new()

    $Stores = @(
        @{Location='LocalMachine'; Store='Root'},
        @{Location='LocalMachine'; Store='CA'},
        @{Location='LocalMachine'; Store='My'},
        @{Location='CurrentUser'; Store='Root'},
        @{Location='CurrentUser'; Store='My'}
    )

    foreach ($Store in $Stores) {
        try {
            Get-ChildItem "Cert:\$($Store.Location)\$($Store.Store)" -ErrorAction SilentlyContinue | ForEach-Object {
                $Certs.Add([PSCustomObject]@{
                    Store = "$($Store.Location)\$($Store.Store)"
                    Subject = $_.Subject
                    Issuer = $_.Issuer
                    Thumbprint = $_.Thumbprint
                    NotBefore = $_.NotBefore.ToString('o')
                    NotAfter = $_.NotAfter.ToString('o')
                    HasPrivateKey = $_.HasPrivateKey
                })
            }
        } catch { }
    }

    $Certs | Export-ToCSV -Path "$Script:CSVFolder\CertificateStore.csv"
}
#endregion

#region Environment Variables
function Get-EnvironmentVariables {
    [System.Environment]::GetEnvironmentVariables('Machine').GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Scope = 'Machine'
            Name = $_.Key
            Value = $_.Value
        }
    } | Export-ToCSV -Path "$Script:CSVFolder\EnvironmentVariables_Machine.csv"

    [System.Environment]::GetEnvironmentVariables('User').GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Scope = 'User'
            Name = $_.Key
            Value = $_.Value
        }
    } | Export-ToCSV -Path "$Script:CSVFolder\EnvironmentVariables_User.csv"
}
#endregion

#region Shadow Copies
function Get-ShadowCopies {
    Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Select-Object ID, InstallDate, VolumeName, DeviceObject, Count,
        @{N='CreationTimeUTC'; E={$_.InstallDate.ToUniversalTime().ToString('o')}} |
        Export-ToCSV -Path "$Script:CSVFolder\ShadowCopies.csv"
}
#endregion

#region Timeline Generation
function Export-Timeline {
    Write-CollectionLog "Generating forensic timeline..." -Level 'INFO'

    # Sort by timestamp and export
    $Script:TimelineEvents | Sort-Object { [datetime]$_.TimestampUTC } |
        Export-Csv -Path "$Script:CSVFolder\ForensicTimeline.csv" -NoTypeInformation -Encoding UTF8

    Write-CollectionLog "Timeline generated with $($Script:TimelineEvents.Count) events" -Level 'SUCCESS'
}
#endregion

#region Evidence Integrity
function Get-EvidenceHashes {
    Write-CollectionLog "Generating evidence manifest with SHA256 hashes..." -Level 'INFO'

    $Hashes = [System.Collections.Generic.List[PSObject]]::new()

    Get-ChildItem $Script:OutputFolder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $Hashes.Add([PSCustomObject]@{
            RelativePath = $_.FullName.Replace($Script:OutputFolder, '.')
            SHA256Hash = Get-SafeFileHash -FilePath $_.FullName
            SizeBytes = $_.Length
            LastWriteTimeUTC = $_.LastWriteTimeUtc.ToString('o')
        })
    }

    $Hashes | Export-Csv -Path "$Script:OutputFolder\EvidenceManifest.csv" -NoTypeInformation -Encoding UTF8

    # Chain of custody document
    @"
================================================================================
                    DFIR COLLECTION - CHAIN OF CUSTODY
================================================================================

Case Name:          $CaseName
Examiner:           $ExaminerName
Collection Start:   $($Script:StartTime.ToUniversalTime().ToString('o')) UTC
Collection End:     $((Get-Date).ToUniversalTime().ToString('o')) UTC
System:             $env:COMPUTERNAME
Domain:             $env:USERDOMAIN

Script Version:     $($Script:Version)
PowerShell:         $($PSVersionTable.PSVersion)
Administrator:      $($Script:IsAdmin)

Total Files:        $($Hashes.Count)
Total Size:         $([math]::Round(($Hashes | Measure-Object -Property SizeBytes -Sum).Sum / 1MB, 2)) MB

Manifest Hash:      $(Get-SafeFileHash "$Script:OutputFolder\EvidenceManifest.csv")

================================================================================
This manifest can be used to verify evidence integrity.
All timestamps are in UTC.
================================================================================
"@ | Out-File "$Script:OutputFolder\CHAIN_OF_CUSTODY.txt" -Encoding UTF8
}
#endregion

#region Main Execution
function Initialize-Collection {
    $Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $Script:OutputFolder = Join-Path $OutputPath "DFIR-$env:COMPUTERNAME-$(Get-Date -Format 'yyyy-MM-dd_HHmmss')"
    $Script:CSVFolder = Join-Path $Script:OutputFolder 'CSV_Results'
    $Script:LogFile = Join-Path $Script:OutputFolder 'Collection.log'

    New-Item -Path $Script:OutputFolder -ItemType Directory -Force | Out-Null
    New-Item -Path $Script:CSVFolder -ItemType Directory -Force | Out-Null

    Write-CollectionLog "========================================" -Level 'INFO'
    Write-CollectionLog "DFIR Collection Starting - v$($Script:Version)" -Level 'INFO'
    Write-CollectionLog "Case: $CaseName" -Level 'INFO'
    Write-CollectionLog "Examiner: $ExaminerName" -Level 'INFO'
    Write-CollectionLog "Administrator: $Script:IsAdmin" -Level 'INFO'
    Write-CollectionLog "Output: $Script:OutputFolder" -Level 'INFO'
    Write-CollectionLog "========================================" -Level 'INFO'

    if (-not $Script:IsAdmin) {
        Write-CollectionLog "WARNING: Limited collection without admin privileges" -Level 'WARNING'
    }

    New-CollectionMetadata
}

function Invoke-FullCollection {
    # Phase 0: Memory (most volatile)
    if (-not $SkipVolatile) {
        Write-CollectionLog "=== Phase 0: Memory Acquisition ===" -Level 'INFO'
        Invoke-SafeCollection -CollectionBlock { Get-MemoryDump } -ArtifactName 'Memory Dump' -RequiresAdmin
    }

    # Phase 1: Volatile Data
    if (-not $SkipVolatile) {
        Write-CollectionLog "=== Phase 1: Volatile Data ===" -Level 'INFO'
        Invoke-SafeCollection -CollectionBlock { Get-SystemDateTime } -ArtifactName 'System DateTime'
        Invoke-SafeCollection -CollectionBlock { Get-NetworkStateVolatile } -ArtifactName 'Network State'
        Invoke-SafeCollection -CollectionBlock { Get-RunningProcesses } -ArtifactName 'Running Processes'
        Invoke-SafeCollection -CollectionBlock { Get-LoadedDLLs } -ArtifactName 'Loaded DLLs'
        Invoke-SafeCollection -CollectionBlock { Get-NamedPipes } -ArtifactName 'Named Pipes'
        Invoke-SafeCollection -CollectionBlock { Get-Handles } -ArtifactName 'Open Handles' -RequiresAdmin
    }

    # Phase 2: User Information
    Write-CollectionLog "=== Phase 2: User Information ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-LocalUserAccounts } -ArtifactName 'Local Users'
    Invoke-SafeCollection -CollectionBlock { Get-LogonSessions } -ArtifactName 'Logon Sessions'

    # Phase 3: Services and Drivers
    Write-CollectionLog "=== Phase 3: Services and Drivers ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-ServicesDetailed } -ArtifactName 'Services'
    Invoke-SafeCollection -CollectionBlock { Get-DriversDetailed } -ArtifactName 'Drivers'
    Invoke-SafeCollection -CollectionBlock { Get-ScheduledTasksComplete } -ArtifactName 'Scheduled Tasks'

    # Phase 4: Persistence
    Write-CollectionLog "=== Phase 4: Persistence Mechanisms ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-AutoRunsBasic } -ArtifactName 'AutoRuns'
    Invoke-SafeCollection -CollectionBlock { Get-AdvancedPersistence } -ArtifactName 'Advanced Persistence'

    # Phase 5: Security Configuration
    Write-CollectionLog "=== Phase 5: Security Configuration ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-SecurityConfiguration } -ArtifactName 'Security Config'
    Invoke-SafeCollection -CollectionBlock { Get-LOLBinArtifacts } -ArtifactName 'LOLBin Artifacts'

    # Phase 6: Execution Artifacts
    Write-CollectionLog "=== Phase 6: Execution Artifacts ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-PrefetchFiles } -ArtifactName 'Prefetch' -RequiresAdmin
    Invoke-SafeCollection -CollectionBlock { Get-AmcacheAndShimcache } -ArtifactName 'Amcache/ShimCache' -RequiresAdmin
    Invoke-SafeCollection -CollectionBlock { Get-SRUMAndBITS } -ArtifactName 'SRUM/BITS' -RequiresAdmin
    Invoke-SafeCollection -CollectionBlock { Get-USNJournal } -ArtifactName 'USN Journal' -RequiresAdmin
    Invoke-SafeCollection -CollectionBlock { Get-MFTInfo } -ArtifactName 'MFT Info' -RequiresAdmin

    # Phase 7: User Activity
    Write-CollectionLog "=== Phase 7: User Activity ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-JumpLists } -ArtifactName 'Jump Lists'
    Invoke-SafeCollection -CollectionBlock { Get-LNKFiles } -ArtifactName 'LNK Files'
    Invoke-SafeCollection -CollectionBlock { Get-RDPBitmapCache } -ArtifactName 'RDP Cache'
    Invoke-SafeCollection -CollectionBlock { Get-PowerShellHistory } -ArtifactName 'PowerShell History'
    Invoke-SafeCollection -CollectionBlock { Get-EmailArtifacts } -ArtifactName 'Email Artifacts'
    Invoke-SafeCollection -CollectionBlock { Get-BrowserArtifacts } -ArtifactName 'Browser Artifacts'

    # Phase 8: Network and Devices
    Write-CollectionLog "=== Phase 8: Network and Devices ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-ConnectedDevices } -ArtifactName 'Connected Devices'
    Invoke-SafeCollection -CollectionBlock { Get-NetworkSharesAndSMB } -ArtifactName 'Network Shares'
    Invoke-SafeCollection -CollectionBlock { Get-RDPConfiguration } -ArtifactName 'RDP Configuration'
    Invoke-SafeCollection -CollectionBlock { Get-HostsFile } -ArtifactName 'Hosts File'

    # Phase 9: Event Logs
    Write-CollectionLog "=== Phase 9: Event Logs ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-ComprehensiveEventLogs } -ArtifactName 'Event Log Files' -RequiresAdmin
    Invoke-SafeCollection -CollectionBlock { Get-SecurityEventAnalysis } -ArtifactName 'Security Events' -RequiresAdmin
    Invoke-SafeCollection -CollectionBlock { Get-KerberosAndDCSyncEvents } -ArtifactName 'Kerberos/DCSync Events' -RequiresAdmin
    Invoke-SafeCollection -CollectionBlock { Get-AMSIEvents } -ArtifactName 'AMSI/ScriptBlock Events' -RequiresAdmin

    # Phase 10: Credential Theft Detection
    Write-CollectionLog "=== Phase 10: Credential Theft Detection ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-CrashDumps } -ArtifactName 'Crash Dumps'
    Invoke-SafeCollection -CollectionBlock { Get-LSASSProtection } -ArtifactName 'LSASS Protection'

    # Phase 11: Additional Artifacts
    Write-CollectionLog "=== Phase 11: Additional Artifacts ===" -Level 'INFO'
    Invoke-SafeCollection -CollectionBlock { Get-AlternateDataStreams } -ArtifactName 'Alternate Data Streams'
    Invoke-SafeCollection -CollectionBlock { Get-InstalledSoftware } -ArtifactName 'Installed Software'
    Invoke-SafeCollection -CollectionBlock { Get-CertificateStore } -ArtifactName 'Certificate Store'
    Invoke-SafeCollection -CollectionBlock { Get-EnvironmentVariables } -ArtifactName 'Environment Variables'
    Invoke-SafeCollection -CollectionBlock { Get-ShadowCopies } -ArtifactName 'Shadow Copies'
}

function Complete-Collection {
    # Save errors
    if ($Script:CollectionErrors.Count -gt 0) {
        $Script:CollectionErrors | Export-Csv "$Script:CSVFolder\CollectionErrors.csv" -NoTypeInformation -Encoding UTF8
    }

    # Statistics
    [PSCustomObject]@{
        TotalArtifacts = $Script:CollectionStats.TotalArtifacts
        Successful = $Script:CollectionStats.SuccessfulCollections
        Failed = $Script:CollectionStats.FailedCollections
        Skipped = $Script:CollectionStats.SkippedCollections
        SuccessRate = [math]::Round(($Script:CollectionStats.SuccessfulCollections / [Math]::Max($Script:CollectionStats.TotalArtifacts, 1)) * 100, 2)
    } | Export-Csv "$Script:CSVFolder\CollectionStatistics.csv" -NoTypeInformation -Encoding UTF8

    # Timeline
    Export-Timeline

    # Metadata and integrity
    Save-CollectionMetadata
    Get-EvidenceHashes

    # Create archive
    $ZipPath = "$Script:OutputFolder.zip"
    Write-CollectionLog "Creating archive: $ZipPath" -Level 'INFO'
    Compress-Archive -Path $Script:OutputFolder -DestinationPath $ZipPath -Force

    Write-CollectionLog "========================================" -Level 'SUCCESS'
    Write-CollectionLog "COLLECTION COMPLETE" -Level 'SUCCESS'
    Write-CollectionLog "Total: $($Script:CollectionStats.TotalArtifacts) | Success: $($Script:CollectionStats.SuccessfulCollections) | Failed: $($Script:CollectionStats.FailedCollections) | Skipped: $($Script:CollectionStats.SkippedCollections)" -Level 'INFO'
    Write-CollectionLog "Output: $Script:OutputFolder" -Level 'INFO'
    Write-CollectionLog "Archive: $ZipPath" -Level 'INFO'
    Write-CollectionLog "========================================" -Level 'SUCCESS'

    return $ZipPath
}

# Execute
try {
    Initialize-Collection
    Invoke-FullCollection
    Complete-Collection
}
catch {
    Write-CollectionLog "CRITICAL ERROR: $($_.Exception.Message)" -Level 'ERROR'
    throw
}
#endregion
