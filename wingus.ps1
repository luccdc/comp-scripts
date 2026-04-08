<#
.SYNOPSIS
    Robust Windows Hardening Script for Competitions (CyberPatriot/CCDC)
.DESCRIPTION
    This script performs baseline security hardening on Windows 10, 11, Server 2019, and Server 2022.
    It includes policy backups, password/lockout policies, disabling default accounts, and media file identification.
    It also thoroughly scans for non-default/suspicious processes, services, tasks, files, and configurations.
.NOTES
    Ensure you test before running in a production environment.
    Author: Gemini CLI
#>

[CmdletBinding()]
param()

#Requires -RunAsAdministrator

# Explicit check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as an Administrator. Please launch PowerShell as Administrator and try again."
    Exit
}

# Interactive prompts
$DisableRDPResponse = Read-Host "Disable Remote Desktop (RDP)? [y/N]"
$DisableRDP = $DisableRDPResponse -eq 'y' -or $DisableRDPResponse -eq 'Y'

$InstallGeminiCLIResponse = Read-Host "Install Gemini CLI? [y/N]"
$InstallGeminiCLI = $InstallGeminiCLIResponse -eq 'y' -or $InstallGeminiCLIResponse -eq 'Y'

$LogDir = "C:\HardeningLogs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir "Hardening_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Log {
    param([string]$Message)
    $Stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Line = "[$Stamp] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line
}

Write-Log "=== Starting Windows Hardening Script ==="
Write-Log "OS Version: $([Environment]::OSVersion.VersionString)"

# ====================================================================
# 1. Backup Security Policies
# ====================================================================
$BackupPath = Join-Path $LogDir "secpol_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').inf"
Write-Log "Backing up current security policies to $BackupPath"

secedit /export /cfg $BackupPath /quiet
if ($LASTEXITCODE -eq 0) {
    Write-Log "Security policy backup successful."
} else {
    Write-Log "WARNING: Security policy backup may have completed with warnings."
}

# ====================================================================
# 2. Disable Default Accounts
# ====================================================================
Write-Log "Locating and disabling default accounts (using SIDs to catch renamed accounts)..."

# Built-in Administrator (SID ends in -500)
$BuiltInAdmin = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-21-*-500" }
if ($BuiltInAdmin) {
    if ($BuiltInAdmin.Enabled) {
        Write-Log "Disabling built-in Administrator account: $($BuiltInAdmin.Name)"
        Disable-LocalUser -SID $BuiltInAdmin.SID
    } else {
        Write-Log "Built-in Administrator account ($($BuiltInAdmin.Name)) is already disabled."
    }
} else {
    Write-Log "Could not locate built-in Administrator account."
}

# Built-in Guest (SID ends in -501)
$BuiltInGuest = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-21-*-501" }
if ($BuiltInGuest) {
    if ($BuiltInGuest.Enabled) {
        Write-Log "Disabling built-in Guest account: $($BuiltInGuest.Name)"
        Disable-LocalUser -SID $BuiltInGuest.SID
    } else {
        Write-Log "Built-in Guest account ($($BuiltInGuest.Name)) is already disabled."
    }
} else {
    Write-Log "Could not locate built-in Guest account."
}

# ====================================================================
# 2.5. Windows Update Service
# ====================================================================
Write-Log "Configuring Windows Update service..."
try {
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Log "Windows Update service set to Automatic and started."
} catch {
    Write-Log "WARNING: Failed to configure Windows Update service: $_"
}

# ====================================================================
# 3. Apply Security Policies (Password, Lockout, Auditing)
# ====================================================================
Write-Log "Configuring Password, Account Lockout, and Audit Policies..."

$SecPolInf = "$env:TEMP\secpol_update.inf"
$SecPolDb = "$env:TEMP\secpol_update.sdb"

# 0 = No auditing, 1 = Success, 2 = Failure, 3 = Success and Failure
$SecPolContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO$"
Revision=1
[System Access]
MinimumPasswordAge = 10
MaximumPasswordAge = 90
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3
[Privilege Rights]
SeShutdownPrivilege = *S-1-5-32-544
SeSystemtimePrivilege = *S-1-5-32-544, *S-1-5-19
SeNetworkLogonRight = *S-1-5-32-544, *S-1-5-32-545
SeRemoteInteractiveLogonRight = *S-1-5-32-544
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\RunAsPPL=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\SubmitControl=4,0
MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\AutoAdminLogon=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,3
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EncryptData=4,1
"@

$SecPolContent | Out-File -FilePath $SecPolInf -Encoding Unicode

# Apply the template using secedit
secedit /configure /db "$SecPolDb" /cfg "$SecPolInf" /quiet
if ($LASTEXITCODE -eq 0) {
    Write-Log "Security policies applied successfully."
} else {
    Write-Log "WARNING: Security policies applied with warnings or errors. Check Windows Event Logs."
}

# Force a Group Policy update to refresh settings
Write-Log "Refreshing Group Policy..."
gpupdate /force /wait:0

# Configure Advanced Auditing
Write-Log "Configuring Advanced Auditing (Success and Failure for all categories)..."
auditpol /set /category:"*" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Log "Advanced auditing policies applied successfully."
} else {
    Write-Log "WARNING: Failed to apply some advanced auditing policies."
}

# Cleanup temp files
Remove-Item -Path $SecPolInf -Force -ErrorAction SilentlyContinue
Remove-Item -Path $SecPolDb -Force -ErrorAction SilentlyContinue

# ====================================================================
# 4. Identify Media Files
# ====================================================================
$MediaExtensions = @("*.mp3", "*.mp4", "*.avi", "*.mov", "*.mkv", "*.wav", "*.jpg", "*.jpeg", "*.png", "*.gif")
# Focusing on C:\Users as searching the entire C:\ drive includes many standard Windows system media files.
$SearchPath = "C:\Users" 
$MediaReport = Join-Path $LogDir "Media_Files_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

Write-Log "Scanning for media files in $SearchPath (Extensions: $($MediaExtensions -join ', '))..."

# Using ErrorAction SilentlyContinue to gracefully handle 'Access Denied' on restricted folders (like ntuser.dat etc.)
$FoundMedia = Get-ChildItem -Path $SearchPath -Include $MediaExtensions -Recurse -File -ErrorAction SilentlyContinue |
              Select-Object FullName, Extension, @{Name="Size(MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}, LastWriteTime

if ($FoundMedia) {
    Write-Log "Found $($FoundMedia.Count) media files. Exporting report to $MediaReport"
    $FoundMedia | Export-Csv -Path $MediaReport -NoTypeInformation
} else {
    Write-Log "No media files found in $SearchPath."
}

# ====================================================================
# 5. Identify Non-Default / Suspicious Artifacts
# ====================================================================
Write-Log "Scanning for non-default processes, services, tasks, and configurations..."
$ArtifactReport = Join-Path $LogDir "Suspicious_Artifacts_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Write-Artifact {
    param([string]$Header, [array]$Data)
    Add-Content -Path $ArtifactReport -Value "`r`n====================================================================="
    Add-Content -Path $ArtifactReport -Value " $Header"
    Add-Content -Path $ArtifactReport -Value "====================================================================="
    if ($Data -and $Data.Count -gt 0) {
        $Data | Format-Table -AutoSize | Out-String | Add-Content -Path $ArtifactReport
    } else {
        Add-Content -Path $ArtifactReport -Value "None found.`r`n"
    }
}

# 5.1 Non-Default Processes
Write-Log "  -> Analyzing running processes..."
$SuspiciousProcesses = Get-Process | Where-Object {
    $_.Path -and ($_.FileVersionInfo.CompanyName -notmatch "Microsoft Corporation") -and ($_.Path -notmatch "VMware|VirtualBox")
} | Select-Object Id, ProcessName, Path, @{Name="Company";Expression={$_.FileVersionInfo.CompanyName}}
Write-Artifact "Non-Microsoft Processes" $SuspiciousProcesses

# 5.2 Non-Default Services
Write-Log "  -> Analyzing services..."
$Services = Get-CimInstance Win32_Service | Where-Object { $_.PathName }
$SuspiciousServices = @()
foreach ($Service in $Services) {
    # Extract path from potentially quoted string with arguments
    $Path = $Service.PathName
    if ($Path -match '^"(.*?)"') { $Path = $matches[1] }
    else { $Path = ($Path -split ' ')[0] }
    
    if (Test-Path $Path) {
        $Company = (Get-Item $Path -ErrorAction SilentlyContinue).VersionInfo.CompanyName
        if ($Company -notmatch "Microsoft Corporation" -and $Company -notmatch "VMware|VirtualBox") {
            $SuspiciousServices += [PSCustomObject]@{
                Name = $Service.Name
                DisplayName = $Service.DisplayName
                State = $Service.State
                StartMode = $Service.StartMode
                Company = $Company
                Path = $Path
            }
        }
    } else {
        $SuspiciousServices += [PSCustomObject]@{
            Name = $Service.Name
            DisplayName = $Service.DisplayName
            State = $Service.State
            StartMode = $Service.StartMode
            Company = "PATH NOT FOUND"
            Path = $Service.PathName
        }
    }
}
Write-Artifact "Non-Microsoft / Suspicious Services" $SuspiciousServices

# 5.3 Non-Default Scheduled Tasks
Write-Log "  -> Analyzing scheduled tasks..."
$SuspiciousTasks = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch "^\\Microsoft\\" -and $_.State -ne "Disabled"
} | Select-Object TaskName, TaskPath, State, Author
Write-Artifact "Non-Microsoft Scheduled Tasks" $SuspiciousTasks

# 5.4 Non-Default Startup Items
Write-Log "  -> Analyzing startup items..."
$StartupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
Write-Artifact "All Startup Items (Review Manually)" $StartupItems

# 5.5 Active Network Connections from Non-Microsoft Processes
Write-Log "  -> Analyzing network connections..."
$NetStat = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' -or $_.State -eq 'Listen' }
$SuspiciousNet = @()
foreach ($Conn in $NetStat) {
    $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
    if ($Proc -and $Proc.Path -and ($Proc.FileVersionInfo.CompanyName -notmatch "Microsoft Corporation")) {
        $SuspiciousNet += [PSCustomObject]@{
            LocalAddress = $Conn.LocalAddress
            LocalPort = $Conn.LocalPort
            RemoteAddress = $Conn.RemoteAddress
            RemotePort = $Conn.RemotePort
            State = $Conn.State
            ProcessName = $Proc.ProcessName
            Company = $Proc.FileVersionInfo.CompanyName
        }
    }
}
Write-Artifact "Network Connections (Non-Microsoft Processes)" ($SuspiciousNet | Sort-Object -Unique ProcessName, LocalPort)

# 5.6 Suspicious Executables in Common Hideouts
Write-Log "  -> Analyzing files in high-risk directories (Temp, Users, ProgramData)..."
$HighRiskDirs = @("C:\Users", "C:\ProgramData", "C:\Windows\Temp")
$SuspiciousFileExtensions = @("*.exe", "*.bat", "*.ps1", "*.vbs", "*.dll")
$SuspiciousFiles = @()
foreach ($Dir in $HighRiskDirs) {
    if (Test-Path $Dir) {
        $SuspiciousFiles += Get-ChildItem -Path $Dir -Include $SuspiciousFileExtensions -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { 
                $_.FullName -notmatch "AppData\\Local\\Microsoft" -and 
                $_.FullName -notmatch "VMware" 
            } | Select-Object FullName, Length, LastWriteTime
    }
}
Write-Artifact "Executables/Scripts in High-Risk Directories" $SuspiciousFiles

# 5.7 User Accounts (Configurations)
Write-Log "  -> Analyzing active user accounts..."
$DefaultUsers = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")
$ActiveUsers = Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin $DefaultUsers } | Select-Object Name, FullName, Description, LastLogon
Write-Artifact "Active Non-Default Local Users" $ActiveUsers

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource
Write-Artifact "Members of Local Administrators Group" $LocalAdmins

# ====================================================================
# 6. SMB Hardening (with Backup)
# ====================================================================
Write-Log "Configuring SMB Hardening..."
$SMBBackup = Join-Path $LogDir "SMB_Config_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
try {
    Get-SmbServerConfiguration | Export-CliXml -Path $SMBBackup
    Write-Log "SMB Configuration backed up to $SMBBackup"

    # Hardening Steps (Registry-based via secedit in Section 3)
    # 1. Require Message Signing (Server and Client)
    # 2. Encrypt Data (Server)
    
    # Disable SMBv1
    if (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Where-Object { $_.State -eq 'Enabled' }) {
        Write-Log "Disabling SMBv1 Protocol..."
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    } else {
        Write-Log "SMBv1 is already disabled or not present."
    }
    Write-Log "SMB hardening applied successfully."
} catch {
    Write-Log "WARNING: Failed to apply some SMB hardening settings: $_"
}

# ====================================================================
# 7. Remote Desktop Management
# ====================================================================
if ($DisableRDP) {
    Write-Log "Disabling Remote Desktop (RDP)..."
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1
    
    # Disable Firewall Rules
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Disable-NetFirewallRule
    Write-Log "RDP has been disabled and firewall rules closed."
}

# ====================================================================
# 8. Install Gemini CLI
# ====================================================================
if ($InstallGeminiCLI) {
    Write-Log "Attempting to install Gemini CLI..."
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Write-Log "Found npm. Running global installation..."
        npm install -g @google/gemini-cli
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Gemini CLI installed successfully."
        } else {
            Write-Log "WARNING: npm install returned a non-zero exit code."
        }
    } else {
        Write-Log "WARNING: Node.js/npm not found. Please install Node.js first to use Gemini CLI."
    }
}

# ====================================================================
# 9. Report Configured Group Policies
# ====================================================================
Write-Log "Reporting configured Group Policy settings (excluding 'Not Configured')..."

# 9.1 Security Policies (secpol.msc / Security Settings)
# We use the backup created in Section 1
if (Test-Path $BackupPath) {
    Write-Log "--- Configured Security Policies ---"
    Get-Content $BackupPath | Where-Object { 
        $_ -match '=' -and 
        $_ -notmatch '^\[Version\]' -and 
        $_ -notmatch '^signature=' -and 
        $_ -notmatch '^Revision=' 
    } | ForEach-Object {
        Write-Log "  [Security] $_"
    }
}

# 9.2 Administrative Templates (Registry-based Policies)
Write-Log "--- Configured Administrative Templates (Registry) ---"
$PolicyRegistryPaths = @(
    "HKLM:\SOFTWARE\Policies",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    "HKCU:\SOFTWARE\Policies",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
)

foreach ($path in $PolicyRegistryPaths) {
    if (Test-Path $path) {
        # Check root properties first
        $rootProps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($rootProps) {
            foreach ($prop in $rootProps.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    Write-Log "  [Registry] $path\$($prop.Name) = $($prop.Value)"
                }
            }
        }
        
        # Check subkeys
        Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $subKeyPath = $_.PSPath
            $properties = Get-ItemProperty -Path $subKeyPath -ErrorAction SilentlyContinue
            foreach ($prop in $properties.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    Write-Log "  [Registry] $($_.Name)\$($prop.Name) = $($prop.Value)"
                }
            }
        }
    }
}

Write-Log "Suspicious artifacts report generated at: `$ArtifactReport"

# ====================================================================
# 10. General System Hardening (Adapted from baseline)
# ====================================================================
Write-Log "Applying general system hardening rules..."

# Firewall Base Rules
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Disable-NetFirewallRule -ErrorAction SilentlyContinue

# Uninstall Commonly Unauthorized/Risky Software
$UninstallApps = @("360安全卫士", "AnyDesk", "CCleaner")
foreach ($App in $UninstallApps) {
    Get-CimInstance -Class Win32_Product -Filter "Name like '%$App%'" -ErrorAction SilentlyContinue | Invoke-CimMethod -MethodName Uninstall -ErrorAction SilentlyContinue
}

# Remove General Known Malware Paths
$GeneralMalwarePaths = @(
    "C:\HideUL",
    "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.23080.2006-0\MpBypasser.dll",
    "C:\Windows\System32\drivers\WinDivert64.sys",
    "C:\Windows\SystemResources\¢◎₥฿Ꭵ₦Ꮛ.ps1"
)
foreach ($Path in $GeneralMalwarePaths) {
    if (Test-Path $Path) { Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

# General Registry Hardening
$RegistryFixes = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="NoConnectedUser"; Value=3; Type="DWord"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"; Name="CrashDumpEnabled"; Value=0; Type="DWord"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"; Name="RestrictDriverInstallationToAdministrators"; Value=1; Type="DWord"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableSmartScreen"; Value=1; Type="DWord"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="ShellSmartScreenLevel"; Value="Block"; Type="String"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DisableLockScreenAppNotifications"; Value=1; Type="DWord"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"; Value=0; Type="DWord"},
    @{Path="HKLM:\Software\Policies\Microsoft\WindowsStore"; Name="RemoveWindowsStore"; Value=1; Type="DWord"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"; Name="UEFISecureBootEnabled"; Value=1; Type="DWord"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="SecurityLayer"; Value=2; Type="DWord"},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fEncryptRPCTraffic"; Value=1; Type="DWord"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"; Name="Enabled"; Value=1; Type="DWord"}
)
foreach ($Fix in $RegistryFixes) {
    if (!(Test-Path $Fix.Path)) { New-Item -Path $Fix.Path -Force | Out-Null }
    Set-ItemProperty -Path $Fix.Path -Name $Fix.Name -Value $Fix.Value -Type $Fix.Type -ErrorAction SilentlyContinue
}

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -ErrorAction SilentlyContinue

# Disable Autoplay for current user
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord -ErrorAction SilentlyContinue

# Apply Bitlocker if capable
Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector -ErrorAction SilentlyContinue

# Ensure Core Services are running
$ServicesToStart = @("wuauserv", "WaaSMedicSvc", "EventLog")
foreach ($Svc in $ServicesToStart) {
    Set-Service -Name $Svc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Svc -ErrorAction SilentlyContinue
}

# Remove Insecure Windows Features
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart -ErrorAction SilentlyContinue

# Additional SecPol edits (General)
$SecPolUpdateAdditions = "$env:TEMP\secpol_general.inf"
$SecPolContentAdd = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO$"
Revision=1
[Privilege Rights]
SeDenyInteractiveLogonRight = *S-1-5-32-555
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\allownullsessionfallback=4,0
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization=4,1
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0
"@
$SecPolContentAdd | Out-File -FilePath $SecPolUpdateAdditions -Encoding Unicode
secedit /configure /db "$env:TEMP\secpol_general.sdb" /cfg "$SecPolUpdateAdditions" /quiet
gpupdate /force /wait:0

Write-Log "=== Windows Hardening Script Completed ==="
Write-Log "Review logs and reports at: `$LogDir"
