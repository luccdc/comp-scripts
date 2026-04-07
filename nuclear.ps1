<#
.SYNOPSIS
    Sets all boolean local security policies to Enabled or Disabled.
.DESCRIPTION
    This script exports the current local security policy, modifies all boolean
    [Registry Values] (Security Options), [Event Audit] policies, and boolean
    [System Access] policies to either Enabled (1/3/4,1) or Disabled (0/4,0),
    and then applies the modified policy.
.EXAMPLE
    .\nuclear.ps1 -State Enabled
.EXAMPLE
    .\nuclear.ps1 -State Disabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Enabled", "Disabled")]
    [string]$State
)

#Requires -RunAsAdministrator

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as an Administrator."
    Exit
}

$exportPath = "$env:TEMP\secpol_export.inf"
$importPath = "$env:TEMP\secpol_import.inf"
$dbPath = "$env:TEMP\secpol.sdb"

Write-Host "[*] Exporting current security policy to $exportPath..."
secedit /export /cfg $exportPath /quiet

if (-not (Test-Path $exportPath)) {
    Write-Error "Failed to export security policy."
    exit
}

Write-Host "[*] Parsing and modifying policy to state: $State..."
# Read the file. It is typically Unicode (UTF-16 LE). Get-Content handles this.
$lines = Get-Content $exportPath

$newLines = @()
$inRegistry = $false
$inAudit = $false
$inSystemAccess = $false

# 4,1 = Enabled, 4,0 = Disabled for DWORD Registry Values
$regVal = if ($State -eq "Enabled") { "4,1" } else { "4,0" }
# 3 = Success and Failure, 0 = No Auditing
$auditVal = if ($State -eq "Enabled") { "3" } else { "0" }
# 1 = Enabled, 0 = Disabled for boolean System Access policies
$boolVal = if ($State -eq "Enabled") { "1" } else { "0" }

$modifiedCount = 0

foreach ($line in $lines) {
    # Check section headers
    if ($line -match '^\[Registry Values\]') {
        $inRegistry = $true; $inAudit = $false; $inSystemAccess = $false
        $newLines += $line
        continue
    }
    if ($line -match '^\[Event Audit\]') {
        $inAudit = $true; $inRegistry = $false; $inSystemAccess = $false
        $newLines += $line
        continue
    }
    if ($line -match '^\[System Access\]') {
        $inSystemAccess = $true; $inAudit = $false; $inRegistry = $false
        $newLines += $line
        continue
    }
    if ($line -match '^\[') {
        $inRegistry = $false; $inAudit = $false; $inSystemAccess = $false
        $newLines += $line
        continue
    }

    $originalLine = $line

    # Modify lines based on current section
    if ($inRegistry) {
        # Match values that end in exactly =4,0 or =4,1 (ignoring spaces)
        if ($line -match '=(4,0|4,1)\s*$') {
            $line = $line -replace '=(4,0|4,1)\s*$', "=$regVal"
        }
    }
    elseif ($inAudit) {
        # Match audit values 0, 1, 2, or 3
        if ($line -match '=(0|1|2|3)\s*$') {
            $line = $line -replace '=(0|1|2|3)\s*$', "=$auditVal"
        }
    }
    elseif ($inSystemAccess) {
        # Modify known boolean values in System Access
        if ($line -match '^(RequireLogonToChangePassword|ForceLogoffWhenHourExpire|ClearTextPassword)\s*=\s*(0|1)\s*$') {
            $line = $line -replace '=(0|1)\s*$', "=$boolVal"
        }
    }

    if ($originalLine -ne $line) {
        $modifiedCount++
    }

    $newLines += $line
}

Write-Host "[*] Modified $modifiedCount policy settings."

Write-Host "[*] Writing modified policy to $importPath..."
$newLines | Out-File -FilePath $importPath -Encoding Unicode

Write-Host "[*] Applying new security policy..."
secedit /configure /db $dbPath /cfg $importPath /quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Security policy applied successfully." -ForegroundColor Green
} else {
    Write-Host "[-] Security policy applied with warnings/errors. Check event logs." -ForegroundColor Yellow
}

Write-Host "[*] Forcing Group Policy update to reflect changes..."
gpupdate /force /wait:0

# Cleanup
Remove-Item $exportPath -ErrorAction SilentlyContinue
Remove-Item $importPath -ErrorAction SilentlyContinue
Remove-Item $dbPath -ErrorAction SilentlyContinue

Write-Host "[+] Done. Local security policies forcefully set to $State." -ForegroundColor Green
