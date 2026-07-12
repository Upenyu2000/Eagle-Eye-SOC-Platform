#Requires -RunAsAdministrator
# Run on DC01 after the LAB.LOCAL forest has been created.
# Creates only synthetic portfolio-lab identities.

Import-Module ActiveDirectory
$ErrorActionPreference = "Stop"

$domainDn = (Get-ADDomain).DistinguishedName
$baseOu = "OU=Portfolio Lab,$domainDn"

function Ensure-OU {
    param([string]$Name, [string]$Path)
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$dn)" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
    }
}

if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$baseOu)" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name "Portfolio Lab" -Path $domainDn -ProtectedFromAccidentalDeletion $true
}

"Users","Groups","Servers","Workstations","Service Accounts" | ForEach-Object {
    Ensure-OU -Name $_ -Path $baseOu
}

$usersOu = "OU=Users,$baseOu"
$groupsOu = "OU=Groups,$baseOu"
$svcOu = "OU=Service Accounts,$baseOu"

$initialPassword = Read-Host "Enter a unique temporary password for synthetic users" -AsSecureString
$servicePassword = Read-Host "Enter a separate strong password for svc_web" -AsSecureString

$labUsers = @(
    @{ Sam="alice"; Given="Alice"; Surname="Analyst" },
    @{ Sam="bob"; Given="Bob"; Surname="Builder" },
    @{ Sam="charlie"; Given="Charlie"; Surname="Reviewer" }
)

foreach ($u in $labUsers) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -SamAccountName $u.Sam `
            -UserPrincipalName "$($u.Sam)@lab.local" `
            -GivenName $u.Given `
            -Surname $u.Surname `
            -Name "$($u.Given) $($u.Surname)" `
            -Path $usersOu `
            -AccountPassword $initialPassword `
            -Enabled $true `
            -ChangePasswordAtLogon $true
    }
}

if (-not (Get-ADGroup -Filter "SamAccountName -eq 'Helpdesk-Lab'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name "Helpdesk-Lab" -SamAccountName "Helpdesk-Lab" `
        -GroupCategory Security -GroupScope Global -Path $groupsOu `
        -Description "Synthetic delegated group for BloodHound analysis"
}
Add-ADGroupMember -Identity "Helpdesk-Lab" -Members "alice" -ErrorAction SilentlyContinue

if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_web'" -ErrorAction SilentlyContinue)) {
    New-ADUser `
        -SamAccountName "svc_web" `
        -UserPrincipalName "svc_web@lab.local" `
        -Name "Web Service Lab" `
        -Path $svcOu `
        -AccountPassword $servicePassword `
        -Enabled $true `
        -PasswordNeverExpires $false `
        -CannotChangePassword $false `
        -Description "Synthetic SPN account for authorised Kerberos telemetry testing"
}

setspn.exe -S "HTTP/web.lab.local" "LAB\svc_web"

$group = Get-ADGroup "Helpdesk-Lab"
$alice = Get-ADUser "alice"
$acl = Get-Acl "AD:\$($group.DistinguishedName)"
$guid = [Guid]"bf9679c0-0de6-11d0-a285-00aa003049e2"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $alice.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $guid
)
$acl.AddAccessRule($rule)
Set-Acl -Path "AD:\$($group.DistinguishedName)" -AclObject $acl

Write-Host "Synthetic LAB.LOCAL identities and relationships created."
Write-Host "Rotate all passwords and remove the SPN after completing the exercise."
