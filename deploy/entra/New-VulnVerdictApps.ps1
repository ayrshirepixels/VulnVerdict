#Requires -Version 5.1
<#
.SYNOPSIS
    Creates the Entra ID app registrations VulnVerdict uses, each with only what it needs, and prints the values to
    enter in the console.

.DESCRIPTION
    Two apps, so a leaked or expired secret affects one job only:

      <Prefix> inventory  Read-only access for the Intune and Defender for Endpoint connectors:
                          Microsoft Graph DeviceManagementManagedDevices.Read.All, and WindowsDefenderATP
                          Machine.Read.All, Software.Read.All and Vulnerability.Read.All (when Defender is set up),
                          with admin consent granted.
      <Prefix> mail       Sends mail as ONE mailbox through Microsoft Graph, using Exchange Online's role-based access
                          for applications (the "Application Mail.Send" role on a scope holding just that mailbox).
                          No Mail.Send permission is granted on the app itself, so it cannot send as anyone else.

    Each app gets a client secret that expires after -SecretMonths months. The script prints the tenant ID, client
    ID, secret and expiry date for each; enter them in the console (Connectors for inventory, Settings > Mail for
    mail), including the expiry date, and the console will warn 30 days before a secret runs out.

    Needs: the Microsoft.Graph.Authentication and Microsoft.Graph.Applications modules, and ExchangeOnlineManagement
    for the mail app. Run as an administrator who can create app registrations and grant consent (Cloud Application
    Administrator or Global Administrator) and, for mail, an Exchange administrator.

.EXAMPLE
    .\New-VulnVerdictApps.ps1 -TenantId contoso.onmicrosoft.com -Mailbox vulnverdict@contoso.com

.EXAMPLE
    .\New-VulnVerdictApps.ps1 -TenantId contoso.onmicrosoft.com -SkipMail -SecretMonths 24
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [ValidatePattern('^[^''"\s]+@[^''"\s]+\.[^''"\s]+$')] [string] $Mailbox,
    [ValidateRange(1, 24)] [int] $SecretMonths = 12,
    [ValidatePattern('^[\w .-]{1,40}$')] [string] $Prefix = 'VulnVerdict',
    [switch] $SkipInventory,
    [switch] $SkipMail
)

$ErrorActionPreference = 'Stop'
if (-not $SkipMail -and -not $Mailbox) { throw 'Give -Mailbox (the address VulnVerdict sends from; a shared mailbox is fine) or pass -SkipMail.' }
if ($SkipMail -and $SkipInventory) { throw 'Nothing to do: -SkipMail and -SkipInventory together.' }

$GraphAppId    = '00000003-0000-0000-c000-000000000000'   # Microsoft Graph
$DefenderAppId = 'fc780465-2017-40d4-a0c5-307022471b92'   # WindowsDefenderATP

function Assert-Module([string] $Name) {
    if (-not (Get-Module -ListAvailable -Name $Name)) { throw "Install the $Name module first: Install-Module $Name -Scope CurrentUser" }
}

# Entra replication takes a few seconds: a new service principal can be briefly unknown to the next call.
function Invoke-WithRetry([scriptblock] $Action, [string] $What) {
    for ($i = 1; ; $i++) {
        try { return & $Action }
        catch {
            if ($i -ge 6) { throw "$What failed: $($_.Exception.Message)" }
            Start-Sleep -Seconds (5 * $i)
        }
    }
}

function Get-AppRole($ResourceSp, [string] $Value) {
    $role = $ResourceSp.AppRoles | Where-Object { $_.Value -eq $Value -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "$($ResourceSp.DisplayName) has no application permission called $Value." }
    return $role
}

function New-VvApp([string] $Name, $Access) {
    if (Get-MgApplication -Filter "displayName eq '$Name'") { throw "An app registration called '$Name' already exists. Delete it first, or pass -Prefix to use another name." }
    $app = New-MgApplication -DisplayName $Name -SignInAudience AzureADMyOrg -RequiredResourceAccess $Access -Notes 'Created by New-VulnVerdictApps.ps1 for the VulnVerdict console.'
    $sp = Invoke-WithRetry { New-MgServicePrincipal -AppId $app.AppId } "Creating the service principal for $Name"
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{ DisplayName = 'VulnVerdict console'; EndDateTime = (Get-Date).AddMonths($SecretMonths).ToUniversalTime() }
    [pscustomobject]@{ App = $app; Sp = $sp; Secret = $secret }
}

Assert-Module Microsoft.Graph.Authentication
Assert-Module Microsoft.Graph.Applications
if (-not $SkipMail) { Assert-Module ExchangeOnlineManagement }

if (-not $PSCmdlet.ShouldProcess($TenantId, "Create $(@(if (-not $SkipInventory) { "'$Prefix inventory'" }; if (-not $SkipMail) { "'$Prefix mail' (sends as $Mailbox only)" }) -join ' and ')")) { return }

Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome
$results = @()

if (-not $SkipInventory) {
    $graph = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
    $defender = Get-MgServicePrincipal -Filter "appId eq '$DefenderAppId'"
    $grants = @(@{ Resource = $graph; Roles = @(Get-AppRole $graph 'DeviceManagementManagedDevices.Read.All') })
    if ($defender) {
        $grants += @{ Resource = $defender; Roles = @('Machine.Read.All', 'Software.Read.All', 'Vulnerability.Read.All' | ForEach-Object { Get-AppRole $defender $_ }) }
    }
    else {
        Write-Warning 'Defender for Endpoint is not set up in this tenant: the inventory app gets the Intune permission only.'
    }
    $access = @($grants | ForEach-Object { @{ ResourceAppId = $_.Resource.AppId; ResourceAccess = @($_.Roles | ForEach-Object { @{ Id = $_.Id; Type = 'Role' } }) } })
    $inv = New-VvApp "$Prefix inventory" $access
    foreach ($g in $grants) {
        foreach ($r in $g.Roles) {
            # granting each application permission to the app's own service principal is what "admin consent" does
            Invoke-WithRetry { New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $inv.Sp.Id -PrincipalId $inv.Sp.Id -ResourceId $g.Resource.Id -AppRoleId $r.Id | Out-Null } "Granting $($r.Value)"
        }
    }
    $results += [pscustomobject]@{
        'Use for'          = 'Connectors: Microsoft Intune' + $(if ($defender) { ' and Defender for Endpoint' } else { '' })
        'Tenant ID'        = (Get-MgContext).TenantId
        'Client ID'        = $inv.App.AppId
        'Client secret'    = $inv.Secret.SecretText
        'Secret expires on'= $inv.Secret.EndDateTime.ToString('yyyy-MM-dd')
    }
}

if (-not $SkipMail) {
    $mail = New-VvApp "$Prefix mail" @()
    Connect-ExchangeOnline -ShowBanner:$false
    $box = Get-EXOMailbox -Identity $Mailbox -ErrorAction SilentlyContinue
    if (-not $box) { throw "$Mailbox is not a mailbox in this tenant. Create a shared mailbox for it first; the '$Prefix mail' app registration was created and can be deleted." }
    $scopeName = "$Prefix mailbox"
    Invoke-WithRetry { New-ServicePrincipal -AppId $mail.App.AppId -ObjectId $mail.Sp.Id -DisplayName "$Prefix mail" | Out-Null } 'Registering the app with Exchange Online'
    if (-not (Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue)) {
        New-ManagementScope -Name $scopeName -RecipientRestrictionFilter "PrimarySmtpAddress -eq '$($box.PrimarySmtpAddress)'" | Out-Null
    }
    New-ManagementRoleAssignment -App $mail.App.AppId -Role 'Application Mail.Send' -CustomResourceScope $scopeName | Out-Null
    $results += [pscustomobject]@{
        'Use for'          = "Settings > Mail > Microsoft 365, from $($box.PrimarySmtpAddress)"
        'Tenant ID'        = (Get-MgContext).TenantId
        'Client ID'        = $mail.App.AppId
        'Client secret'    = $mail.Secret.SecretText
        'Secret expires on'= $mail.Secret.EndDateTime.ToString('yyyy-MM-dd')
    }
    Write-Host "Exchange can take up to an hour to apply the mailbox permission; a test email may be refused until then." -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'Enter these in the VulnVerdict console. The secrets are shown once: paste them now, then clear this window.' -ForegroundColor Cyan
$results | Format-List
