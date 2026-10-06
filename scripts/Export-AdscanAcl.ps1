<#
.SYNOPSIS
Exports selected AD object DACLs and transitive directory memberships, read-only.
.DESCRIPTION
Requires the ActiveDirectory PowerShell module. This exports a directory model,
not a captured Windows logon token. Review trust filtering / token context before
using -ConfirmDirectoryTokenModel to allow calculated decisions.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string[]]$Identity,
    [Parameter(Mandatory)][string[]]$ObjectDN,
    [string[]]$Rights = @('write_dacl', 'write_owner', 'write_property'),
    [string]$OutputPath = '.\acl-snapshot.json',
    [switch]$ConfirmDirectoryTokenModel
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$principals = @()
$objects = @()
$checks = @()
foreach ($userIdentity in $Identity) {
    $user = Get-ADUser -Identity $userIdentity -Server $Server -Properties tokenGroups, SIDHistory, primaryGroupID
    $groupSids = @($user.tokenGroups | ForEach-Object {
        ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$_, 0)).Value
    })
    $history = @($user.SIDHistory | ForEach-Object { $_.Value })
    # SIDHistory / cross-domain token filtering requires an actual token model.
    $complete = $ConfirmDirectoryTokenModel.IsPresent -and $history.Count -eq 0
    $principals += @{
        sid = $user.SID.Value
        name = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { $user.SamAccountName }
        groups = $groupSids; primary_group_sid = "$($user.SID.AccountDomainSid.Value)-$($user.primaryGroupID)"
        sid_history = $history; sid_history_enabled = $false
        authenticated = $true; token_complete = $complete
    }
}
foreach ($dn in $ObjectDN) {
    $object = Get-ADObject -Identity $dn -Server $Server -Properties ntSecurityDescriptor, objectSid
    $bytes = $object.ntSecurityDescriptor.GetSecurityDescriptorBinaryForm()
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
    $aces = @()
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        $type = switch ($ace.AceType.ToString()) {
            'AccessAllowed' { 'allow' }
            'AccessAllowedObject' { 'allow' }
            'AccessDenied' { 'deny' }
            'AccessDeniedObject' { 'deny' }
            default { 'unsupported' }
        }
        $entry = @{
            type = $type
            trustee_sid = if ($ace -is [System.Security.AccessControl.KnownAce]) { $ace.SecurityIdentifier.Value } else { '*' }
            mask = if ($ace -is [System.Security.AccessControl.KnownAce]) { ('0x{0:X8}' -f ([long]$ace.AccessMask -band 0xFFFFFFFFL)) } else { '0x000F01FF' }
            inherited = (($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited) -ne 0)
            inherit_only = (($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0)
            conditional = $type -eq 'unsupported'
        }
        if ($ace -is [System.Security.AccessControl.ObjectAce] -and
            ($ace.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent)) {
            $entry.object_type_guid = $ace.ObjectAceType.ToString()
        }
        $aces += $entry
    }
    $record = @{
        id = $dn; name = $object.Name; dacl_complete = $true; dacl = $aces
        owner_sid = $descriptor.Owner.Value
        object_sid = if ($object.objectSid) { $object.objectSid.Value } else { '' }
        observed_at = [DateTime]::UtcNow.ToString('o')
    }
    if ($null -eq $descriptor.DiscretionaryAcl) { $record.dacl = $null; $record.null_dacl = $true }
    $objects += $record
    foreach ($principal in $principals) {
        foreach ($right in $Rights) {
            $checks += @{ principal_sid = $principal.sid; object_id = $dn; rights = @($right) }
        }
    }
}
@{
    version = 1; target = $Server; source = 'RSAT RawSecurityDescriptor / directory tokenGroups'
    observed_at = [DateTime]::UtcNow.ToString('o'); principals = $principals
    groups = @(); objects = $objects; checks = $checks
} | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output "Snapshot exported: $OutputPath"
