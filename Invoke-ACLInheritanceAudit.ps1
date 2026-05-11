#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Detects Active Directory user accounts with disabled ACL inheritance.

.DESCRIPTION
    Scans all user objects in the directory (or a specific OU), checks whether
    ACL inheritance is disabled, and categorizes each finding:

      [SKIP]   adminCount=1  -- SDProp active, skip entirely.
      [ORPHAN] adminCount=0/null + not in any protected group -- safe to fix.
      [REVIEW] adminCount=0/null + still in a protected group -- manual review.

    Protected groups are resolved via well-known RIDs (language-independent).
    Generates an HTML report and a CSV export. Optionally applies fixes.

.PARAMETER SearchBase
    Root OU for the search. Defaults to the entire domain.

.PARAMETER OutputPath
    Output folder for reports. Defaults to the script directory.

.PARAMETER FixInheritance
    Re-enables ACL inheritance on ORPHAN accounts and clears adminCount.

.PARAMETER EnabledOnly
    Only scans enabled user accounts.

.EXAMPLE
    .\Invoke-ACLInheritanceAudit.ps1
    .\Invoke-ACLInheritanceAudit.ps1 -SearchBase "OU=CORP,DC=contoso,DC=local"
    .\Invoke-ACLInheritanceAudit.ps1 -SearchBase "OU=CORP,DC=contoso,DC=local" -FixInheritance
    .\Invoke-ACLInheritanceAudit.ps1 -EnabledOnly -OutputPath "C:\Reports"
    .\Invoke-ACLInheritanceAudit.ps1 -FixInheritance -WhatIf

.NOTES
    Author  : Systems & Network Administration
    Version : 2.0.0
    Requires: ActiveDirectory module, read/write access to AD objects
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "Root OU for the search (DistinguishedName). Defaults to domain root.")]
    [string]$SearchBase = (Get-ADDomain).DistinguishedName,

    [Parameter(HelpMessage = "Output folder for HTML and CSV reports.")]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(HelpMessage = "Re-enable ACL inheritance and clear adminCount on ORPHAN accounts.")]
    [switch]$FixInheritance,

    [Parameter(HelpMessage = "Only scan enabled user accounts.")]
    [switch]$EnabledOnly
)

#region -- Initialization ----------------------------------------------------

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptVersion  = "2.0.0"
$startTime      = Get-Date
$timestamp      = $startTime.ToString("yyyyMMdd_HHmmss")
$htmlFile       = Join-Path $OutputPath "ACLInheritanceAudit_$timestamp.html"
$csvFile        = Join-Path $OutputPath "ACLInheritanceAudit_$timestamp.csv"

$results        = [System.Collections.Generic.List[PSCustomObject]]::new()
$fixedCount     = 0
$errorCount     = 0
$scanned        = 0
$skippedSdprop  = 0
$skippedExcluded = 0
$orphanCount    = 0
$reviewCount    = 0

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) {
        "INFO"    { "Cyan"   }
        "SUCCESS" { "Green"  }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red"    }
        default   { "White"  }
    }
    Write-Host "[$( Get-Date -Format 'HH:mm:ss')] [$Level] $Message" -ForegroundColor $color
}

#endregion

#region -- SDProp Protected Groups (Well-Known RIDs) -------------------------
#
# Domain-relative RIDs:
#   512  Domain Admins
#   518  Schema Admins
#   519  Enterprise Admins
#   520  Group Policy Creator Owners
#
# BUILTIN RIDs (S-1-5-32):
#   544  Administrators
#   548  Account Operators
#   549  Server Operators
#   550  Print Operators
#   551  Backup Operators
#   552  Replicator
#

Write-Log "Resolving SDProp-protected groups via well-known SIDs..."

$domainSid   = (Get-ADDomain).DomainSID.Value
$builtinSid  = "S-1-5-32"

$domainRids  = @(512, 518, 519, 520)
$builtinRids = @(544, 548, 549, 550, 551, 552)

$protectedGroupSids = [System.Collections.Generic.HashSet[string]]::new()

foreach ($rid in $domainRids)  { $protectedGroupSids.Add("$domainSid-$rid")  | Out-Null }
foreach ($rid in $builtinRids) { $protectedGroupSids.Add("$builtinSid-$rid") | Out-Null }

$protectedGroupDNs = [System.Collections.Generic.HashSet[string]]::new()

foreach ($sid in $protectedGroupSids) {
    try {
        $grp = Get-ADGroup -Filter "objectSID -eq '$sid'" -Properties DistinguishedName
        if ($grp) {
            $protectedGroupDNs.Add($grp.DistinguishedName) | Out-Null
            Write-Log "  Resolved: $($grp.Name) [$sid]"
        }
    }
    catch {
        Write-Log "  Could not resolve SID $sid -- $_" "WARN"
    }
}

Write-Log "Protected groups resolved: $($protectedGroupDNs.Count)" "SUCCESS"
Write-Host ""

function Test-ProtectedGroupMembership {
    param([Microsoft.ActiveDirectory.Management.ADUser]$User)
    try {
        $tokenGroups = (Get-ADUser -Identity $User.DistinguishedName -Properties tokenGroups).tokenGroups
        foreach ($groupSid in $tokenGroups) {
            if ($protectedGroupSids.Contains($groupSid.ToString())) { return $true }
        }
        return $false
    }
    catch {
        $memberOf = (Get-ADUser -Identity $User.DistinguishedName -Properties MemberOf).MemberOf
        foreach ($dn in $memberOf) {
            if ($protectedGroupDNs.Contains($dn)) { return $true }
        }
        return $false
    }
}

#endregion

#region -- User Collection ---------------------------------------------------

Write-Log "Starting ACL inheritance audit v$scriptVersion"
Write-Log "SearchBase     : $SearchBase"
Write-Log "EnabledOnly    : $EnabledOnly"
Write-Log "FixInheritance : $FixInheritance"
Write-Host ""

$adFilter = if ($EnabledOnly) { "Enabled -eq `$true" } else { "*" }

Write-Log "Retrieving user objects from Active Directory..."

try {
    $allUsers = Get-ADUser -Filter $adFilter `
                           -SearchBase $SearchBase `
                           -Properties DistinguishedName, ObjectGUID, Enabled, Department, Description, adminCount `
                           -SearchScope Subtree
}
catch {
    Write-Log "Failed to retrieve AD users: $_" "ERROR"
    exit 1
}

# Exclusion list -- accounts that must never be touched regardless of ACL state
# MSOL_* / AADConnect_* : AAD Connect service accounts (touching ACL breaks directory sync)
# krbtgt               : Kerberos ticket-granting account
$excludedPatterns = @("MSOL_*", "AADConnect_*", "krbtgt")

$skippedSdprop   = ($allUsers | Where-Object { $_.adminCount -eq 1 } | Measure-Object).Count

$users = $allUsers | Where-Object {
    if ($_.adminCount -eq 1) { return $false }
    foreach ($pattern in $excludedPatterns) {
        if ($_.SamAccountName -like $pattern) {
            $skippedExcluded++
            Write-Log "Excluded (protected account): $($_.SamAccountName)" "WARN"
            return $false
        }
    }
    return $true
}

if ($skippedSdprop -gt 0) {
    Write-Log "Skipped $skippedSdprop account(s) with adminCount=1 (SDProp active)." "WARN"
}
if ($skippedExcluded -gt 0) {
    Write-Log "Skipped $skippedExcluded explicitly excluded account(s) (MSOL/AADConnect/krbtgt)." "WARN"
}

$total = ($users | Measure-Object).Count
Write-Log "Found $total user object(s) to scan." "INFO"
Write-Host ""

#endregion

#region -- ACL Scan ----------------------------------------------------------

foreach ($user in $users) {
    $scanned++

    Write-Progress -Activity "Scanning ACL inheritance" `
                   -Status "$scanned / $total -- $($user.SamAccountName)" `
                   -PercentComplete (($scanned / $total) * 100)

    try {
        # Use nTSecurityDescriptor via ObjectGUID -- immune to DN special characters
        $secDesc = (Get-ADUser -Identity $user.ObjectGUID `
                               -Properties nTSecurityDescriptor).nTSecurityDescriptor

        if (-not $secDesc.AreAccessRulesProtected) { continue }

        $isProtected = Test-ProtectedGroupMembership -User $user

        if ($isProtected) {
            $category  = "REVIEW"
            $fixStatus = "Manual review required"
            $reviewCount++
            Write-Log "REVIEW : $($user.SamAccountName) -- still in protected group" "WARN"
        }
        else {
            $category = "ORPHAN"
            $orphanCount++

            if ($FixInheritance) {
                if ($PSCmdlet.ShouldProcess($user.DistinguishedName, "Re-enable ACL inheritance + clear adminCount")) {
                    try {
                        $secDesc.SetAccessRuleProtection($false, $true)
                        Set-ADUser -Identity $user.ObjectGUID -Replace @{ nTSecurityDescriptor = $secDesc }
                        # Only clear adminCount if it was explicitly set (0) -- if null, attribute was never set
                        if ($null -ne $user.adminCount) {
                            Set-ADUser -Identity $user.ObjectGUID -Clear adminCount
                        }
                        $fixStatus = "Fixed"
                        $fixedCount++
                        $fixMsg = if ($null -ne $user.adminCount) { "inheritance restored, adminCount cleared" } else { "inheritance restored (adminCount was null -- not modified)" }
                        Write-Log "FIXED  : $($user.SamAccountName) -- $fixMsg" "SUCCESS"
                    }
                    catch {
                        $fixStatus = "Fix failed"
                        $errorCount++
                        Write-Log "ERROR  : $($user.SamAccountName) -- $_" "ERROR"
                    }
                }
                else {
                    $fixStatus = "Skipped (WhatIf)"
                }
            }
            else {
                $fixStatus = "Not fixed"
                $adminCountDisplay = if ($null -eq $user.adminCount) { "null (SDProp residue with adminCount cleared, or manual ACL change)" } else { $user.adminCount }
                Write-Log "ORPHAN : $($user.SamAccountName) -- adminCount=$adminCountDisplay" "WARN"
            }
        }

        $results.Add([PSCustomObject]@{
            SamAccountName    = $user.SamAccountName
            DisplayName       = $user.Name
            Enabled           = $user.Enabled
            Department        = $user.Department
            adminCount        = if ($null -eq $user.adminCount) { "null" } else { [string]$user.adminCount }
            Category          = $category
            InProtectedGroup  = $isProtected
            OU                = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
            DistinguishedName = $user.DistinguishedName
            FixStatus         = $fixStatus
        })
    }
    catch {
        $errorCount++
        Write-Log "Error processing $($user.SamAccountName): $_" "ERROR"
    }
}

Write-Progress -Activity "Scanning ACL inheritance" -Completed

#endregion

#region -- CSV Export --------------------------------------------------------

if ($results.Count -gt 0) {
    try {
        $results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Log "CSV exported: $csvFile" "SUCCESS"
    }
    catch {
        Write-Log "CSV export failed: $_" "ERROR"
    }
}
else {
    Write-Log "No accounts with disabled inheritance found." "SUCCESS"
}

#endregion

#region -- HTML Report -------------------------------------------------------

$endTime       = Get-Date
$duration      = [math]::Round(($endTime - $startTime).TotalSeconds, 1)
$affectedCount = $results.Count

$tableRows = if ($results.Count -gt 0) {
    ($results | ForEach-Object {

        $enabledBadge = if ($_.Enabled) {
            '<span class="badge badge-enabled">Enabled</span>'
        } else {
            '<span class="badge badge-disabled">Disabled</span>'
        }

        $categoryBadge = switch ($_.Category) {
            "ORPHAN" { '<span class="badge badge-orphan">ORPHAN</span>' }
            "REVIEW" { '<span class="badge badge-review">REVIEW</span>' }
            default  { '<span class="badge badge-muted">UNKNOWN</span>' }
        }

        $fixBadge = switch ($_.FixStatus) {
            "Fixed"                  { '<span class="badge badge-fixed">Fixed</span>' }
            "Not fixed"              { '<span class="badge badge-notfixed">Not fixed</span>' }
            "Skipped (WhatIf)"       { '<span class="badge badge-whatif">WhatIf</span>' }
            "Manual review required" { '<span class="badge badge-review">Manual review</span>' }
            default                  { '<span class="badge badge-error">Error</span>' }
        }

        $adminVal = if ($_.adminCount -eq "null" -or $_.adminCount -eq '' -or $null -eq $_.adminCount) {
            '<span class="na">null</span>'
        } else {
            $_.adminCount
        }

        "<tr>
            <td><code>$($_.SamAccountName)</code></td>
            <td>$($_.DisplayName)</td>
            <td>$enabledBadge</td>
            <td>$categoryBadge</td>
            <td>$adminVal</td>
            <td>$($_.Department)</td>
            <td class='dn' title='$($_.DistinguishedName)'>$($_.OU)</td>
            <td>$fixBadge</td>
        </tr>"
    }) -join "`n"
} else {
    '<tr><td colspan="8" class="no-results">No accounts with disabled ACL inheritance detected.</td></tr>'
}

$genDate   = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
$closeDate = $endTime.ToString("yyyy-MM-dd HH:mm:ss")

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ACL Inheritance Audit v$scriptVersion</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; padding: 40px 32px; }
  header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 36px; padding-bottom: 24px; border-bottom: 1px solid #1e2535; }
  .header-left h1 { font-size: 22px; font-weight: 600; color: #f8fafc; letter-spacing: -0.3px; }
  .header-left p  { font-size: 13px; color: #64748b; margin-top: 4px; }
  .header-meta { text-align: right; font-size: 12px; color: #475569; line-height: 1.8; }
  .header-meta strong { color: #94a3b8; }
  .legend { display: flex; gap: 24px; flex-wrap: wrap; margin-bottom: 28px; padding: 16px 20px; background: #161b27; border: 1px solid #1e2535; border-radius: 10px; font-size: 12px; }
  .legend-item { display: flex; align-items: center; gap: 8px; }
  .legend-item .desc { color: #64748b; }
  .stats { display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; margin-bottom: 32px; }
  .stat-card { background: #161b27; border: 1px solid #1e2535; border-radius: 10px; padding: 18px 20px; }
  .stat-card .label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; color: #475569; margin-bottom: 8px; }
  .stat-card .value { font-size: 28px; font-weight: 700; line-height: 1; }
  .stat-card.warn   .value { color: #f59e0b; }
  .stat-card.ok     .value { color: #10b981; }
  .stat-card.info   .value { color: #60a5fa; }
  .stat-card.error  .value { color: #f87171; }
  .stat-card.orange .value { color: #fb923c; }
  .stat-card.muted  .value { color: #475569; }
  .stat-card.purple .value { color: #c084fc; }
  .section-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; color: #475569; margin-bottom: 14px; }
  .table-wrapper { background: #161b27; border: 1px solid #1e2535; border-radius: 10px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead { background: #1a2033; border-bottom: 1px solid #1e2535; }
  thead th { padding: 12px 14px; text-align: left; font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.7px; color: #64748b; }
  tbody tr { border-bottom: 1px solid #1a2033; transition: background 0.15s; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #1a2235; }
  td { padding: 10px 14px; vertical-align: middle; color: #cbd5e1; }
  td code { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px; color: #93c5fd; background: #1e293b; padding: 2px 7px; border-radius: 4px; }
  td.dn { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 10.5px; color: #475569; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: default; }
  .na { color: #334155; font-style: italic; }
  .badge { display: inline-block; font-size: 10.5px; font-weight: 600; padding: 2px 8px; border-radius: 20px; letter-spacing: 0.3px; }
  .badge-enabled   { background: #052e16; color: #4ade80; border: 1px solid #166534; }
  .badge-disabled  { background: #1c1917; color: #a8a29e; border: 1px solid #44403c; }
  .badge-fixed     { background: #052e16; color: #34d399; border: 1px solid #065f46; }
  .badge-notfixed  { background: #1c1407; color: #fbbf24; border: 1px solid #92400e; }
  .badge-error     { background: #1f0707; color: #f87171; border: 1px solid #7f1d1d; }
  .badge-whatif    { background: #0c1a2e; color: #60a5fa; border: 1px solid #1e40af; }
  .badge-orphan    { background: #1c1407; color: #fb923c; border: 1px solid #9a3412; }
  .badge-review    { background: #1a0a2e; color: #c084fc; border: 1px solid #6b21a8; }
  .badge-muted     { background: #1c1917; color: #a8a29e; border: 1px solid #44403c; }
  .no-results { text-align: center; padding: 48px !important; color: #10b981; font-size: 14px; }
  footer { margin-top: 32px; font-size: 11px; color: #334155; text-align: center; }
</style>
</head>
<body>

<header>
  <div class="header-left">
    <h1>ACL Inheritance Audit - AD User Accounts</h1>
    <p>Disabled inheritance detection | SDProp orphan classification | Protected groups resolved via well-known RIDs</p>
  </div>
  <div class="header-meta">
    <strong>Generated</strong> $genDate<br>
    <strong>Duration</strong> ${duration}s<br>
    <strong>Search base</strong> $SearchBase<br>
    <strong>Version</strong> $scriptVersion
  </div>
</header>

<div class="legend">
  <div class="legend-item">
    <span class="badge badge-orphan">ORPHAN</span>
    <span class="desc">adminCount=0/null &middot; not in any protected group &middot; SDProp residue (rights removed, inheritance never restored) or manual ACL change &middot; safe to fix</span>
  </div>
  <div class="legend-item">
    <span class="badge badge-review">REVIEW</span>
    <span class="desc">adminCount=0/null &middot; still in a protected group &middot; manual review required</span>
  </div>
  <div class="legend-item">
    <span class="badge badge-muted">SKIP</span>
    <span class="desc">adminCount=1 &middot; SDProp active &middot; excluded from report</span>
  </div>
</div>

<div class="stats">
  <div class="stat-card info">
    <div class="label">Users scanned</div>
    <div class="value">$total</div>
  </div>
  <div class="stat-card warn">
    <div class="label">Inheritance disabled</div>
    <div class="value">$affectedCount</div>
  </div>
  <div class="stat-card orange">
    <div class="label">Orphan (fixable)</div>
    <div class="value">$orphanCount</div>
  </div>
  <div class="stat-card purple">
    <div class="label">Review needed</div>
    <div class="value">$reviewCount</div>
  </div>
  <div class="stat-card ok">
    <div class="label">Fixed</div>
    <div class="value">$fixedCount</div>
  </div>
  <div class="stat-card muted">
    <div class="label">Skipped (SDProp=1)</div>
    <div class="value">$skippedSdprop</div>
  </div>
</div>

<p class="section-title">Affected accounts</p>
<div class="table-wrapper">
  <table>
    <thead>
      <tr>
        <th>SamAccountName</th>
        <th>Display Name</th>
        <th>Account</th>
        <th>Category</th>
        <th>adminCount</th>
        <th>Department</th>
        <th>OU Path</th>
        <th>Fix Status</th>
      </tr>
    </thead>
    <tbody>
      $tableRows
    </tbody>
  </table>
</div>

<footer>
  Invoke-ACLInheritanceAudit v$scriptVersion - $closeDate - Protected groups: RIDs 512,518,519,520 (domain) + 544,548,549,550,551,552 (BUILTIN)
</footer>

</body>
</html>
"@

try {
    [System.IO.File]::WriteAllText($htmlFile, $html, [System.Text.Encoding]::UTF8)
    Write-Log "HTML report exported: $htmlFile" "SUCCESS"
}
catch {
    Write-Log "HTML export failed: $_" "ERROR"
}

#endregion

#region -- Summary -----------------------------------------------------------

Write-Host ""
Write-Host "-------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  SUMMARY" -ForegroundColor White
Write-Host "-------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Users scanned           : $total"
Write-Host "  Skipped (adminCount=1)  : $skippedSdprop"   -ForegroundColor DarkGray
Write-Host "  Inheritance disabled    : $affectedCount"    -ForegroundColor $(if ($affectedCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  +-- Orphan (fixable)    : $orphanCount"     -ForegroundColor $(if ($orphanCount -gt 0) { "DarkYellow" } else { "Gray" })
Write-Host "  +-- Review needed       : $reviewCount"     -ForegroundColor $(if ($reviewCount -gt 0) { "Magenta" } else { "Gray" })
Write-Host "  Fixed                   : $fixedCount"      -ForegroundColor $(if ($fixedCount -gt 0) { "Green" } else { "Gray" })
Write-Host "  Errors                  : $errorCount"      -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "Gray" })
Write-Host "  Duration                : ${duration}s"
Write-Host "-------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  HTML : $htmlFile"
if ($results.Count -gt 0) { Write-Host "  CSV  : $csvFile" }
Write-Host "-------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""

#endregion
