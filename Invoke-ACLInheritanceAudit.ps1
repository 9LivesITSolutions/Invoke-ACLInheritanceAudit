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
            '<span class="badge b-enabled"><span class="badge-dot"></span>Enabled</span>'
        } else {
            '<span class="badge b-disabled"><span class="badge-dot"></span>Disabled</span>'
        }

        $categoryBadge = switch ($_.Category) {
            "ORPHAN" { '<span class="badge b-orphan"><span class="badge-dot"></span>ORPHAN</span>' }
            "REVIEW" { '<span class="badge b-review"><span class="badge-dot"></span>REVIEW</span>' }
            default  { '<span class="badge b-skip"><span class="badge-dot"></span>UNKNOWN</span>' }
        }

        $fixBadge = switch ($_.FixStatus) {
            "Fixed"                  { '<span class="badge b-fixed"><span class="badge-dot"></span>Fixed</span>' }
            "Not fixed"              { '<span class="badge b-notfixed"><span class="badge-dot"></span>Not fixed</span>' }
            "Skipped (WhatIf)"       { '<span class="badge b-whatif"><span class="badge-dot"></span>WhatIf</span>' }
            "Manual review required" { '<span class="badge b-manual"><span class="badge-dot"></span>Manual review</span>' }
            default                  { '<span class="badge b-err"><span class="badge-dot"></span>Error</span>' }
        }

        $adminVal = if ($_.adminCount -eq "null" -or $_.adminCount -eq '' -or $null -eq $_.adminCount) {
            '<span class="na">null</span>'
        } else {
            $_.adminCount
        }

        "<tr>
            <td class='mono'>$($_.SamAccountName)</td>
            <td>$($_.DisplayName)</td>
            <td>$enabledBadge</td>
            <td>$categoryBadge</td>
            <td class='mono'>$adminVal</td>
            <td class='dim'>$($_.Department)</td>
            <td class='path' title='$($_.DistinguishedName)'>$($_.OU)</td>
            <td>$fixBadge</td>
        </tr>"
    }) -join "`n"
} else {
    '<tr><td colspan="8" class="no-data"><div class="icon">&#10003;</div><p>No accounts with disabled inheritance found</p><small>All user accounts have ACL inheritance enabled</small></td></tr>'
}

$genDate   = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
$closeDate = $endTime.ToString("yyyy-MM-dd HH:mm:ss")

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ACL Inheritance Audit</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #f8f9fa;
    --surface:   #ffffff;
    --border:    #e5e7eb;
    --border-sm: #f0f1f3;
    --text-1:    #111827;
    --text-2:    #6b7280;
    --text-3:    #9ca3af;
    --mono:      "Cascadia Code", "Consolas", "SF Mono", monospace;
    --radius-sm: 6px;
    --radius:    10px;
    --radius-lg: 14px;
  }

  body {
    font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    background: var(--bg);
    color: var(--text-1);
    font-size: 13.5px;
    line-height: 1.5;
    min-height: 100vh;
    padding: 48px 40px;
  }

  .page { max-width: 1320px; margin: 0 auto; }

  /* ---- Header ---- */
  .header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 32px;
    margin-bottom: 40px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
  }

  .header-brand { display: flex; align-items: center; gap: 14px; }

  .header-icon {
    width: 40px; height: 40px;
    background: #111827;
    border-radius: var(--radius-sm);
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }

  .header-icon svg { width: 20px; height: 20px; stroke: #fff; fill: none; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }

  .header-title { font-size: 17px; font-weight: 600; color: var(--text-1); letter-spacing: -0.3px; }
  .header-sub   { font-size: 12px; color: var(--text-3); margin-top: 2px; }

  .header-meta {
    text-align: right;
    font-size: 12px;
    color: var(--text-3);
    line-height: 2;
    flex-shrink: 0;
  }

  .header-meta span { color: var(--text-2); font-weight: 500; }

  /* ---- Stats grid ---- */
  .stats {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    margin-bottom: 32px;
  }

  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 16px;
    position: relative;
    overflow: hidden;
  }

  .stat::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    border-radius: var(--radius) var(--radius) 0 0;
    background: var(--accent, #e5e7eb);
  }

  .stat-label { font-size: 11px; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 8px; }
  .stat-value { font-size: 26px; font-weight: 600; color: var(--text-1); line-height: 1; }
  .stat-sub   { font-size: 11px; color: var(--text-3); margin-top: 4px; }

  .stat.blue   { --accent: #3b82f6; } .stat.blue   .stat-value { color: #1d4ed8; }
  .stat.amber  { --accent: #f59e0b; } .stat.amber  .stat-value { color: #b45309; }
  .stat.orange { --accent: #f97316; } .stat.orange .stat-value { color: #c2410c; }
  .stat.purple { --accent: #8b5cf6; } .stat.purple .stat-value { color: #6d28d9; }
  .stat.green  { --accent: #10b981; } .stat.green  .stat-value { color: #047857; }
  .stat.gray   { --accent: #d1d5db; } .stat.gray   .stat-value { color: var(--text-2); }

  /* ---- Legend ---- */
  .legend {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-bottom: 24px;
  }

  .legend-item {
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 99px;
    padding: 5px 12px 5px 6px;
    font-size: 12px;
    color: var(--text-2);
  }

  /* ---- Section heading ---- */
  .section-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 12px;
  }

  .section-head h2 { font-size: 13px; font-weight: 600; color: var(--text-1); }
  .section-head .count { font-size: 12px; color: var(--text-3); }

  /* ---- Table ---- */
  .table-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }

  table { width: 100%; border-collapse: collapse; }

  thead th {
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-3);
    background: var(--bg);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  tbody tr { border-bottom: 1px solid var(--border-sm); transition: background 0.1s; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: #f9fafb; }

  td { padding: 10px 14px; vertical-align: middle; color: var(--text-1); }

  td.mono {
    font-family: var(--mono);
    font-size: 12px;
    color: #374151;
  }

  td.path {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-3);
    max-width: 280px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: default;
  }

  td.dim { color: var(--text-3); font-size: 12px; font-style: italic; }

  .no-data { text-align: center; padding: 56px 24px; }
  .no-data .icon { font-size: 32px; margin-bottom: 12px; }
  .no-data p { font-size: 14px; color: var(--text-2); font-weight: 500; }
  .no-data small { font-size: 12px; color: var(--text-3); }

  /* ---- Badges ---- */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 99px;
    letter-spacing: 0.2px;
    white-space: nowrap;
  }

  .badge-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }

  .b-enabled  { background: #dcfce7; color: #166534; }
  .b-enabled  .badge-dot { background: #16a34a; }
  .b-disabled { background: #f3f4f6; color: #6b7280; }
  .b-disabled .badge-dot { background: #9ca3af; }

  .b-orphan { background: #fff7ed; color: #c2410c; }
  .b-orphan .badge-dot { background: #f97316; }
  .b-review { background: #f5f3ff; color: #6d28d9; }
  .b-review .badge-dot { background: #8b5cf6; }
  .b-skip   { background: #f3f4f6; color: #6b7280; }
  .b-skip   .badge-dot { background: #9ca3af; }

  .b-fixed    { background: #dcfce7; color: #166534; }
  .b-fixed    .badge-dot { background: #16a34a; }
  .b-notfixed { background: #fefce8; color: #854d0e; }
  .b-notfixed .badge-dot { background: #ca8a04; }
  .b-whatif   { background: #eff6ff; color: #1d4ed8; }
  .b-whatif   .badge-dot { background: #3b82f6; }
  .b-manual   { background: #f5f3ff; color: #6d28d9; }
  .b-manual   .badge-dot { background: #8b5cf6; }
  .b-err      { background: #fef2f2; color: #991b1b; }
  .b-err      .badge-dot { background: #ef4444; }

  /* ---- Footer ---- */
  .footer {
    margin-top: 40px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .footer-brand { display: flex; align-items: center; gap: 8px; }
  .footer-brand .dot { width: 6px; height: 6px; background: #111827; border-radius: 50%; }
  .footer-brand span { font-size: 12px; font-weight: 600; color: var(--text-1); }
  .footer p { font-size: 11px; color: var(--text-3); }
</style>
</head>
<body>
<div class="page">

<header class="header">
  <div class="header-brand">
    <div class="header-icon">
      <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <div>
      <div class="header-title">ACL Inheritance Audit</div>
      <div class="header-sub">Active Directory user accounts &middot; SDProp orphan classification &middot; Well-known RIDs</div>
    </div>
  </div>
  <div class="header-meta">
    <div><span>Generated</span> $genDate</div>
    <div><span>Duration</span> ${duration}s</div>
    <div><span>Search base</span> $SearchBase</div>
    <div><span>Version</span> $scriptVersion</div>
  </div>
</header>

<div class="stats">
  <div class="stat blue">
    <div class="stat-label">Scanned</div>
    <div class="stat-value">$total</div>
    <div class="stat-sub">user accounts</div>
  </div>
  <div class="stat amber">
    <div class="stat-label">Affected</div>
    <div class="stat-value">$affectedCount</div>
    <div class="stat-sub">inheritance disabled</div>
  </div>
  <div class="stat orange">
    <div class="stat-label">Orphan</div>
    <div class="stat-value">$orphanCount</div>
    <div class="stat-sub">safe to fix</div>
  </div>
  <div class="stat purple">
    <div class="stat-label">Review</div>
    <div class="stat-value">$reviewCount</div>
    <div class="stat-sub">needs attention</div>
  </div>
  <div class="stat green">
    <div class="stat-label">Fixed</div>
    <div class="stat-value">$fixedCount</div>
    <div class="stat-sub">this run</div>
  </div>
  <div class="stat gray">
    <div class="stat-label">Skipped</div>
    <div class="stat-value">$skippedSdprop</div>
    <div class="stat-sub">SDProp active</div>
  </div>
</div>

<div class="legend">
  <div class="legend-item">
    <span class="badge b-orphan"><span class="badge-dot"></span>ORPHAN</span>
    adminCount=0/null &middot; not in protected group &middot; safe to fix
  </div>
  <div class="legend-item">
    <span class="badge b-review"><span class="badge-dot"></span>REVIEW</span>
    still in protected group &middot; manual review required
  </div>
  <div class="legend-item">
    <span class="badge b-skip"><span class="badge-dot"></span>SKIP</span>
    adminCount=1 &middot; SDProp active &middot; excluded
  </div>
</div>

<div class="section-head">
  <h2>Affected accounts</h2>
  <span class="count">$affectedCount result(s)</span>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Account</th>
        <th>Display name</th>
        <th>Status</th>
        <th>Category</th>
        <th>adminCount</th>
        <th>Department</th>
        <th>OU path</th>
        <th>Fix status</th>
      </tr>
    </thead>
    <tbody>
      $tableRows
    </tbody>
  </table>
</div>

<footer class="footer">
  <div class="footer-brand">
    <div class="dot"></div>
    <span>9 Lives IT Solutions</span>
  </div>
  <p>Invoke-ACLInheritanceAudit v$scriptVersion &middot; $closeDate &middot; RIDs 512,518,519,520 + 544,548,549,550,551,552</p>
</footer>

</div>
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
