# Invoke-ACLInheritanceAudit

> PowerShell audit tool for detecting and remediating disabled ACL inheritance on Active Directory user accounts.

Developed and maintained by **[9 Lives IT Solutions](https://github.com/9LivesITSolutions)** — Healthcare IT consulting · Infrastructure · Security.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-informational.svg)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)]()

---

## Overview

Active Directory's SDProp mechanism disables ACL inheritance on accounts that are members of privileged groups (Domain Admins, Schema Admins, etc.). When those accounts lose their privileged group membership, SDProp never restores the inheritance — leaving orphaned objects with broken ACL inheritance indefinitely.

This script scans all user objects in a domain (or a scoped OU), identifies accounts with disabled inheritance, and classifies each finding into actionable categories. It can optionally remediate ORPHAN accounts automatically.

Protected groups are resolved via **well-known RIDs** (language-independent — works on any locale).

---

## Features

- Detects all user accounts with disabled ACL inheritance
- Classifies findings into three categories: `ORPHAN`, `REVIEW`, `SKIP`
- Resolves SDProp-protected groups via well-known RIDs (no hardcoded group names)
- Recursive group membership check via `tokenGroups` LDAP attribute
- Handles DN special characters (accents, spaces) using `ObjectGUID` instead of path-based access
- Automatically excludes `MSOL_*` / `AADConnect_*` / `krbtgt` accounts
- Distinguishes `adminCount=0` (SDProp residue) from `adminCount=null` (rights removed, inheritance never restored)
- Optional auto-remediation: re-enables inheritance and clears `adminCount` on ORPHAN accounts
- Exports HTML report (dark theme, stat cards, badge classification) and CSV
- Full `-WhatIf` support via `SupportsShouldProcess`
- Progress bar and color-coded console output

---

## Classification

| Category | Condition | Recommended Action |
|---|---|---|
| `SKIP` | `adminCount=1` | Do nothing — SDProp is active, fixing has no lasting effect |
| `ORPHAN` | `adminCount=0/null` + not in any protected group | Safe to fix: re-enable inheritance + clear `adminCount` |
| `REVIEW` | `adminCount=0/null` + still member of a protected group | Manual review — SDProp inconsistency |

---

## Requirements

| Dependency | Version |
|---|---|
| PowerShell | >= 5.1 |
| ActiveDirectory module (RSAT) | Any |
| AD read access | Required for audit |
| AD write access | Required for `-FixInheritance` |

---

## Installation

```powershell
# Clone the repository
git clone https://github.com/9LivesITSolutions/Invoke-ACLInheritanceAudit.git
cd Invoke-ACLInheritanceAudit
```

No dependencies to install. The script requires only the built-in `ActiveDirectory` PowerShell module (part of RSAT).

---

## Usage

```powershell
# Audit entire domain (read-only)
.\Invoke-ACLInheritanceAudit.ps1

# Scope to a specific OU
.\Invoke-ACLInheritanceAudit.ps1 -SearchBase "OU=CORP,DC=contoso,DC=local"

# Audit and auto-fix ORPHAN accounts
.\Invoke-ACLInheritanceAudit.ps1 -SearchBase "OU=CORP,DC=contoso,DC=local" -FixInheritance

# Audit enabled accounts only
.\Invoke-ACLInheritanceAudit.ps1 -EnabledOnly

# Preview fix without applying (WhatIf)
.\Invoke-ACLInheritanceAudit.ps1 -FixInheritance -WhatIf

# Custom output path
.\Invoke-ACLInheritanceAudit.ps1 -OutputPath "C:\Reports"
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-SearchBase` | `string` | Domain root | OU DistinguishedName to scope the search |
| `-OutputPath` | `string` | Script directory | Folder for HTML and CSV output files |
| `-FixInheritance` | `switch` | `$false` | Re-enable inheritance on ORPHAN accounts and clear `adminCount` |
| `-EnabledOnly` | `switch` | `$false` | Only scan enabled user accounts |

---

## Output

Two files are generated on each run, timestamped (`yyyyMMdd_HHmmss`):

| File | Description |
|---|---|
| `ACLInheritanceAudit_<timestamp>.html` | Dark-theme HTML report with stat cards and badge classification |
| `ACLInheritanceAudit_<timestamp>.csv` | Full CSV export of all affected accounts |

### HTML Report Columns

`SamAccountName` · `DisplayName` · `Account status` · `Category` · `adminCount` · `Department` · `OU Path` · `Fix Status`

---

## Protected Groups (Well-Known RIDs)

The following groups are resolved dynamically via their well-known SIDs:

| RID | Group |
|---|---|
| `S-1-5-<domain>-512` | Domain Admins |
| `S-1-5-<domain>-518` | Schema Admins |
| `S-1-5-<domain>-519` | Enterprise Admins |
| `S-1-5-<domain>-520` | Group Policy Creator Owners |
| `S-1-5-32-544` | Administrators (BUILTIN) |
| `S-1-5-32-548` | Account Operators (BUILTIN) |
| `S-1-5-32-549` | Server Operators (BUILTIN) |
| `S-1-5-32-550` | Print Operators (BUILTIN) |
| `S-1-5-32-551` | Backup Operators (BUILTIN) |
| `S-1-5-32-552` | Replicator (BUILTIN) |

---

## Excluded Accounts

The following accounts are always excluded from scanning and remediation:

| Pattern | Reason |
|---|---|
| `MSOL_*` | AAD Connect service account — modifying ACL breaks directory sync |
| `AADConnect_*` | AAD Connect alternate naming |
| `krbtgt` | Kerberos ticket-granting account |

---

## Notes on adminCount

| Value | Meaning |
|---|---|
| `1` | SDProp is currently active on this account |
| `0` | SDProp previously set this value; account no longer privileged but inheritance was never restored |
| `null` | `adminCount` was cleared or never set by SDProp — likely a former privileged account whose `adminCount` was manually cleared, or a manual ACL change |

---

## Project Structure

```
Invoke-ACLInheritanceAudit/
├── Invoke-ACLInheritanceAudit.ps1   # Main script
├── README.md
├── CHANGELOG.md
└── LICENSE
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'feat: add your-feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
