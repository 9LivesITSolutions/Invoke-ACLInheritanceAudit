# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.0.0] - 2026-05-11

### Added
- SDProp orphan classification: `ORPHAN` vs `REVIEW` vs `SKIP` categories
- Protected group resolution via well-known RIDs (language-independent, no hardcoded names)
- Recursive group membership check via `tokenGroups` LDAP attribute with `MemberOf` fallback
- Explicit exclusion list for `MSOL_*`, `AADConnect_*`, and `krbtgt` accounts
- Distinction between `adminCount=0` (SDProp residue) and `adminCount=null` (cleared or never set)
- Auto-remediation skips `Clear adminCount` when attribute is `null` (no-op prevention)
- Fix log message reflects actual action taken (`adminCount cleared` vs `adminCount was null`)
- HTML report legend section explaining all three categories

### Changed
- ACL reading migrated from `Get-Acl -LiteralPath "AD:..."` to `nTSecurityDescriptor` via `ObjectGUID`
- All AD object lookups now use `ObjectGUID` instead of `DistinguishedName` to handle special characters
- HTML stat cards updated to 6 columns (added Orphan, Review, Excluded counts)
- `adminCount` stored as typed string in result objects for reliable null display

### Fixed
- `La syntaxe du nom de l'objet est incorrecte` errors on DNs with accents, spaces, or special characters
- `chemin d'accès introuvable` errors on objects in TRASH OUs or with unusual paths
- Misleading `manual ACL change suspected` message replaced with accurate dual-cause description
- Duplicate `$skippedExcluded` counter initialization removed
- `$adFilter = { * }` scriptblock replaced with `"*"` string for valid `Get-ADUser -Filter` syntax

---

## [1.0.0] - 2026-05-11

### Added
- Initial release
- Scan of all AD user accounts for disabled ACL inheritance
- `adminCount=1` exclusion (SDProp-managed accounts)
- HTML dark-theme report with stat cards and badge classification
- CSV export with timestamp
- `-FixInheritance` switch to re-enable inheritance and clear `adminCount`
- `-EnabledOnly` switch to scope scan to enabled accounts
- `-WhatIf` support via `SupportsShouldProcess`
- Progress bar and color-coded console output

---

<!-- Links -->
[Unreleased]: https://github.com/9LivesITSolutions/Invoke-ACLInheritanceAudit/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/9LivesITSolutions/Invoke-ACLInheritanceAudit/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/9LivesITSolutions/Invoke-ACLInheritanceAudit/releases/tag/v1.0.0
