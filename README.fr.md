# Invoke-ACLInheritanceAudit

> Outil d'audit PowerShell pour détecter et corriger l'héritage ACL désactivé sur les comptes utilisateurs Active Directory.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-informational.svg)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)]()
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)]()

[English version](README.md)

---

## Présentation

Le mécanisme SDProp d'Active Directory désactive l'héritage des ACL sur les comptes membres de groupes privilégiés (Domain Admins, Schema Admins, etc.). Lorsque ces comptes quittent les groupes privilégiés, SDProp ne rétablit jamais l'héritage : les objets orphelins gardent indéfiniment un héritage ACL cassé.

Ce script analyse tous les objets utilisateur d'un domaine (ou d'une OU), identifie les comptes dont l'héritage est désactivé et classe chaque résultat dans une catégorie exploitable. Il peut en option corriger automatiquement les comptes ORPHAN.

Les groupes protégés sont résolus via les **RID connus** (indépendant de la langue : fonctionne sur n'importe quelle locale).

---

## Fonctionnalités

- Détecte tous les comptes utilisateur dont l'héritage ACL est désactivé
- Classe les résultats en trois catégories : `ORPHAN`, `REVIEW`, `SKIP`
- Résout les groupes protégés par SDProp via les RID connus (aucun nom de groupe codé en dur)
- Vérification récursive de l'appartenance aux groupes via l'attribut LDAP `tokenGroups`
- Gère les caractères spéciaux des DN (accents, espaces) en utilisant `ObjectGUID` plutôt qu'un accès par chemin
- Exclut automatiquement les comptes `MSOL_*` / `AADConnect_*` / `krbtgt`
- Distingue `adminCount=0` (résidu SDProp) de `adminCount=null` (droits retirés, héritage jamais rétabli)
- Correction automatique optionnelle : rétablit l'héritage et efface `adminCount` sur les comptes ORPHAN
- Export d'un rapport HTML (thème sombre, cartes de statistiques, badges de classification) et d'un CSV
- Prise en charge complète de `-WhatIf` via `SupportsShouldProcess`
- Barre de progression et sortie console colorée

---

## Classification

| Catégorie | Condition                                                  | Action recommandée                                                     |
| --------- | ---------------------------------------------------------- | ---------------------------------------------------------------------- |
| `SKIP`    | `adminCount=1`                                             | Ne rien faire — SDProp est actif, une correction n'aurait aucun effet durable |
| `ORPHAN`  | `adminCount=0/null` + membre d'aucun groupe protégé        | Correction sûre : rétablir l'héritage + effacer `adminCount`           |
| `REVIEW`  | `adminCount=0/null` + toujours membre d'un groupe protégé  | Revue manuelle — incohérence SDProp                                    |

---

## Prérequis

| Dépendance                    | Version                          |
| ----------------------------- | -------------------------------- |
| PowerShell                    | >= 5.1                           |
| Module ActiveDirectory (RSAT) | Toute version                    |
| Accès en lecture à l'AD       | Requis pour l'audit              |
| Accès en écriture à l'AD      | Requis pour `-FixInheritance`    |

---

## Installation

```
git clone https://github.com/9LivesITSolutions/Invoke-ACLInheritanceAudit.git
cd Invoke-ACLInheritanceAudit
```

Aucune dépendance à installer. Le script n'utilise que le module PowerShell `ActiveDirectory` intégré (fourni avec RSAT).

---

## Utilisation

```
# Auditer tout le domaine (lecture seule)
.\Invoke-ACLInheritanceAudit.ps1

# Limiter à une OU
.\Invoke-ACLInheritanceAudit.ps1 -SearchBase "OU=CORP,DC=contoso,DC=local"

# Auditer et corriger automatiquement les comptes ORPHAN
.\Invoke-ACLInheritanceAudit.ps1 -SearchBase "OU=CORP,DC=contoso,DC=local" -FixInheritance

# Auditer uniquement les comptes activés
.\Invoke-ACLInheritanceAudit.ps1 -EnabledOnly

# Prévisualiser la correction sans l'appliquer (WhatIf)
.\Invoke-ACLInheritanceAudit.ps1 -FixInheritance -WhatIf

# Dossier de sortie personnalisé
.\Invoke-ACLInheritanceAudit.ps1 -OutputPath "C:\Reports"
```

---

## Paramètres

| Paramètre         | Type     | Défaut                | Description                                                              |
| ----------------- | -------- | --------------------- | ------------------------------------------------------------------------ |
| `-SearchBase`     | `string` | Racine du domaine     | DistinguishedName de l'OU qui limite la recherche                        |
| `-OutputPath`     | `string` | Dossier du script     | Dossier des fichiers HTML et CSV                                         |
| `-FixInheritance` | `switch` | `$false`              | Rétablit l'héritage sur les comptes ORPHAN et efface `adminCount`        |
| `-EnabledOnly`    | `switch` | `$false`              | Analyse uniquement les comptes utilisateur activés                       |

---

## Sorties

Deux fichiers sont générés à chaque exécution, horodatés (`yyyyMMdd_HHmmss`) :

| Fichier                                | Description                                                             |
| -------------------------------------- | ----------------------------------------------------------------------- |
| `ACLInheritanceAudit_<timestamp>.html` | Rapport HTML en thème sombre avec cartes de statistiques et badges      |
| `ACLInheritanceAudit_<timestamp>.csv`  | Export CSV complet de tous les comptes concernés                        |

### Colonnes du rapport HTML

`SamAccountName` · `DisplayName` · `Account status` · `Category` · `adminCount` · `Department` · `OU Path` · `Fix Status`

---

## Groupes protégés (RID connus)

Les groupes suivants sont résolus dynamiquement via leurs SID connus :

| RID                  | Groupe                      |
| -------------------- | --------------------------- |
| `S-1-5-<domain>-512` | Domain Admins               |
| `S-1-5-<domain>-518` | Schema Admins               |
| `S-1-5-<domain>-519` | Enterprise Admins           |
| `S-1-5-<domain>-520` | Group Policy Creator Owners |
| `S-1-5-32-544`       | Administrators (BUILTIN)    |
| `S-1-5-32-548`       | Account Operators (BUILTIN) |
| `S-1-5-32-549`       | Server Operators (BUILTIN)  |
| `S-1-5-32-550`       | Print Operators (BUILTIN)   |
| `S-1-5-32-551`       | Backup Operators (BUILTIN)  |
| `S-1-5-32-552`       | Replicator (BUILTIN)        |

---

## Comptes exclus

Les comptes suivants sont toujours exclus de l'analyse et de la correction :

| Motif          | Raison                                                                         |
| -------------- | ------------------------------------------------------------------------------ |
| `MSOL_*`       | Compte de service AAD Connect — modifier l'ACL casse la synchronisation        |
| `AADConnect_*` | Nommage alternatif AAD Connect                                                 |
| `krbtgt`       | Compte du service de distribution de clés Kerberos                             |

---

## Notes sur adminCount

| Valeur | Signification                                                                                                                                              |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `1`    | SDProp est actuellement actif sur ce compte                                                                                                                |
| `0`    | SDProp avait positionné cette valeur ; le compte n'est plus privilégié mais l'héritage n'a jamais été rétabli                                              |
| `null` | `adminCount` a été effacé ou n'a jamais été positionné par SDProp — probablement un ancien compte privilégié dont `adminCount` a été effacé à la main, ou une modification manuelle de l'ACL |

---

## Structure du projet

```
Invoke-ACLInheritanceAudit/
├── Invoke-ACLInheritanceAudit.ps1   # Script principal
├── README.md
├── README.fr.md
├── CHANGELOG.md
└── LICENSE
```

---

## Contribuer

1. Forker le dépôt
2. Créer une branche (`git checkout -b feature/ma-fonctionnalite`)
3. Commiter (`git commit -m 'feat: add ma-fonctionnalite'`)
4. Pousser la branche (`git push origin feature/ma-fonctionnalite`)
5. Ouvrir une Pull Request

Merci de suivre les [Conventional Commits](https://www.conventionalcommits.org/) pour les messages de commit.

---

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](LICENSE).

---

Maintenu par **9 Lives IT Solutions** — Informatique de santé & automatisation d'infrastructure.
