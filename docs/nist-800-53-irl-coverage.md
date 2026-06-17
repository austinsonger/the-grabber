# NIST 800-53 IRL Coverage — Grabber

Generated 2026-06-16. Based on `framework_mapping/evidence-list.json` after the NIST 800-53 expansion (Tasks 1-57). Source IRL: A-LIGN NIST 800-53 IRL (Report-3.xlsx — 558 rows, 555 "General" + 2 "Policy").

## Summary

| Category | Count |
|---|---|
| Total IRL requirements | 558 |
| Policy/Procedure (manual, never automatable) | 2 |
| "General" requirements | 555 |
| Likely covered by automated grabber evidence | ~420 (estimate) |
| Inherited from AWS shared responsibility (PE, AT, MA, PS) | ~95 |
| Likely gaps requiring manual evidence | ~40 |

## Coverage by NIST family

Mapping of each NIST 800-53 family to the grabber evidence collectors that satisfy it. Counts refer to evidence-list.json entries with that control ID under `framework_refs.NIST_800_53.controls`.

| Family | Coverage | Lead collectors (EV IDs) |
|---|---|---|
| AC (Access Control) | strong | EV6–EV19 IAM, EV131 Cred Report, EV132 Access Advisor, EV134 IdC, EV173 Org Delegated |
| AT (Awareness & Training) | inherited | — (manual / HR system) |
| AU (Audit & Accountability) | strong | EV21–EV29 CloudTrail, EV125–EV130 new CT, EV37–EV42 CW, EV75 VPC FL, EV91 ALB, EV99 S3 logging, EV138 Logs Insights, EV139 EB Archives |
| CA (Assessment, Authorization, Monitoring) | strong | EV30–EV35 Config, EV103–EV105 SecHub, EV100–EV101 GD, EV171 TA, EV175 AuditManager |
| CM (Configuration Management) | strong | EV30–EV36 Config + Drift, EV43–EV50 EC2/EBS, EV124 tagging, EV174 Control Tower, EV176 Resource Explorer |
| CP (Contingency Planning) | strong | EV2, EV3/EV59, EV58, EV122–EV123, EV146–EV151 (vault-lock, copy, restore-testing, DRS, R53 ARC, RDS PITR, S3 replication/lock) |
| IA (Identification & Auth) | strong | EV6, EV8, EV11, EV16, EV66, EV131, EV134, EV135, EV136, EV137 |
| IR (Incident Response) | medium | EV100–EV102 GD, EV103 SecHub, EV29 IAM changes, EV172 Health |
| MA (Maintenance) | inherited | — (AWS shared responsibility) |
| MP (Media Protection) | partial | EV93–EV96 S3 encryption, EV153 ObjectLock, EV179 Macie Jobs |
| PE (Physical & Environmental) | inherited | — (AWS data-center) |
| PL (Planning) | inherited | — (organizational) |
| PS (Personnel Security) | inherited | — (HR system) |
| RA (Risk Assessment) | strong | EV17 Access Analyzer, EV100/EV103/EV106 findings, EV109 Macie, EV157 Inspector Coverage, EV158 Suppression |
| SA (System & Services Acquisition) | medium | EV36 CFN drift, EV46 launch templates, EV53 ECR, EV169 Artifact, EV170 CodePipeline/Build, EV175 AuditManager |
| SC (System & Comms Protection) | strong | EV48–EV50, EV57/EV60–EV62, EV63–EV67, EV87, EV89–EV90, EV92–EV96, EV110–EV112, EV159–EV165 (WAF dest, TGW, PrivateLink, R53 DNS FW, KMS Grants, AppMesh TLS) |
| SI (System & Info Integrity) | strong | EV100–EV108, EV113–EV121, EV37/EV40, EV140, EV143–EV145, EV154–EV158 |
| SR (Supply Chain) | medium | EV53, EV106a, EV166–EV170 (Signer, ECR sigs, CodeArtifact, Artifact, CodePipeline) |

## How to derive a per-Req-ID coverage matrix

For each Req ID in the IRL:
1. Parse the `Requirement` cell (column F) — extract distinct NIST control IDs (e.g. `AC-01a.[01][02]` → base control `AC-1`).
2. Look up each base control across all entries in `framework_mapping/evidence-list.json` under `framework_refs.NIST_800_53.controls`.
3. Union the matching `evidence_id`s → that's the coverage for that Req ID.

A future enhancement (`src/irl/` module) can perform this join automatically and write a per-Req-ID CSV. For now, the family-level mapping above is the operational guide.

## Inherited / non-automatable

Items keyed to PE, AT, full PS-*, MA, and most PL controls cannot be collected by AWS APIs. These should reference the AWS FedRAMP/SOC2/ISO Artifact packages (see EV169) and organizational policy/training records.

## Known gaps requiring manual evidence

- Privacy program docs (PT family if in scope)
- Personnel screening records (PS-3)
- Security awareness training records (AT-2, AT-3, AT-4)
- Physical access logs (PE-*)
- BCP/IR tabletop exercise minutes (CP-4 narratives, IR-3 narratives)
- SBOM attestations (partial — EV167 covers ECR signatures, but third-party SaaS SBOMs are manual)
- Vendor risk reviews (SR-6)
