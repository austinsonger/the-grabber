# ECR findings match the inventory

Status: implemented. Supersedes
`2026-09-16-ecr-production-image-check.md` (production-image check) and the
earlier CSV-comparison check.

## Requirement

Every ECR image digest listed in the inventory (`AWS_Inventory-*.csv`,
`Container Image` rows) must have **all of its ACTIVE Inspector2
vulnerabilities** in the ECR findings output
(`*_Inspector2_ECR_Image_Findings-*.csv`), attributed to that inventory asset.
The inventory decides which digests matter; which image production runs is out
of scope.

## FedRAMP rules this follows

1. **One POA&M item per unique vulnerability, all affected assets listed.**
   Official POA&M template, Asset Identifier column: "Enter the corresponding
   unique asset ID specified in the Integrated Inventory Workbook (IIW)…
   Include the complete identifier name (no short hand). If multiple assets are
   affected, separate each by a new line."
   (https://www.fedramp.gov/resources/templates/FedRAMP-POAM-Template.xlsx)
2. **Never group different vulnerabilities.** "CSPs must not group multiple
   unique vulnerabilities into a single POA&M item." A CSP *may* split one
   vulnerability into several items.
   (https://www.fedramp.gov/legacy/playbook/csp/authorization/poam/)
3. **Vulnerability identity is the scanner's ID.** Template: "include the
   vulnerability identifier provided by the scanner (plugin ID)." For Inspector2
   this is the vulnerability ID (normally the CVE), not the per-image finding ARN.
4. **Container assets are image classes in the IIW.** "A unique asset
   identifier must be assigned to every class of image which corresponds to one
   or more production-deployed containers. These image-based asset identifiers
   must be documented in the FedRAMP Integrated Inventory Workbook Template."
   Individual container instances "do not need to be included".
   (https://www.fedramp.gov/resources/documents/Vulnerability_Scanning_Requirements_for_Containers.pdf)

## Why the current output fails the requirement

- The inventory row carries the newest pushed digest per repository; the
  findings collector keeps findings for the newest pushed image *that has
  findings* (`filter_latest_image_per_repo`). These differ, so findings land on
  digests the inventory doesn't list (61 findings on 2026-09-16).
- Findings are date-filtered by `first_observed_at`, so older ACTIVE
  vulnerabilities on an inventoried digest are left out.
- Rolled-up rows list raw ECR ARNs joined by `; ` instead of inventory asset IDs.
- Collected from the security account, the collector cannot list the Ops
  registry, so it silently fell back to the old image choice.

## Design

### Data flow

```
Inventory run (unchanged)
  AWS_Inventory-<ts>.csv  — Container Image row: UNIQUE ASSET IDENTIFIER,
                            Comments: RepositoryArn, ImageDigest

ECR findings run (changed)
  1. Newest inventory/**/AWS_Inventory-*.csv; none → error "run inventory first"
  2. Container Image rows with an ImageDigest, for this run's account/region
  3. Image index digests → per-platform digests (ecr:BatchGetImage)
  4. Per digest: inspector2:ListFindings  repository + image hash + ACTIVE
  5. Group by (CVE ID, Package Name) — the existing rollup key; one row each
  6. Write *_Inspector2_ECR_Image_Findings-<ts>.csv

Check (separate command and TUI section)
  per inventory asset: live Inspector ACTIVE IDs  vs  IDs whose rows list the asset
```

### Components

1. **`src/providers/aws/inspector_ecr/inventory_digests.rs` (new, pure).**
   Finds the newest `inventory/**/AWS_Inventory-*.csv` and returns
   `InventoryImage { asset_id, account, region, repository, repository_arn,
   digest }` for every `Container Image` row with a digest. Rows without a
   digest (e.g. empty repositories) are counted and logged, not returned.
2. **Findings collector (`inspector_ecr/mod.rs`), changed.**
   - Scope: inventory images whose account and region match the run. From the
     Inspector2 delegated-admin account, member-account images are included
     (Inspector exposes them there).
   - Image indexes: detected by manifest media type
     (`application/vnd.oci.image.index.v1+json`,
     `application/vnd.docker.distribution.manifest.list.v2+json`) and expanded
     to platform digests, skipping attestation manifests (`os: unknown`).
     Findings on a platform digest are attributed to the inventory asset of the
     index. If the index cannot be read, the asset is logged and left for the
     check to report.
   - Query: `ListFindings` with `ecrImageRepositoryName`, `ecrImageHash`,
     `findingStatus = ACTIVE`, paginated. No date filter.
   - Existing columns are kept (the POA&M readers depend on them). Changes:
     - New column **`Asset Identifier`**: inventory `UNIQUE ASSET IDENTIFIER`
       values of every affected asset, newline-separated, sorted, de-duplicated.
     - New column **`Inventory File`**: basename of the inventory CSV used.
     - `Resource ID`, `Repository Name`, `Image Hash`, `Image Tags`: newline-
       separated per affected image (was `; `), same order as each other.
   - Grouping: `rollup_ecr_by_cve` keeps its key, (CVE ID, Package Name). This
     never merges different vulnerability IDs (rule 2) and splitting one CVE by
     package is permitted (rule 2). Keeping the key avoids changing existing
     POA&M item identity.
   - Removed from this collector: `filter_latest_image_per_repo`,
     `dedup_ecr_image_rows`, the `first_observed_at` date filter, the
     `MAX_ROWS_PER_SEVERITY` severity loop.
3. **Check: `--check-ecr-findings`** (`src/ecr_findings_check.rs`, new).
   - Inputs: newest inventory CSV and newest ECR findings CSV (paths printed),
     plus `--profile`/`--region` for live Inspector2 queries.
   - Per inventory container asset:
     - Live: set of ACTIVE vulnerability IDs (CVE ID) across its digest or
       platform digests, and Inspector2 coverage status/reason.
     - CSV: set of CVE IDs from rows whose `Asset Identifier` lists the asset.
     - Result: `OK` (sets equal), `MISSING_IN_CSV`, `EXTRA_IN_CSV`,
       `NO_SCAN_DATA` (not covered, or `INACTIVE` with reason). All but `OK`
       are failures.
   - Output: `ECR-Findings-Check-<ts>.csv` next to the findings CSV — asset ID,
     digest(s), scan status, reason, Inspector count, CSV count, missing IDs,
     extra IDs, result. Summary with a count per result. Exit 1 on any failure.
4. **TUI:** feature-screen entry "ECR Findings Check" with its own screens:
   profile/region → shows the two files that will be used → confirm → results
   (summary + report path). Never runs as part of Inventory. Touches the six
   TUI files listed in CLAUDE.md.

### Errors and edge cases

| Case | Behaviour |
|---|---|
| No inventory CSV | Collector fails: "run inventory first"; no findings file. |
| Inventory older than 24h | WARN with its age; continue. |
| Inventory image with 0 ACTIVE findings | No findings rows; check shows it `OK` with count 0 (or `NO_SCAN_DATA` if not scanned). |
| Digest not in Inspector2 coverage / `SCAN_ELIGIBILITY_EXPIRED` / `UNSUPPORTED_MEDIA_TYPE` | Collector logs it; check reports `NO_SCAN_DATA` with reason. |
| Image index unreadable | Collector WARN; check reports `NO_SCAN_DATA` ("index not expanded"). |
| Inventory account/region not reachable from this run | Skipped with WARN naming the asset. |

## Permissions (read-only)

Findings run: `inspector2:ListFindings`, `ecr:BatchGetImage` on the registry.
Check: `inspector2:ListFindings`, `inspector2:ListCoverage`.

## Testing

- Unit: inventory parsing (digest present/absent, repository ARN with `/`);
  index manifest expansion (attestations skipped); grouping (same CVE+package
  across assets → one row with newline-separated asset IDs; different CVEs →
  separate rows); check set comparison for each result.
- Live, read-only, federal: inventory → ECR findings from
  `fed:SecurityAdmin-132576345808` → check. Expect every covered asset `OK`;
  the 23 `SCAN_ELIGIBILITY_EXPIRED`, 2 `UNSUPPORTED_MEDIA_TYPE` (if not
  expanded) and 1 uncovered digest seen on 2026-09-16 as `NO_SCAN_DATA`.

## Cleanup in the same change

- Remove `src/ecr_production_images.rs`, `--check-ecr-production`,
  `--org-profile`, `--prod-tag` and their CHANGELOG entry (uncommitted).
- Remove `--check-ecr-inventory` (commit `3e39bb8`) and its CHANGELOG entry.
- Keep the ECR `describe_images` pagination fix in inventory and its `Fixed`
  entry.
- Delete `docs/plans/2026-09-16-ecr-production-image-check.md` (superseded).
- CHANGELOG `Changed`: ECR image findings now cover exactly the inventory's
  image digests, include all ACTIVE vulnerabilities regardless of the date
  range, and list inventory asset identifiers one per line. Describe the old
  wrong output: findings attached to digests not in the inventory, and older
  ACTIVE findings omitted by the date range. `Added`: `--check-ecr-findings`
  and the TUI section.

## Open question for review

- The memory note "Inspector2 date filtering — always use first_observed_at"
  assumed findings are period-scoped. This spec removes the period scope for
  ECR image findings (all ACTIVE). Confirm that monthly ConMon evidence should
  show all open vulnerabilities, not only newly observed ones.
