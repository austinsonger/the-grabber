# ECR inventory: one row per in-use image

## Problem

`collect_containers` (`src/inventory_orchestrator/compute.rs`) writes **one
`Container Image` row per ECR repository**, keyed by the repository URI and
carrying only the newest pushed image's `ImageDigest`. Older images that are
still deployed never appear in the inventory.

`--check-ecr-inventory` showed the effect on the 2026-09-16 federal/security
run: 61 Inspector findings (36 + 19 + 6 CVEs) sit on images in
`tetrate-io/tis-fips`, `webapp-base` and `websocket-server` whose digests are
not the newest push, so they have no matching inventory asset. FedRAMP's
container scanning requirements expect every production image class that
carries vulnerabilities to have a unique asset identifier in the Integrated
Inventory Workbook.

Secondary bug: `describe_images` is called once without pagination, so a
repository with more images than one page returns (100 by default) has
`ImageCount`/`OldestPush` silently truncated. No repository is that large today
(largest: 72).

## Proposal

No hard-coded windows. Which images count as in use, and for how long, comes
from each account's own Inspector configuration at collection time.

1. **Paginate** `describe_images` (`.into_paginator().items().send()`).
2. **Read in-use status from Inspector.** Call `inspector2 ListCoverage`
   filtered to `AWS_ECR_CONTAINER_IMAGE` for the account/region. Each resource's
   `resourceMetadata.ecrImage` carries `in_use_count` and `last_in_use_at`
   (`EcrContainerImageMetadata`, confirmed in aws-sdk-inspector2 1.110.0). These
   are the same values behind the findings CSV's `Currently In Use` / `In Use
   Count` columns, so inventory and findings share one definition of "in use".
3. **Derive the window from the account's Inspector config.** Call
   `inspector2 GetConfiguration` and read `ecrConfiguration.rescanDurationState`:
   - `pull_date_rescan_mode` decides which timestamp governs:
     `LAST_IN_USE_AT` → compare against `last_in_use_at`;
     `LAST_PULL_DATE` → compare against ECR `lastRecordedPullTime`.
   - `pull_date_rescan_duration` (`DAYS_14`/`30`/`60`/`90`/`180`) is the window.
   - `rescan_duration = LIFETIME` means Inspector keeps every image monitored,
     so every image is included.
   An image is included when `in_use_count > 0`, or its governing timestamp
   falls inside the window. That is the exact set Inspector is still scanning,
   which is the set that can produce findings.
4. **Always include the newest image** per repository, so every repository keeps
   at least one row (today's output stays a subset of the new output). Keep the
   repository-only row for repositories with zero images.
5. **Inspector ECR scanning disabled or config unreadable** (`AccessDenied`,
   not enabled): no findings can exist for that account, so emit every image
   with `InUseSource: unavailable` in `Comments`. Nothing is guessed and nothing
   is dropped. Log a WARN naming the account/region.
6. **Row shape.** Unique asset identifier `<repo_uri>@<digest>` (the standard
   pullable image reference, stable across tag moves). Per-image `Comments`:
   `ImageDigest`, `ImageTags`, `PushedAt`, `LastRecordedPullTime`,
   `InUseCount`, `LastInUseAt`, `InUseSource` (`inspector` | `unavailable`),
   `InUseWindow` (e.g. `LAST_IN_USE_AT/DAYS_30`, recorded so an auditor can see
   which rule applied). Repository-level fields repeat on each row.
7. `--check-ecr-inventory` keeps working unchanged (`RepositoryArn` and
   `ImageDigest` stay in `Comments`); add a test for the per-image row shape.

## Permissions

Adds `inspector2:ListCoverage` and `inspector2:GetConfiguration` to the
inventory run. Missing permissions fall under step 5 rather than failing the
inventory.

## Open question

- **Workbook size.** Row count grows from ~53 to the number of in-use images.
  Check against a real account before shipping.

## Touches

- `src/inventory_orchestrator/compute.rs` — `collect_containers`, plus an
  Inspector2 client passed in from the orchestrator.
- `src/inventory_orchestrator/mod.rs` — construct/pass the Inspector2 client.
- `src/ecr_inventory_check.rs` — test for the per-image row shape.
- `README.md` — IAM permissions list.
- `CHANGELOG.md` — `Changed`: inventory lists in-use container images
  individually; the unique asset identifier changes from repo URI to
  `repo_uri@digest` (breaks row-for-row diffs against earlier inventories).
  `Fixed`: image count / oldest push could be truncated for very large
  repositories.
