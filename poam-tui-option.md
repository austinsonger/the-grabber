# POAM TUI Option

## Goal
Add a third TUI feature (`POAM`) that runs a single-account local reconciliation flow: pick region/year/month, resolve the security evidence folder, select the newest Inspector2 ECR CSV, reconcile with `FedRAMP-POAM.xlsx`, and show added/closed/error counts in Results.

## Tasks
- [ ] Task 1: Extend TUI mode/state for POAM in [src/tui/mod.rs](/Users/austin-songer/code/grabber/src/tui/mod.rs) and [src/tui/ui.rs](/Users/austin-songer/code/grabber/src/tui/ui.rs) (`Feature::Poam`, POAM-only screens for region/year/month, POAM summary fields in `App`). → Verify: `rg -n "Feature::Poam|PoamRegion|PoamYear|PoamMonth|poam_" src/tui/mod.rs src/tui/ui.rs`.
- [ ] Task 2: Update feature-selection UI to include `POAM` as a third card and wire step indicator mappings for POAM flow (`Region -> Year -> Month -> Confirm -> Run`). → Verify: start TUI and confirm “What would you like to do?” shows `Collectors`, `Inventory`, `POAM`.
- [ ] Task 3: Add POAM keyboard handling + validation in [src/tui/mod.rs](/Users/austin-songer/code/grabber/src/tui/mod.rs): single region required, year defaults to current year but editable, month uses human month names and maps to `MM-MMM`. → Verify: TUI blocks Enter when POAM fields are invalid and allows advance when valid.
- [ ] Task 4: Add POAM domain module [src/poam.rs](/Users/austin-songer/code/grabber/src/poam.rs) with helpers to resolve `evidence-output/security/<region>/<year>/<MM-MMM>/`, parse month names, and select latest `Corporate_Security_Inspector2_ECR_Findings-YYYY-MM-DD-######.csv`. → Verify: unit tests for month mapping + CSV filename ordering pass.
- [ ] Task 5: Implement CSV ingestion in [src/poam.rs](/Users/austin-songer/code/grabber/src/poam.rs) keyed by `Finding ARN`, with typed accessors for required mapping fields (title, description, severity, CVE, remediation, scores, timestamps). → Verify: unit test with fixture CSV covers required columns and missing-field warnings.
- [ ] Task 6: Implement POA&M workbook reconciliation in [src/poam.rs](/Users/austin-songer/code/grabber/src/poam.rs): read `evidence-output/poam/FedRAMP-POAM.xlsx`, match `Weakness Source Identifier` to `Finding ARN`, append new Open rows, move resolved Open rows to Closed, preserve sheet header offsets (Open row 5, Closed row 2). → Verify: test workbook fixture shows expected add/move counts and row placement.
- [ ] Task 7: Implement POAM field mapping + derivations in [src/poam.rs](/Users/austin-songer/code/grabber/src/poam.rs): `POAM ID`, `Original Risk Rating`, `Original Detection Date`, `Status Date`, `Remediation Plan`, `Vendor Dependency`, `CVE`, comments/supporting-doc path; leave manual fields blank. → Verify: snapshot/assertion test checks mapped cell values for one synthetic finding.
- [ ] Task 8: Wire POAM execution path in [src/main.rs](/Users/austin-songer/code/grabber/src/main.rs) as a separate branch from collectors/inventory: skip AWS SDK prep, run POAM logic during Running screen, send completion payload to Results, and fail gracefully when no matching CSV exists. → Verify: POAM run with missing CSV ends in Results with clear error, not panic.
- [ ] Task 9: Extend Results rendering in [src/tui/ui.rs](/Users/austin-songer/code/grabber/src/tui/ui.rs) for POAM mode to show region/year/month, resolved evidence path, selected CSV name, `added_open_count`, `moved_closed_count`, and warnings/errors. → Verify: manual run displays all required summary lines in Results.
- [ ] Task 10: Verification (last): run `cargo fmt`, `cargo check`, and targeted tests for POAM helpers/reconciliation; then perform one end-to-end POAM TUI run against existing local evidence paths. → Verify: commands succeed and end-to-end run updates workbook + shows non-empty POAM summary.

## Done When
- [ ] TUI includes `POAM` and follows the requested flow exactly: `Welcome -> FeatureSelection(POAM) -> Region -> Year -> Month -> Confirm -> Running -> Results`.
- [ ] Evidence path resolution and CSV selection behavior matches spec, including graceful “no CSV found” handling.
- [ ] `FedRAMP-POAM.xlsx` Open/Closed reconciliation works with `Finding ARN <-> Weakness Source Identifier` key and reports added/closed/warnings in Results.
- [ ] Existing `Collectors` and `Inventory` flows remain unchanged.

## Notes
- Re-open behavior policy: if finding exists in Closed and appears again in current CSV, first implementation should log warning and treat as new Open row (or skip with warning); keep policy isolated in one function for later change.
- Because this feature edits `.xlsx` data in place across two sheets, prefer a dedicated workbook read/write path in `src/poam.rs` with fixture-based tests before wiring TUI.
