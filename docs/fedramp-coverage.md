# FedRAMP Coverage & Evidence Self-Identification

Every evidence file grabber emits carries three metadata columns and a
manifest footer so an auditor can identify the file's mapping even after
it's been renamed, extracted from a bundle, or pasted into a working paper.

## Per-row columns

Every CSV row gets three trailing columns (right of all pre-existing columns):

| Column | Value |
|---|---|
| `FedRAMP Req IDs` | Pipe-separated, sorted list of NIST-1000-series Req IDs (e.g. `NIST-1043\|NIST-1519\|NIST-1535`). |
| `FedRAMP Control IDs` | Pipe-separated NIST 800-53 Moderate control IDs (e.g. `AC-02h.\|PS-04a-d\|PS-07d.`). |
| `Source Evidence File` | Basename of the emitted file (e.g. `123456789012_Okta_Deprovisioning_Timeliness-2026-07-16-142330.csv`). |

## Trailing footer

Every CSV ends with:

```
<blank row>
# FedRAMP Req IDs,NIST-1043|NIST-1519|NIST-1535
# Source Evidence File,123456789012_Okta_Deprovisioning_Timeliness-2026-07-16-142330.csv
```

## JSON manifest

Every JSON evidence file has a top-level `_fedramp_manifest` object:

```json
{
  "collected_at": "...",
  "records": [...],
  "_fedramp_manifest": {
    "req_ids": ["NIST-1043", "NIST-1519", "NIST-1535"],
    "control_ids": ["AC-02h.", "PS-04a-d", "PS-07d."],
    "source_evidence_file": "123456789012_Okta_Deprovisioning_Timeliness-2026-07-16-142330.json"
  }
}
```

## Per-run coverage report

After every run, grabber writes `<run-dir>/fedramp-coverage-actual.csv` with
one row per NIST-1000-series Req ID (all 193 in the FedRAMP Moderate IRL):

| Column | Value |
|---|---|
| `Req ID` | e.g. `NIST-1043` |
| `Control ID` | e.g. `AC-02h.` |
| `Family` | e.g. `AC` |
| `Description` | First sentence of the requirement text |
| `Collector Name` | Filename prefix of the collector that produced evidence, or blank |
| `Source Evidence File` | Basename of the emitted file, or blank |
| `Row Count` | Rows produced this run, or `0` |
| `Bucket` | `COVERED` or `UNCOVERED` |

## Adding a new collector's mapping

Edit `assets/fedramp-map.json` — no code change required. New collectors
inherit their mapping from the JSON via the `fedramp_mapping()` default
method on the `CsvCollector` / `JsonCollector` trait.
