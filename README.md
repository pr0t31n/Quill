# Quill — iOS IPA Static Analyser

Quill extracts and statically analyses iOS .ipa bundles for common
security misconfigurations and hard-coded secrets.

## Checks (v0.3.0)

| Phase | Output | Detects |
|-------|--------|---------|
| extract | Payload/*.app extracted | Bundle structure |
| info_plist | info_plist.json | ATS exceptions, custom URL schemes, background modes |
| entitlements | entitlements.xml | get-task-allow, wildcard application-identifier (macOS only) |
| strings | string_findings.txt | AWS keys, Google API keys, Slack tokens, private keys |

## Requirements

- Python 3.10+
- `strings` binutils (auto-installed on Linux)
- `codesign` (macOS host only — for entitlements analysis)

## Install

```bash
python3 install.py
```

## Usage

```bash
python3 quill.py --ipa MyApp.ipa
```

## Output

Run directories follow the pr0t31n universal structure (CLAUDE.md §13):

```
<clients_base>/<client_short>/<year>/quill/<client_short>_<ts>/
├── meta.json
├── findings.json                # universal findings (risk UPPERCASED)
├── findings.csv                 # CSV mirror
├── summary.json                 # risk_counts + timing
├── scan.log / scan.log.json     # timestamped event log (§13b/§14f)
├── errors.log / errors.log.json # ERROR-level + TOOL_ERROR (codesign/strings failures)
├── extract/Payload/*.app        # extracted bundle
├── info_plist.json              # + info_plist.json.log    (§14i analysis transcript)
├── entitlements.xml             # + entitlements.xml.log   (§14 codesign tool .log)
├── strings_raw.txt              # + strings_raw.txt.log    (§14 strings tool .log)
└── string_findings.txt          # + string_findings.txt.log (§14i analysis transcript)
```

Subprocess tools (`codesign`, `strings`) emit a `<output>.log` sibling (§14 via
`pr0t31n_tool_runner`); built-in (`plistlib`) and aggregation steps emit an
analysis-transcript `.log` (§14i). Every finding's `output_file` references
**both** its evidence file **and** that file's `.log`, run-dir-relative.

## Token protocol

Set `QUILL_MANAGED=1` for `__VANTAGE_*` token output.
