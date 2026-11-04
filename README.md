# Quill v1.21.2 -- Mobile Application Security Analysis Tool

Quill is a dual-platform mobile application security analyser supporting iOS (IPA) and Android (APK) targets. It combines static binary analysis, Frida-based dynamic instrumentation, and MITM traffic capture into a single tool with three selectable analysis modes.

Quill integrates with Crucible v2 for managed execution, real-time log streaming, and cross-tool action-item pipelines that automatically queue Fracture and Siphon scans against discovered web and API targets.

---

## Features

### Dual Platform Support
- **iOS**: IPA extraction, Info.plist parsing, entitlements analysis, binary hardening checks (PIE, NX, stack canary, ARC, RPATH, FairPlay encryption, symbol stripping), framework analysis, permissions enumeration, runtime protection detection (jailbreak detection, certificate pinning)
- **Android**: APK extraction (apktool), AndroidManifest.xml analysis (debuggable, backup, cleartext, exported components, deep links), dangerous permissions enumeration, DEX-level SAST, native `.so` library scanning, network security configuration audit, Firebase detection, APK signing scheme analysis (v1/v2/v3 with Janus risk), APKiD packer/obfuscation detection, tracker SDK identification, behaviour pattern analysis

### Three Analysis Modes
| Mode | What runs | Device required |
|------|-----------|-----------------|
| `static` | Binary unpacking, manifest/plist parsing, SAST, entitlements, permissions, hardening checks, secrets scanning, tracker detection, signing analysis | No |
| `dynamic` | Frida instrumentation, runtime hooking, memory analysis | Yes |
| `full` (default) | Static + dynamic combined in a single pass | Yes (for dynamic phases) |

MITM traffic capture (`--mitm`) is independent of mode and can be combined with any of the three.

### Static Analysis
- **Manifest / Info.plist parsing** -- exported components, debuggable flags, backup configuration, ATS exceptions, URL schemes, background modes
- **Entitlements extraction** -- get-task-allow, wildcard application-identifier, keychain access groups
- **Binary hardening** -- PIE, NX stack, stack canary, ARC (iOS), RELRO (Android), symbol stripping, debug symbols, FairPlay encryption
- **SAST / secrets scanning** -- AWS keys, Google API keys, Slack tokens, GitHub tokens, Stripe/OpenAI keys, private keys, Firebase endpoints, hardcoded passwords/tokens
- **Permissions analysis** -- dangerous/runtime permission enumeration with protection level classification
- **Network security configuration** -- cleartext traffic, domain pin-sets, NSPinnedDomains (iOS), trust anchors
- **Code-level checks** -- insecure C API imports (gets, sprintf, strcpy), NSLog usage, MODE_WORLD_READABLE/WRITABLE, SQL injection patterns, weak crypto (DES, ECB, MD5, SHA1), WebView JavaScript bridges, insecure random, hardcoded IVs
- **Tracker / SDK detection** -- identifies analytics, advertising, and crash-reporting SDKs (Google Analytics, Firebase, Facebook, Adjust, AppsFlyer, Branch, Mixpanel, Amplitude, Braze, Sentry, New Relic, Datadog, and others)
- **APK signing analysis** -- v1 (JAR), v2 (APK Signature Scheme), v3 scheme detection; Janus vulnerability risk assessment; certificate details and validity
- **Browsable activity / deep link analysis** -- URL scheme enumeration, intent filter extraction, deep link attack surface mapping
- **Behaviour pattern analysis** -- API usage vs declared permissions correlation, undeclared permission detection
- **Firebase configuration detection** -- exposed database URLs, API keys, project configuration
- **Domain and URL extraction** -- embedded URLs, email addresses, phone numbers (with false-positive filtering)
- **File hash computation** -- SHA-256, SHA-1, MD5 of the original application binary

### Dynamic Analysis (Frida)
Frida-based runtime instrumentation on a connected device or emulator. Pre-built scripts and the modular phase system provide:

- **SSL pinning bypass** -- TrustManager bypass (Android), NSURLSession override (iOS)
- **Root/jailbreak detection bypass** -- File.exists hook for su paths (Android), jailbreak path checks (iOS)
- **Data storage monitoring** -- SharedPreferences writes, SQLite queries, keychain/keystore operations
- **Cryptographic operations interception** -- Cipher transforms, MessageDigest algorithms, key generation
- **WebView security monitoring** -- JavaScript bridge exposure, debugging enabled, URL loads, eval calls
- **Biometric authentication monitoring** -- biometric prompt interception, bypass attempts
- **Clipboard monitoring** -- read/write operations for data leakage detection
- **Screenshot protection check** -- verifies FLAG_SECURE and screenshot prevention implementation
- **Authentication flow monitoring** -- credential operations, keychain access, token handling

### MITM Traffic Capture
Independent proxy-based traffic capture via mitmdump. Works with any analysis mode and does not require Frida (though Frida SSL bypass is auto-injected when available).

**Capture features:**
- Persistent mitmproxy CA stored in `/opt/pr0t31n/Quill/.mitmproxy/`
- Auto-import into Burp Java truststore when chaining
- Upstream proxy support (`--mitm-upstream-proxy`) for Burp chain workflows: Device -> Quill MITM -> Burp -> Internet
- Transparent proxy mode (`--mitm-transparent`) for iptables/pf setups
- Auto-passthrough for cert-pinned hosts that reject the MITM CA
- Configurable host ignore patterns (`--mitm-ignore-hosts`)
- Memory threshold monitoring with automatic capture pause
- Combined capture: phases and Frida dynamic checks run inside the MITM proxy window in a single navigation session

**Traffic analysis checks (10):**
| Check | Detects |
|-------|---------|
| Cleartext HTTP | Unencrypted HTTP traffic |
| Sensitive URLs | Credentials, tokens, PII in URL paths/query strings |
| Sensitive bodies | Secrets in request/response bodies |
| Security headers | Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| API keys | Exposed API keys and tokens in headers/bodies |
| Cookie security | Missing Secure, HttpOnly, SameSite flags |
| Certificate issues | Weak signature algorithms, short validity, self-signed certs |
| Tracker communications | Third-party analytics/advertising SDK traffic |
| Authentication weaknesses | Basic auth, token exposure, credential transmission patterns |
| TLS versions | Deprecated TLS 1.0 / 1.1 connections |

**Output from MITM analysis:**
- HAR export (HTTP Archive format)
- API inventory (discovered endpoints, methods, response codes)
- Traffic analysis report (per-host statistics, protocol breakdown)

### Modular Phase System
Seven self-contained analysis phases that run via an orchestrator. Each phase:
- Declares whether it needs user interaction (manual gates, auto-detect gates)
- Emits findings, log entries, and action items via Crucible tokens
- Receives a DeviceConnector and shared context dict

| Phase | Order | Description | Device required |
|-------|-------|-------------|-----------------|
| `recon` | 100 | Static analysis of extracted binary (metadata, components, secrets, SDKs, binary protections) | No |
| `storage` | 200 | Inspect app data directories for insecure storage (SharedPreferences, SQLite, plist, keychain residue, world-readable files) | Yes |
| `ipc` | 300 | Test inter-process communication attack surface (content providers, deep links, intent injection, SQL injection via content URIs) | Yes |
| `logs` | 400 | Scan device logs (logcat/syslog) for leaked secrets, PII, tokens, internal URLs | Yes |
| `memory` | 500 | Inspect process memory for JWTs, bearer tokens, API keys, passwords, private keys, credit cards, SSNs, PINs | Yes |
| `resilience` | 600 | Test tamper resistance (root/jailbreak detection, SSL pinning, debugger protection, emulator detection, screenshot prevention, clipboard security) | Yes |
| `instrumentation` | 700 | Manage Frida hooks for runtime analysis (9 hook scripts) | Yes |

Select individual phases with `--phases recon,storage,ipc` or skip the system entirely with `--no-phases`.

### Frida Hook Scripts
Nine pre-built Frida scripts in `frida_scripts/`:

| Script | Purpose | Platforms |
|--------|---------|-----------|
| `ssl_bypass.js` | SSL pinning bypass | Android, iOS |
| `root_detect_bypass.js` | Root/jailbreak detection bypass | Android, iOS |
| `crypto_hooks.js` | Cryptographic operations monitor | Android, iOS |
| `auth_hooks.js` | Authentication flow monitor | Android, iOS |
| `clipboard_monitor.js` | Clipboard read/write monitor | Android, iOS |
| `screenshot_check.js` | Screenshot protection check | Android, iOS |
| `keychain_hooks.js` | Keychain/keystore monitor | Android, iOS |
| `webview_hooks.js` | WebView URL loads, JS bridges, eval calls | Android, iOS |
| `biometric_hooks.js` | Biometric authentication monitor | Android, iOS |

### Finding Categories
Every finding is tagged with one of eight categories:

- **Transport Security** -- cleartext traffic, missing TLS, weak ciphers, certificate issues, ATS exceptions, missing pinning
- **Application Hardening** -- missing PIE/NX/canary, debug symbols, no obfuscation, root/jailbreak detection absence, no anti-tamper
- **Build Configuration** -- debuggable flag, backup allowed, test-only flags
- **Code Signing** -- unsigned APK, v1-only signing (Janus vulnerable), weak hash algorithm, expired certificates
- **Information Disclosure** -- hardcoded secrets, Firebase exposure, embedded credentials, debug endpoints
- **Privacy** -- tracker SDKs, analytics collection, advertising identifiers
- **Sensitive Data Exposure** -- secrets in memory, tokens in logs, PII in URLs, credentials in request bodies
- **Android Permissions** -- dangerous runtime permissions, over-privileged permission requests

### Third-Party Domain Filtering
MITM analysis automatically filters out noise from known third-party domains (analytics, CDNs, advertising networks) to focus findings on first-party application traffic. The built-in list covers 40+ domain suffixes including Google, Facebook, Cloudflare, Akamai, Fastly, Sentry, Datadog, Segment, Mixpanel, and others. Third-party traffic is still recorded but findings against these domains are suppressed.

### Auto-Queue Pipeline (Crucible Integration)
When running under Crucible (`CRUCIBLE_MANAGED=1`), Quill automatically queues follow-on scans:

**Real-time MITM auto-queue:**
- Monitors captured traffic for API endpoints and web applications
- Captures authentication tokens (headers, cookies, JSON fields) per host
- Queues **Siphon** (API security testing) for discovered API endpoints
- Queues **Fracture** (web application testing) for discovered web targets
- Auth-gated: waits for authentication capture before emitting action items; items without auth go to manual approval
- Deduplicates by (tool, target) pair

**Post-analysis cross-tool action items:**
- Analyses completed findings for cross-tool opportunities
- Queues **Forge** for cloud service audit when AWS/Azure/Google credentials found
- Queues **Siphon** for API testing when API keys or endpoints discovered
- Queues **Fracture** for web testing when WebView URLs discovered

### Role Tagging
Each finding is tagged with the analysis role that produced it:
- `STATIC` -- from static binary analysis
- `FRIDA` -- from dynamic Frida instrumentation
- `MITM` -- from traffic capture analysis

### Findings Catalogue
139 catalogue entries covering all possible findings Quill can emit, with full OWASP, CWE, CVSS, NIST, PCI DSS, and MITRE ATT&CK mappings. Located at `findings_catalogue.json`.

### Device Connectors
Platform-specific device communication:
- **Android**: ADB-based connector with logcat streaming, process management, file pull/push, root detection
- **iOS**: SSH/idevice-based connector with syslog streaming, process management, file operations, jailbreak detection

---

## Requirements

- Python 3.10+
- `androguard` >= 4.1.2 (Android binary XML decoding)
- `mitmproxy` >= 10.0 (MITM traffic capture -- optional, required for `--mitm`)

### System Dependencies

| Tool | Purpose | Platform |
|------|---------|----------|
| `strings` (binutils) | Binary string extraction | Linux (auto-installed) |
| `codesign` | Entitlements extraction | macOS only (Xcode CLI tools) |
| `otool` | Binary hardening analysis | macOS only (Xcode CLI tools) |
| `nm` | Symbol table analysis | macOS / Linux |
| `apktool` | APK decompilation | All (for Android targets) |
| `jadx` | DEX decompilation | All (for Android targets) |
| `jarsigner` | APK signature verification | All (JDK required) |
| `frida` / `frida-tools` | Dynamic instrumentation | All (optional, for dynamic/full mode) |
| `adb` | Android device communication | All (for Android dynamic analysis) |
| `apkid` | Packer/obfuscation detection | All (optional) |
| `apksigner` | APK signature scheme detection | All (Android SDK, optional) |

iOS dynamic analysis additionally requires SSH access to a jailbroken device.

---

## Installation

```bash
cd /opt/pr0t31n/Quill
python3 install.py
```

The installer:
1. Checks Python >= 3.10
2. Installs `binutils` (for `strings`) on Linux if missing
3. Installs Python dependencies from `requirements.txt`

For dynamic analysis, install Frida separately:
```bash
pip3 install --break-system-packages frida-tools
```

---

## Usage

### Static-Only Analysis (no device required)

```bash
# Android APK
python3 quill.py --app com.example.apk --mode static --client-short acme

# iOS IPA
python3 quill.py --app MyApp.ipa --mode static --client-short acme

# Auto-detect platform from file extension
python3 quill.py --app target.apk --mode static
```

### Full Analysis (static + dynamic)

```bash
# Android -- device connected via ADB
python3 quill.py --app com.example.apk --client-short acme

# iOS -- jailbroken device accessible via SSH
python3 quill.py --app MyApp.ipa --client-short acme --device usb

# Specify target process name
python3 quill.py --app com.example.apk --target-process com.example.app
```

### Dynamic-Only Analysis (Frida instrumentation)

```bash
python3 quill.py --mode dynamic --platform android --target-process com.example.app
```

### MITM Traffic Capture

```bash
# MITM alongside full analysis
python3 quill.py --app com.example.apk --mitm --client-short acme

# MITM-only (no static or dynamic)
python3 quill.py --mitm --platform android --client-short acme

# MITM with Burp upstream proxy chain
python3 quill.py --app com.example.apk --mitm \
    --mitm-upstream-proxy http://127.0.0.1:8080 \
    --mitm-burp-ca /path/to/burp-ca.pem

# Custom port and host ignore
python3 quill.py --app com.example.apk --mitm --mitm-port 9090 \
    --mitm-ignore-hosts '.*\.sentry\.io|.*\.mixpanel\.com'

# Transparent proxy mode
python3 quill.py --app com.example.apk --mitm --mitm-transparent
```

### Phase Selection

```bash
# Run only specific phases
python3 quill.py --app com.example.apk --phases recon,storage,ipc

# Skip the phase system entirely (legacy mode)
python3 quill.py --app com.example.apk --no-phases
```

### Crucible Managed Mode

When launched by Crucible v2, set the environment variable:
```bash
CRUCIBLE_MANAGED=1 python3 quill.py --app com.example.apk --client-short acme --mitm
```

This enables:
- `__CRUCIBLE_LOG__`, `__CRUCIBLE_ERR__`, `__CRUCIBLE_STATUS__` token streaming
- `__CRUCIBLE_FINDING__` real-time finding emission
- `__CRUCIBLE_ACTION_ITEM__` auto-queue pipeline for Fracture/Siphon
- `__CRUCIBLE_PROMPT__` interactive gate prompts

---

## CLI Reference

```
usage: quill [-h] [--app APP] [--ipa IPA] [--platform {ios,android,auto}]
             [--mode {static,dynamic,full}] [--dynamic]
             [--device DEVICE] [--target-process TARGET_PROCESS]
             [--client-short CLIENT_SHORT] [--client-name CLIENT_NAME]
             [--engagement-name ENGAGEMENT_NAME]
             [--mitm] [--mitm-duration SECONDS] [--mitm-port PORT]
             [--mitm-transparent] [--mitm-upstream-proxy URL]
             [--mitm-burp-ca PATH] [--mitm-ignore-hosts REGEX]
             [--project PROJECT] [--phases PHASES] [--no-phases]
             [--version]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--app` | -- | Path to .ipa or .apk file |
| `--ipa` | -- | Legacy alias for `--app` |
| `--platform` | `auto` | Target platform: `ios`, `android`, or `auto` (detect from extension) |
| `--mode` | `full` | Analysis mode: `static`, `dynamic`, or `full` |
| `--dynamic` | -- | Legacy flag, same as `--mode full` |
| `--device` | -- | Frida device ID for dynamic/full mode |
| `--target-process` | -- | Target process name for dynamic analysis |
| `--client-short` | `default` | Client short name for output directory |
| `--client-name` | -- | Full client name (defaults to `--client-short`) |
| `--engagement-name` | `quill run` | Engagement name written to meta.json |
| `--mitm` | -- | Enable MITM traffic capture (works with any mode) |
| `--mitm-port` | `8080` | mitmproxy listen port |
| `--mitm-transparent` | -- | Transparent proxy mode (requires iptables/pf) |
| `--mitm-upstream-proxy` | -- | Upstream proxy URL for chain workflows |
| `--mitm-burp-ca` | -- | Path to upstream proxy CA (cert+key PEM) for single-CA trust |
| `--mitm-ignore-hosts` | -- | Regex of hosts to pass through unintercepted |
| `--mitm-duration` | -- | Deprecated (capture runs until stopped) |
| `--project` | -- | Override output directory path |
| `--phases` | `all` | Comma-separated phase names, or `none` to skip |
| `--no-phases` | -- | Skip the modular phase system entirely |
| `--version` | -- | Print version and exit |

---

## Output

Run directories follow the pr0t31n universal output structure:

```
<clients_base>/<client_short>/<year>/quill/<client_short>_<YYYYMMDD_HHMMSS>/
├── meta.json                      # Tool identity, client, engagement
├── findings.json                  # Universal findings (schema v1.1)
├── findings.csv                   # CSV mirror
├── summary.json                   # Risk counts + timing
├── scan.log / scan.log.json       # Timestamped event log
├── errors.log / errors.log.json   # ERROR + TOOL_ERROR entries
├── checkpoint.json                # Resumable checkpoint (findings count + timestamp)
│
├── extract/                       # Extracted application bundle
│   └── Payload/*.app              #   (iOS) or AndroidManifest.xml + classes.dex (Android)
│
├── info_plist.json                # Parsed Info.plist (iOS)
├── info_plist.json.log            # Analysis transcript
├── entitlements.xml               # Extracted entitlements (iOS)
├── entitlements.xml.log           # codesign tool .log
├── strings_raw.txt                # Raw strings output
├── strings_raw.txt.log            # strings tool .log
├── string_findings.txt            # Matched secret patterns
│
├── manifest_analysis.json         # AndroidManifest analysis (Android)
├── permission_analysis.json       # Permission audit results
├── network_security_config.json   # NSC analysis (Android)
├── signing_analysis.json          # APK signing scheme analysis
├── tracker_report.json            # Detected tracker SDKs
├── firebase_report.json           # Firebase configuration findings
├── apkid_report.json              # APKiD packer/obfuscation results
├── browsable_activities.json      # Deep link / URL scheme analysis
├── behaviour_patterns.json        # API usage vs permissions correlation
├── binary_mitigations.json        # Binary hardening check results (iOS)
├── code_analysis.json             # SAST results
├── domains_urls.json              # Extracted domains and URLs
├── emails.json                    # Extracted email addresses
├── file_hashes.json               # SHA-256, SHA-1, MD5 of the binary
│
├── components.json                # Crucible intelligence: app components
├── permissions.json               # Crucible intelligence: permission inventory
├── network_config.json            # Crucible intelligence: network security config
├── secrets.json                   # Crucible intelligence: discovered secrets
├── trackers.json                  # Crucible intelligence: tracker inventory
│
├── mitm/                          # MITM capture artifacts
│   ├── flows.mitm                 # Raw mitmproxy flow dump
│   ├── traffic.har                # HAR export
│   ├── api_inventory.json         # Discovered API endpoints
│   ├── traffic_analysis.json      # Per-host traffic statistics
│   └── evidence/                  # Per-check evidence files
│
├── frida/                         # Frida dynamic analysis output
│   ├── ssl_bypass.json            # SSL pinning bypass results
│   ├── root_detect.json           # Root/jailbreak detection results
│   ├── data_storage.json          # SharedPreferences/SQLite monitoring
│   ├── crypto.json                # Cryptographic operations log
│   └── webview.json               # WebView security observations
│
└── action_items.json              # Cross-tool action items for Crucible
```

---

## Token Protocol

When `CRUCIBLE_MANAGED=1` is set, Quill emits structured tokens on stdout for real-time integration with Crucible v2:

| Token | Purpose |
|-------|---------|
| `__CRUCIBLE_LOG__` | Log message streaming |
| `__CRUCIBLE_ERR__` | Error message streaming |
| `__CRUCIBLE_STATUS__` | Phase/progress status updates (JSON) |
| `__CRUCIBLE_FINDING__` | Real-time finding emission (JSON) |
| `__CRUCIBLE_PROMPT__` | Interactive gate prompts for user action |
| `__CRUCIBLE_ACTION_ITEM__` | Cross-tool auto-queue items (JSON) |

---

## Integration Points

| Tool | Integration |
|------|-------------|
| **Crucible v2** | Managed execution, log streaming, findings display, phase status, MITM controls, action item pipeline |
| **Fracture** | Auto-queued via MITM action items when web targets are discovered |
| **Siphon** | Auto-queued via MITM action items when API endpoints are discovered |
| **Forge** | Auto-queued when cloud service credentials (AWS/Azure/Google) are found |
| **Prometheus** | Findings ingested via universal parser (`meta.json` routing) |
| **FindingsDB** | Dual-write to SQLite alongside JSON when `PR0T31N_FINDINGS_DB` is set |
| **Arbiter** | Catalogue enrichment via `findings_catalogue.json` (139 entries, QUILL-prefixed IDs) |

---

## Directory Structure

```
/opt/pr0t31n/Quill/
├── quill.py                    # Main entry point (6,282 lines)
├── VERSION                     # 1.21.2
├── requirements.txt            # androguard, mitmproxy
├── install.py                  # Multi-platform installer
├── findings_catalogue.json     # 139 finding definitions
├── LICENSE                     # GPLv3
├── README.md                   # This file
├── device/                     # Platform device connectors
│   ├── base.py                 #   Abstract DeviceConnector interface
│   ├── android.py              #   ADB-based Android connector
│   └── ios.py                  #   SSH/idevice iOS connector
├── phases/                     # Modular analysis phase system
│   ├── base.py                 #   Phase interface, orchestrator, gates
│   ├── recon.py                #   Phase 1: static binary analysis
│   ├── storage.py              #   Phase 2: data storage inspection
│   ├── ipc.py                  #   Phase 3: IPC attack surface testing
│   ├── logs.py                 #   Phase 4: device log analysis
│   ├── memory.py               #   Phase 5: process memory inspection
│   ├── resilience.py           #   Phase 6: tamper resistance testing
│   └── instrumentation.py      #   Phase 7: Frida hook management
└── frida_scripts/              # Pre-built Frida instrumentation scripts
    ├── ssl_bypass.js
    ├── root_detect_bypass.js
    ├── crypto_hooks.js
    ├── auth_hooks.js
    ├── clipboard_monitor.js
    ├── screenshot_check.js
    ├── keychain_hooks.js
    ├── webview_hooks.js
    └── biometric_hooks.js
```

---

## License

GPLv3
