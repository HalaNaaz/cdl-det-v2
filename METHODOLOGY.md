# Technical Methodology & Detection Engineering Framework

**Document:** Engineering Methodology, Telemetry Standards & Validation Framework  
**Project:** Cyberion Defense Labs Detection Engineering (CDL-DET-V2)  
**Author:** Hala Naaz  
**Repository:** `cdl-det-v2-main`  
**Status:** Grounded Engineering Baseline (Reconciled against Active Implementation)

---

## 1. Engineering Framework Overview

The Cyberion Defense Labs (CDL) Detection Engineering methodology provides a disciplined, reproducible framework for authoring, testing, and operationalizing threat detection rules. Rather than equating rule authoring with threat visibility, this framework enforces empirical verification against authentic adversary telemetry, rigorous schema validation, and transparent gap analysis.

```
+---------------------------------------------------------------------------------------------------+
|                                 CDL DETECTION LIFECYCLE PHASES                                    |
+---------------------------------------------------------------------------------------------------+
| 1. Threat Modeling & Hypotheses   --> Map threat actors & post-exploitation techniques (ATT&CK).  |
| 2. Telemetry Ingestion & Parsing  --> Ingest NDJSON/EVTX logs via streaming Python parsers.       |
| 3. Sigma Rule Authoring & Schema  --> Draft rules in YAML compliant with pySigma & Correlation HQ.|
| 4. Static Integrity & UUID Audit  --> Verify zero UUID collisions & zero duplicate selection blocks.|
| 5. Empirical Telemetry Matching   --> Execute automated verification tests against raw attack logs.|
| 6. Gap Analysis & Matrix Mapping  --> Classify coverage (Validated, Partial, Telemetry Gap, etc.).|
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Telemetry Acquisition & Ground-Truth Artifacts

The engagement evaluates two primary security log artifacts stored physically in `data/`:

### 2.1 Primary Artifact: Mordor Adversary Emulation NDJSON
- **Filename:** `data/empire_mimikatz_logonpasswords_2020-08-07103224.json`
- **Origin:** The Mordor Project (Open-source pre-recorded adversary simulation telemetry generated via PowerShell Empire and Mimikatz).
- **Physical Specifications:** 43,478,765 bytes (~43.5 MB) in Newline-Delimited JSON (NDJSON) format.
- **Empirical Parsing Metrics:**
  - Total lines scanned: **6,026**
  - Valid JSON event records: **6,026**
  - Malformed lines: **0**
- **Captured Channels & Telemetry Distribution:**
  - `Windows PowerShell` (Event ID 800: 2,940 events, Event ID 600: 8 events, Event ID 400: 1 event)
  - `Microsoft-Windows-PowerShell/Operational` (Event ID 4103: 1,695 events)
  - `Microsoft-Windows-Sysmon/Operational` (Event ID 10: 272 events, Event ID 12: 154 events, Event ID 3: 90 events, Event ID 7: 81 events, Event ID 13: 45 events, Event ID 11: 14 events, Event ID 5: 11 events, Event ID 18: 5 events, Event ID 9: 3 events, Event ID 17: 2 events, Event ID 1: 1 event, Event ID 22: 1 event)
  - `Security` (Event ID 5156: 211 events, Event ID 5158: 195 events, Event ID 4658: 86 events, Event ID 4656: 49 events, Event ID 4663: 43 events, Event ID 4690: 43 events, Event ID 4703: 13 events, Event ID 4689: 11 events, Event ID 4672: 10 events, Event ID 4634: 10 events, Event ID 4627: 10 events, Event ID 4624: 10 events, Event ID 4673: 6 events, Event ID 5145: 2 events, Event ID 4688: 1 event, Event ID 4670: 1 event, Event ID 5140: 1 event)
  - `Microsoft-Windows-WMI-Activity/Operational` (Event ID 5857: 1 event)
- **Known Telemetry Constraints:**
  - *PowerShell Architecture:* PowerShell Operational logging (Event ID 4103) is embedded directly within this JSON dataset; it does not exist as an independent 3rd physical file. Event ID 4104 (ScriptBlock Logging) was not captured.
  - *Missing Channels:* Windows Security Event ID 4625 (failed logon) and Windows System Event ID 7045 (service installation) are completely absent.

### 2.2 Secondary Artifact: Sysmon Command-Line FTP EVTX
- **Filename:** `data/exec_sysmon_1_ftp.evtx`
- **Physical Specifications:** 69,632 bytes (~68 KB) in binary Windows Event Log format (`ElfFile`).
- **Telemetry Profile:** Captures execution of `cmd.exe /c` launching `ftp.exe -s:script.txt` on a Windows 7 SP1 host.
- **Parsing Limitation:** In the current environment, `python-evtx` is uninstalled. Binary inspection confirmed file structure and UTF-16LE command-line strings, but programmatic parsing is deferred pending library integration.

---

## 3. Streaming Log Parsing & Notebook Reproducibility

To ensure analytical reproducibility across environments, `data/parse_logs.ipynb` was developed with strict operational standards:

1. **Streaming Processing:** Rather than loading the entire 43.5 MB JSON file into memory at once, the notebook implements streaming line-by-line parsing via standard Python `json.loads()`, guaranteeing deterministic execution on memory-constrained systems.
2. **Dynamic Relative Path Resolution:** The notebook uses `pathlib.Path` to dynamically detect its working environment:
   ```python
   curr = Path.cwd().resolve()
   if (curr / "empire_mimikatz_...json").is_file():
       dataset_path = curr / "empire_mimikatz_...json"
   elif (curr / "data" / "empire_mimikatz_...json").is_file():
       dataset_path = curr / "data" / "empire_mimikatz_...json"
   ```
   This ensures that running `jupyter execute data/parse_logs.ipynb` succeeds whether invoked from the repository root or within the `data/` directory.
3. **Explicit Data Quality Accounting:** The parser explicitly counts lines processed, valid JSON objects created, and malformed lines encountered, confirming zero data corruption.

---

## 4. Sigma Rule Authoring, Schema Validation & Integrity Standards

All 15 production rules in `rules/` adhere to standard SigmaHQ specifications:

### 4.1 Schema Compliance
- **Single-Event Rules (14 Rules):** Validated using `pySigma` (`sigma.collection.SigmaCollection.from_yaml`). Single-event rules conform strictly to standard `logsource` taxonomy (`process_creation`, `process_access`, `network_connection`, `registry_set`, `security`, `system`, `powershell`).
- **Multi-Event Correlation Rule (1 Rule):** Authored in compliance with the **SigmaHQ Correlation Specification** (`action: correlation`, `type: temporal`, `rule: [...]`, `timespan: 1m`, `group-by: [ComputerName]`, `ordered: true`).

### 4.2 UUID Integrity & Anti-Collision Standards
- Every rule must possess a valid Version 4 UUID (`id` field).
- The automated test runner (`tests/validate_rules.py`) scans all rules and verifies that the total number of unique UUIDs exactly matches the total production rule count (15 / 15).
- In Phase 2, a duplicate UUID collision on `sysmon_ftp_brute_force.yml` was permanently resolved by issuing unique UUID `a4b5c6d7-8901-23ab-cdef-444444444444`.

### 4.3 Anti-Duplication Standards
- Automated validation performs structural hash checks across all YAML detection selection blocks to guarantee zero copy-paste logic duplication.

### 4.4 Test Fixture Isolation
- Rule development fixtures (`test_rule.yml`) are strictly isolated in `tests/` and excluded from production `rules/` to prevent synthetic or dummy rules from being deployed to production engines.

---

## 5. MITRE ATT&CK Mapping & Defensive Gap Analysis

The project rejects superficial "paper coverage" where any tagged technique is reported as fully protected. All techniques in [`docs/ATTACK_COVERAGE_MATRIX.md`](file:///docs/ATTACK_COVERAGE_MATRIX.md) are classified into five explicit, evidence-backed categories:

1. **Validated detection:** Representative attack telemetry was parsed and triggered the detection logic during testing (e.g. T1003.001 Sysmon 10 LSASS Handle Access; T1033 Sysmon 1 Whoami).
2. **Rule exists — telemetry validation incomplete:** A structurally valid rule exists, but required telemetry is absent, blocked, or failed in testing (e.g. T1110 Brute Force due to absent Event 4625; T1543.003 Service Creation due to absent Event 7045).
3. **Partial coverage:** The rule monitors narrow CLI parameters or specific LOLBins, but leaves broader attack surface exposed (e.g. T1059.001 PowerShell encoded flags; T1021.002 PsExec flags).
4. **Telemetry gap:** Required logging channels (Web Proxy, DNS, System event logs) are uncollected.
5. **No rule mapped:** Known adversary techniques identified during threat modeling that lack rule coverage, defining open engineering backlog priorities.

---

## 6. Telemetry Verification & Test Runner Architecture

The automated test runner [`tests/validate_rules.py`](file:///tests/validate_rules.py) executes both structural checks and behavioral telemetry matching:

```
+----------------------------------------------------------------------------------+
|                   AUTOMATED VALIDATION WORKFLOW (`validate_rules.py`)            |
+----------------------------------------------------------------------------------+
| 1. Test Fixture Isolation Check  --> Verifies test_rule.yml is isolated outside  |
|                                      production rules/ directory.                |
| 2. Production Rule Discovery     --> Locates exactly 15 production rules in      |
|                                      rules/*.yml.                                |
| 3. pySigma Schema Parsing        --> Validates 14 single-event rules via         |
|                                      pySigma; validates correlation schema.      |
| 4. UUID & Duplication Audit      --> Validates 15 unique UUIDs; 0 duplicate      |
|                                      detection selection blocks.                 |
| 5. Telemetry Matching Suite      --> Scans Mordor NDJSON dataset for exact event |
|                                      primitives matching rule logic.             |
| 6. Reporting & Result Summary    --> Reports individual PASS/FAIL/BLOCKED/NOT    |
|                                      RUN statuses with explicit evidence strings.|
+----------------------------------------------------------------------------------+
```

### Empirical Test Logic:
- **LSASS Process Access (`sysmon_lsass_dump.yml`):** Filters Sysmon Event ID 10 where `TargetImage` ends with `lsass.exe`, verifies `GrantedAccess` includes read masks (`0x1010`, `0x10`, `0x1410`), and confirms exclusion of benign system processes (`svchost.exe`, `csrss.exe`).
- **Whoami System Discovery (`sysmon_recon_whoami.yml`):** Evaluates Sysmon Event ID 1 where `Image` ends with `whoami.exe` and verifies that benign `ParentImage` values (`userinit.exe`) do not trigger the rule.
- **PowerShell ScriptBlock Logging (`sysmon_whoami_recon.yml`):** Evaluates Event ID 4103/4104 for explicit credential access invocation strings.
- **Authentication Brute Force (`sysmon_ftp_brute_force.yml`):** Monitors Windows Security Event ID 4625 for sequential network logons.
- **Valid Accounts Privilege Assignment (`sysmon_valid_accounts.yml`):** Evaluates Windows Security Event ID 4672 for sensitive user rights (`SeDebugPrivilege`), filtering computer accounts (`$` suffix).
- **Service Creation (`sysmon_service_creation.yml`):** Monitors Windows System Event ID 7045 for service installation events.
- **Temporal Correlation (`correlation_ps_lsass_dump.yml`):** Evaluates the time delta between interactive PowerShell execution and LSASS handle access on the same host.

---

## 7. False Positive Engineering & Filter Tuning

A detection rule without filter tuning produces unmanageable operational fatigue. Across the 15 production rules, specific tuning passes were applied:

1. **LSASS Process Access:** Whitelisted core Windows system binaries (`C:\Windows\System32\svchost.exe`, `csrss.exe`, `lsass.exe`, `lsm.exe`) that routinely inspect process handles under normal OS operation.
2. **Whoami System Discovery:** Filtered standard user logon initializations where `ParentImage` is `C:\Windows\System32\userinit.exe`.
3. **Privilege Assignment:** Filtered standard Active Directory computer account logons (`SubjectUserName|endswith: '$'`) which frequently receive administrative tokens during domain synchronization.
4. **PowerShell Network Connections:** Filtered standard RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) to suppress internal administrative management traffic.

---

## 8. Multi-Event Temporal Correlation Standards

While single-event rules identify isolated actions, sophisticated adversary behavior requires correlating multi-stage attack chains:

```
[Event 1: PowerShell Process Initiation]  --> UtcTime: 2020-08-07 10:32:45 UTC (WORKSTATION5)
                     |
                (Delta: 11 Seconds)
                     |
                     v
[Event 2: LSASS Process Handle Access]    --> UtcTime: 2020-08-07 10:32:56 UTC (WORKSTATION5)
```

### Stateful Correlation Requirements:
- **Syntax Standardization:** `correlation_ps_lsass_dump.yml` utilizes official SigmaHQ correlation syntax, referencing child rule IDs and specifying temporal constraints (`timespan: 1m`, `ordered: true`, `group-by: [ComputerName]`).
- **Execution Reality:** Standard static linters (including base pySigma) are stateless and cannot evaluate temporal state machines across streaming log feeds. In production, this rule requires compilation against a SIEM stream worker, correlation backend, or temporal sequencer.

---

## 9. Quality Assurance, Reproducibility & Limitations

### Reproducibility Verification
- The automated validation runner can be executed at any time via:
  ```bash
  python tests/validate_rules.py
  ```
- All dataset paths, rule IDs, and event fields are verified against actual repository files.
- Zero mock events or synthetic records were injected into datasets to force passing results.

### Known Technical Limitations
1. **Uncollected Event Channels:** Verification of brute force (Event 4625) and service installation (Event 7045) is currently blocked pending log ingestion.
2. **Binary EVTX Parsing:** Programmatic parsing of `exec_sysmon_1_ftp.evtx` requires integrating an EVTX extraction library.
3. **In-Memory Evasion:** In-memory script execution frameworks evade plaintext ScriptBlock matching, confirming that defense-in-depth must combine script monitoring with host memory handle inspection.
