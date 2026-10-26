# Cyberion Defense Labs Detection Engineering (CDL-DET-V2)

[![Detection Engineering](https://img.shields.io/badge/Security-Detection%20Engineering-blue.svg)](#)
[![Sigma Rules](https://img.shields.io/badge/Sigma%20Rules-15%20Active-green.svg)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-22%20Techniques-orange.svg)](#)
[![Automated Validation](https://img.shields.io/badge/pySigma-Schema%20Validated-brightgreen.svg)](#)
[![Telemetry Test](https://img.shields.io/badge/Telemetry%20Tests-2%20PASS%20%7C%201%20FAIL%20%7C%203%20BLOCKED%20%7C%201%20NOT%20RUN-yellow.svg)](#)

> **Portfolio Engineering Artifact:** A defensible, evidence-grounded detection engineering project featuring 15 production Sigma rules, pySigma schema validation, empirical adversary emulation testing, comprehensive MITRE ATT&CK mapping, and threat hunt investigations.

---

## 1. Project Purpose & Problem Statement

Modern Security Operations Centers (SOCs) and Detection Engineering teams frequently suffer from **"paper coverage"** — the assumption that authoring a detection rule or mapping a MITRE ATT&CK technique guarantees operational visibility. In reality, rules often fail due to:
- Syntax errors and duplicate selection logic across rule repositories.
- Identifier (UUID) collisions causing indexing failures in SIEM platforms.
- Over-reliance on brittle plaintext indicators easily bypassed by in-memory adversary execution.
- Blind spots caused by uncollected event channels or unverified telemetry baselines.

The **CDL-DET-V2** project remediates these challenges by establishing an evidence-backed detection engineering pipeline. Through six rigorous development phases, the project audits, remediates, tests, and documents 15 production Sigma rules against authentic adversary emulation datasets (the Mordor Project and Sysmon EVTX traces), upholding strict standards of analytical honesty, schema reproducibility, and transparent telemetry tracking.

---

## 2. Detection Engineering Architecture & Workflow

```
                                      +------------------------------------+
                                      |   Adversary Emulation Telemetry    |
                                      |  - Mordor NDJSON (43.5 MB, 6,026)  |
                                      |  - Sysmon EVTX (68 KB, CLI FTP)    |
                                      +-----------------+------------------+
                                                        |
                                                        v
                                      +-----------------+------------------+
                                      |  Automated Log Ingestion Pipeline  |
                                      |      `data/parse_logs.ipynb`       |
                                      |  - Streaming NDJSON parser         |
                                      |  - Dynamic relative path resolver  |
                                      +-----------------+------------------+
                                                        |
                                                        v
+------------------------------------+        +---------+------------------+
|   Sigma Production Rule Corpus     |        |   Automated Test Runner    |
|   `rules/*.yml` (15 Rules)         |------->| `tests/validate_rules.py`  |
|   - 14 Single-Event Sigma Rules    |        | - pySigma Schema Engine    |
|   - 1 Multi-Event Correlation Rule |        | - UUID Uniqueness Check    |
|   - Zero Duplicate Logic           |        | - Fixture Isolation Check  |
+------------------------------------+        | - Telemetry Matching Suite |
                                              +---------+------------------+
                                                        |
                         +------------------------------+-------------------------------+
                         |                                                              |
                         v                                                              v
      +------------------+------------------+                    +----------------------+--------------------+
      |    Analytical MITRE ATT&CK Matrix   |                    |       Telemetry Data Dictionary           |
      |   `docs/ATTACK_COVERAGE_MATRIX.md`  |                    |      `data/DATA_DICTIONARY.md`            |
      |   - 22 Evaluated Techniques         |                    |   - 6,026 Ground-Truth Events Mapped      |
      |   - 5 Explicit Coverage Classes     |                    |   - Observed vs Absent Distinctions       |
      |   - Gap Analysis & Next Actions     |                    |   - Field Definitions & Constraints       |
      +-------------------------------------+                    +-------------------------------------------+
```

---

## 3. Repository File Structure

```
cdl-det-v2-main/
│
├── README.md                                  # Primary project entry point, architecture & validation guide
├── EXECUTIVE_SUMMARY.md                       # High-level executive briefing for security leadership
├── METHODOLOGY.md                             # Technical detection engineering methodology & testing standards
│
├── data/
│   ├── DATA_DICTIONARY.md                     # Ground-truth telemetry catalog, event distribution & fields
│   ├── empire_mimikatz_logonpasswords_...json # Mordor adversary emulation dataset (NDJSON, 43.5 MB, 6,026 lines)
│   ├── exec_sysmon_1_ftp.evtx                 # Sysmon binary event log (68 KB, command-line FTP execution)
│   └── parse_logs.ipynb                       # Reproducible streaming telemetry parser & analysis notebook
│
├── docs/
│   ├── ATTACK_COVERAGE_MATRIX.md              # 22-technique ATT&CK matrix with explicit coverage classifications
│   ├── ATTACK_MAPPING.md                      # Technique candidates and scoping documentation
│   ├── EXECUTIVE_SUMMARY.md                   # Mirrored executive briefing in docs directory
│   ├── FP_TUNING_PASSES.md                    # False positive analysis and filter tuning history
│   ├── IOC_RESEARCH.md                        # Adversary artifacts and indicators of compromise
│   └── METHODOLOGY.md                         # Mirrored technical methodology in docs directory
│
├── hunts/
│   ├── HUNT_001_C2_BEACONING.md               # Threat Hunt 001: Web C2 Beaconing (T1071.001)
│   └── HUNT_002_CREDENTIAL_DUMPING.md         # Threat Hunt 002: LSASS Memory Dumping (T1003.001)
│
├── incidents/
│   ├── INCIDENT_001_LSASS_DUMP.md             # Incident Case Report 001: LSASS Credential Dumping
│   └── INCIDENT_002_COMMAND_LINE_FTP_EXFIL.md # Incident Case Report 002: CLI FTP Staging & Exfiltration
│
├── playbooks/
│   ├── PLAYBOOK_001_LSASS_DUMP.md             # Incident Response Playbook 001: LSASS Memory Extraction
│   ├── PLAYBOOK_002_CREDENTIAL_COMPROMISE.md  # Incident Response Playbook 002: Credential Compromise & Abuse
│   └── PLAYBOOK_003_LATERAL_MOVEMENT.md       # Incident Response Playbook 003: Remote Services & Lateral Movement
│
├── rules/                                     # Production Sigma Rules (15 Active Rules)
│   ├── correlation_ps_lsass_dump.yml          # Multi-event temporal correlation rule (PowerShell -> LSASS)
│   ├── sysmon_cmd_execution.yml               # Suspicious command shell invocation (/c, /k, /r)
│   ├── sysmon_ftp_brute_force.yml             # Authentication brute force detection (Security Event 4625)
│   ├── sysmon_ftp_exfil.yml                   # Scripted command-line FTP execution (ftp.exe -s:)
│   ├── sysmon_lsass_dump.yml                  # LSASS process handle read access (Sysmon Event 10)
│   ├── sysmon_net_ftp_exfil.yml               # Outbound network socket via FTP (Sysmon Event 3)
│   ├── sysmon_net_powershell_conn.yml         # Outbound network connection initiated by PowerShell
│   ├── sysmon_persistence_service.yml         # Service creation via CLI SC.EXE (Sysmon Event 1)
│   ├── sysmon_powershell_encoded.yml          # Encoded PowerShell command execution (-enc flags)
│   ├── sysmon_psexec_lateral.yml              # PsExec service execution and lateral movement
│   ├── sysmon_recon_whoami.yml                # System discovery via whoami.exe execution
│   ├── sysmon_reg_run_persistence.yml         # Persistence via Registry Run/RunOnce key modification
│   ├── sysmon_service_creation.yml            # Service Control Manager service installation (Event 7045)
│   ├── sysmon_valid_accounts.yml              # Sensitive administrator privilege assignment (Event 4672)
│   └── sysmon_whoami_recon.yml                # PowerShell ScriptBlock credential dump invocation
│
├── rules_backup_phase1/                       # Safe backup archive of pre-remediation Phase 1 rule files
│
└── tests/
    ├── test_rule.yml                          # Isolated test fixture (deliberately excluded from production rules/)
    └── validate_rules.py                      # Automated test runner (pySigma parser, UUID audit, telemetry tests)
```

---

## 4. Production Sigma Rule Inventory

The repository contains exactly **15 production Sigma rules** in `rules/`, all verified with unique UUIDs and compliant with pySigma / SigmaHQ schemas:

| # | Rule Filename | Unique UUID | Title | Log Source Category / Service | Primary ATT&CK Tags | Empirical Telemetry Status |
| :---: | :--- | :--- | :--- | :--- | :--- | :---: |
| 1 | [`correlation_ps_lsass_dump.yml`](file:///rules/correlation_ps_lsass_dump.yml) | `c0d1e2f3-4567-89ab-cdef-101010101010` | Correlation - PowerShell Execution Followed by LSASS Access | `action: correlation` (temporal) | `T1003.001`, `T1059.001` | **NOT RUN** (Engine required) |
| 2 | [`sysmon_cmd_execution.yml`](file:///rules/sysmon_cmd_execution.yml) | `c4d5e6f7-8901-23ab-cdef-444444444444` | Suspicious Command Shell Execution | Sysmon 1 (`process_creation`) | `T1059.003` | *Unobserved in JSON* |
| 3 | [`sysmon_ftp_brute_force.yml`](file:///rules/sysmon_ftp_brute_force.yml) | `a4b5c6d7-8901-23ab-cdef-444444444444` | Potential Authentication Brute Force - Multiple Failed Logons | Security 4625 (`security`) | `T1110` | **BLOCKED** (Event 4625 absent) |
| 4 | [`sysmon_ftp_exfil.yml`](file:///rules/sysmon_ftp_exfil.yml) | `f7a8b9c0-1234-56ab-cdef-777777777777` | Data Exfiltration via Command Line FTP | Sysmon 1 (`process_creation`) | `T1041` | *Unparsed EVTX* |
| 5 | [`sysmon_lsass_dump.yml`](file:///rules/sysmon_lsass_dump.yml) | `a2b3c4d5-6789-01ab-cdef-222222222222` | LSASS Process Memory Access for Credential Dumping | Sysmon 10 (`process_access`) | `T1003.001` | **PASS** (Matched `0x1010`) |
| 6 | [`sysmon_net_ftp_exfil.yml`](file:///rules/sysmon_net_ftp_exfil.yml) | `f1a2b3c4-5678-90ab-cdef-111111111111` | Outbound Network Connection via FTP Executable | Sysmon 3 (`network_connection`) | `T1041` / `T1048.003` | *Unobserved in JSON* |
| 7 | [`sysmon_net_powershell_conn.yml`](file:///rules/sysmon_net_powershell_conn.yml) | `f5a6b7c8-9012-34ab-cdef-555555555555` | Outbound Network Connection Triggered by PowerShell | Sysmon 3 (`network_connection`) | `T1059.001` | *Filtered (RFC1918 internal)* |
| 8 | [`sysmon_persistence_service.yml`](file:///rules/sysmon_persistence_service.yml) | `f3a4b5c6-7890-12ab-cdef-333333333333` | Service Installation via SC.EXE | Sysmon 1 (`process_creation`) | `T1543.003` | *Unobserved in JSON* |
| 9 | [`sysmon_powershell_encoded.yml`](file:///rules/sysmon_powershell_encoded.yml) | `b3c4d5e6-7890-12ab-cdef-333333333333` | Encoded PowerShell Command Execution | Sysmon 1 (`process_creation`) | `T1059.001`, `T1027` | *Unobserved in JSON* |
| 10 | [`sysmon_psexec_lateral.yml`](file:///rules/sysmon_psexec_lateral.yml) | `d5e6f7a8-9012-34ab-cdef-555555555555` | PsExec Lateral Movement Execution | Sysmon 1 (`process_creation`) | `T1021.002` | *Unobserved in JSON* |
| 11 | [`sysmon_recon_whoami.yml`](file:///rules/sysmon_recon_whoami.yml) | `f2a3b4c5-6789-01ab-cdef-222222222222` | System Discovery via Whoami Command Execution | Sysmon 1 (`process_creation`) | `T1033` | **PASS** (Matched `whoami.exe`) |
| 12 | [`sysmon_reg_run_persistence.yml`](file:///rules/sysmon_reg_run_persistence.yml) | `f4a5b6c7-8901-23ab-cdef-444444444444` | Persistence via Registry Run Key Modification | Sysmon 13 (`registry_set`) | `T1547.001` | *Unobserved in JSON* |
| 13 | [`sysmon_service_creation.yml`](file:///rules/sysmon_service_creation.yml) | `e6f7a8b9-0123-45ab-cdef-666666666666` | Windows Service Installation via SCM | System 7045 (`system`) | `T1543.003` | **BLOCKED** (System log absent) |
| 14 | [`sysmon_valid_accounts.yml`](file:///rules/sysmon_valid_accounts.yml) | `a8b9c0d1-2345-67ab-cdef-888888888888` | Special Privileges Assigned to New Logon Session | Security 4672 (`security`) | `T1078` | **BLOCKED** (Machine only) |
| 15 | [`sysmon_whoami_recon.yml`](file:///rules/sysmon_whoami_recon.yml) | `b9c0d1e2-3456-78ab-cdef-999999999999` | PowerShell ScriptBlock Logging - Credential Access Invocation | PowerShell 4103/4104 (`powershell`) | `T1059.001`, `T1003.001` | **FAIL** (In-memory jobs) |

---

## 5. MITRE ATT&CK Enterprise Coverage Summary

The project evaluates **22 distinct techniques and sub-techniques** across 9 tactics in [`docs/ATTACK_COVERAGE_MATRIX.md`](file:///docs/ATTACK_COVERAGE_MATRIX.md), rejecting binary "covered/not-covered" oversimplifications:

| Coverage Classification | Distinct Techniques | Techniques Included | Description |
| :--- | :---: | :--- | :--- |
| **Validated detection** | **2** | `T1003.001` (LSASS Handle Access), `T1033` (Whoami Discovery) | Authentic attack event was observed and the rule triggered as expected. |
| **Rule exists — validation incomplete** | **4** *(6 rules)* | `T1110` (Brute Force), `T1543.003` (Service Creation 7045), `T1078` (Valid Accounts), `T1041` (FTP Exfil) *(also includes secondary rule for `T1003.001` ScriptBlock and the Correlation Rule)* | Rule is authored and structurally valid, but telemetry is absent, blocked, or failed in testing. |
| **Partial coverage** | **6** | `T1059.001` (PowerShell), `T1059.003` (Command Shell), `T1027` (Obfuscation), `T1021.002` (PsExec/SMB), `T1547.001` (Run Keys), `T1048.003` (FTP Exfil Non-C2) | Rule covers specific switches/LOLBins but is susceptible to alternative evasion techniques. |
| **Telemetry gap** | **4** | `T1071.001` (Web C2), `T1053.005` (Scheduled Tasks), `T1046` (Network Scanning), `T1047` (WMI Execution) | Logging channel or telemetry source is absent from current collection. |
| **No rule mapped (Backlog)** | **6** | `T1055` (Process Injection), `T1003.002` (SAM Dumping), `T1082` (System Info), `T1016` (Network Config), `T1562.001` (Impair Defenses), `T1070.001` (Clear Event Logs) | High-priority techniques identified during threat modeling awaiting detection authoring. |
| **Total Evaluated** | **22** | **22 Distinct ATT&CK Techniques across 9 Tactics** | Comprehensive evidence-backed defensive coverage assessment. |

---

## 6. Telemetry Inventory & Ground-Truth Findings

The project evaluates two physical telemetry artifacts documented in [`data/DATA_DICTIONARY.md`](file:///data/DATA_DICTIONARY.md):

1. **`empire_mimikatz_logonpasswords_2020-08-07103224.json` (Mordor NDJSON)**
   - **Size:** 43,478,765 bytes (~43.5 MB) | **Records:** 6,026 lines scanned, 6,026 valid events, 0 malformed.
   - **Top Channels:** Windows PowerShell Engine 800 (2,940), PowerShell Operational 4103 (1,695), Sysmon ProcessAccess 10 (272), Windows Filtering Platform 5156/5158 (406), Sysmon Registry 12/13 (199), Sysmon Network 3 (90), Sysmon ImageLoad 7 (81), Security Handle/Object 4656/4658/4663/4690 (221), Security Logon/Token 4624/4634/4672/4703 (43), Sysmon File/Process 1/5/11 (26).
   - *Key Telemetry Fact:* PowerShell Operational (Event ID 4103) is embedded within this NDJSON file, not stored as a separate 3rd physical file. Event ID 4104 (ScriptBlock Logging), Event ID 4625 (Failed Logon), and Event ID 7045 (System Service Install) are **absent** from this dataset.

2. **`exec_sysmon_1_ftp.evtx` (Binary Windows Event Log)**
   - **Size:** 69,632 bytes (~68 KB) | **Header:** `ElfFile` (standard binary EVTX).
   - **Contents:** Contains Sysmon Event ID 1 (`cmd.exe /c` executing `ftp.exe -s:...`) and Sysmon Event ID 3.
   - *Limitation:* Inspected via binary headers and strings; not parsed programmatically by the automated Python test suite due to missing `python-evtx` library in the environment.

---

## 7. Prerequisites & Environment Setup

### Required Tools & Runtimes
- **Operating System:** Windows, Linux, or macOS.
- **Python Version:** Python 3.10+ (tested on Python 3.14.6 x64).
- **Core Dependencies:**
  - `PyYAML` — For YAML schema parsing and structure validation.
  - `pySigma` — Official SigmaHQ engine for single-event rule validation.
  - `pandas` — For tabular telemetry aggregation and event distribution analysis.
  - `jupyter` / `nbclient` / `nbformat` — For notebook execution and validation.

---

## 8. Usage & Verification Guide

### 1. Execute the Automated Sigma Rule Validator
Run the validation script directly from the repository root:

```bash
python tests/validate_rules.py
```

To run the built-in validator unit tests and self-test verification:

```bash
python tests/validate_rules.py --self-test
```

**Expected Validator Output:**
- Production Rule Count: `15 / 15 (PASS)`
- UUID Uniqueness: `15 unique IDs across 15 production rules (PASS)`
- Duplicate Detection Logic: `0 duplicate blocks found (PASS)`
- pySigma Schema Validation: `14 single-event rules validated (PASS); 1 correlation rule validated against Sigma Correlation Schema (PASS)`
- Telemetry Verification: `2 PASS, 1 FAIL, 3 BLOCKED, 1 NOT RUN`
- Overall Exit Code: `0`

### 2. Execute the Telemetry Parsing Notebook
To execute the streaming NDJSON parser notebook from the repository root without overwriting raw source data:

```bash
# Standard execution (Linux / macOS):
jupyter execute data/parse_logs.ipynb

# Windows PowerShell execution (ensuring UTF-8 console decode):
$env:PYTHONUTF8="1"; jupyter execute data/parse_logs.ipynb
```

The notebook dynamically resolves dataset paths relative to both the repository root and `data/` subfolder, parses 6,026 NDJSON events, groups event distributions by channel and Event ID, and prints confirmed detection evidence.

---

## 9. Comprehensive Validation Results Summary

| Test # | Target Rule | Test Description & Telemetry Source | Result | Evidence & Engineering Rationale |
| :---: | :--- | :--- | :---: | :--- |
| **1** | `sysmon_lsass_dump.yml` | Sysmon Event ID 10 Handle Access to `lsass.exe` | **PASS** | Matched 1 non-benign handle read: Source `powershell.exe`, Target `lsass.exe`, `GrantedAccess` `0x1010` on WORKSTATION5 at `10:32:56 UTC`. |
| **2** | `sysmon_recon_whoami.yml` | Sysmon Event ID 1 Discovery with UserInit Exclusion | **PASS** | Matched 1 process creation: `whoami.exe` spawned by parent `powershell.exe` at `14:32:45 UTC`. Benign `userinit.exe` filter confirmed. |
| **3** | `sysmon_whoami_recon.yml` | PowerShell ScriptBlock Logging Credential Access | **FAIL** | 1,695 Event 4103 records present, but Empire executed via in-memory jobs (`Receive-AgentJob`, `Test-MemoryRangeValid`) without plaintext `Invoke-Mimikatz`. |
| **4** | `sysmon_ftp_brute_force.yml`| Windows Security Event ID 4625 Failed Logons | **BLOCKED** | Event ID 4625 is absent (0 records) in the Mordor dataset. Test blocked pending authentication failure logs. |
| **5** | `sysmon_valid_accounts.yml` | Windows Security Event ID 4672 Sensitive Privileges | **BLOCKED** | All 10 Event 4672 records belong to machine account `MONDORDC$` and were filtered out. Human admin telemetry is absent. |
| **6** | `sysmon_service_creation.yml`| Windows System Event ID 7045 Service Installation | **BLOCKED** | Windows System event log is absent from the Mordor JSON dataset. Test blocked pending System channel telemetry. |
| **7** | `correlation_ps_lsass_dump.yml`| Temporal Correlation: PowerShell followed by LSASS | **NOT RUN** | Underlying events confirmed 11 seconds apart on host WORKSTATION5. Full correlation query requires a stateful correlation engine backend. |

---

## 10. Technical Limitations & Engineering Roadmap

1. **Authentication & Persistence Telemetry Gaps:**
   - Ingest `winevent_security_4625_bruteforce.json` and `winevent_system_7045_service_install.json` to unblock behavioral validation for brute-force and service installation rules.
2. **Binary EVTX Parsing Integration:**
   - Integrate `python-evtx` into the test runner to programmatically evaluate `exec_sysmon_1_ftp.evtx` and unblock automated testing for `sysmon_ftp_exfil.yml`.
3. **Correlation Engine Deployment:**
   - Deploy a streaming correlation engine (such as a SIEM correlation worker or pySigma correlation backend) to execute multi-event temporal queries in automated CI/CD pipelines.
4. **Resilient In-Memory Script Heuristics:**
   - Complement plaintext ScriptBlock keyword matching with AST-level de-obfuscation and memory allocation anomaly detection to detect in-memory post-exploitation frameworks.

---

## 11. Documentation Links

- **MITRE ATT&CK Matrix:** [`docs/ATTACK_COVERAGE_MATRIX.md`](file:///docs/ATTACK_COVERAGE_MATRIX.md)
- **Telemetry Data Dictionary:** [`data/DATA_DICTIONARY.md`](file:///data/DATA_DICTIONARY.md)
- **Executive Summary:** [`EXECUTIVE_SUMMARY.md`](file:///EXECUTIVE_SUMMARY.md)
- **Engineering Methodology:** [`METHODOLOGY.md`](file:///METHODOLOGY.md)
- **Threat Hunts:** [`hunts/HUNT_001_C2_BEACONING.md`](file:///hunts/HUNT_001_C2_BEACONING.md) | [`hunts/HUNT_002_CREDENTIAL_DUMPING.md`](file:///hunts/HUNT_002_CREDENTIAL_DUMPING.md)
- **Incident Reports:** [`incidents/INCIDENT_001_LSASS_DUMP.md`](file:///incidents/INCIDENT_001_LSASS_DUMP.md) | [`incidents/INCIDENT_002_COMMAND_LINE_FTP_EXFIL.md`](file:///incidents/INCIDENT_002_COMMAND_LINE_FTP_EXFIL.md)
- **Incident Response Playbooks:** [`playbooks/PLAYBOOK_001_LSASS_DUMP.md`](file:///playbooks/PLAYBOOK_001_LSASS_DUMP.md) | [`playbooks/PLAYBOOK_002_CREDENTIAL_COMPROMISE.md`](file:///playbooks/PLAYBOOK_002_CREDENTIAL_COMPROMISE.md) | [`playbooks/PLAYBOOK_003_LATERAL_MOVEMENT.md`](file:///playbooks/PLAYBOOK_003_LATERAL_MOVEMENT.md)

---

## 12. Portfolio Summary & Readiness Statement

The **CDL-DET-V2** project provides a transparent, defensible demonstration of enterprise detection engineering. All 15 production rules have been structurally verified with zero duplicate selection blocks and 100% unique UUIDs. Detections against LSASS process memory access and whoami system discovery were verified against authentic adversary emulation traces. Unvalidated rules and telemetry gaps are explicitly documented rather than concealed, providing an honest baseline ready for peer review, SOC deployment, and future research iterations.
