# Telemetry Data Dictionary & Log Source Specification

**Project:** Cyberion Defense Labs Detection Engineering (CDL-DET-V2)  
**Repository:** `cdl-det-v2-main`  
**Phase:** Phase 4 — MITRE ATT&CK Coverage Matrix & Telemetry Data Dictionary  
**Last Updated:** August 2026  
**Status:** Empirical Baseline (Audited against Repository Artifacts & Notebook Parse Results)

---

## 1. Scope, Purpose & Physical Artifact Inventory

This data dictionary catalogs the security log artifacts physically present in `data/`, detailing the event channels, Event IDs, schemas, and fields available for detection engineering and threat hunting. Rather than providing generic Windows event documentation, this dictionary is grounded directly in empirical observations from automated log parsing (`data/parse_logs.ipynb`) and validation tests (`tests/validate_rules.py`).

### Physical Dataset Inventory in `data/`

The repository contains exactly two physical raw telemetry files under `data/`:

| Artifact Filename | Physical Format | File Size | Ingestion / Parsing Status | Primary Telemetry Contents |
| :--- | :--- | :--- | :--- | :--- |
| `empire_mimikatz_logonpasswords_2020-08-07103224.json` | NDJSON (Newline Delimited JSON) | 43,478,765 bytes (~43.5 MB) | **Inspected & Parsed** (6,026 lines scanned; 6,026 valid records; 0 malformed lines) | Mixed enterprise telemetry from Mordor adversary emulation: Windows Security, Sysmon Operational, Windows PowerShell Engine, PowerShell Operational, and WMI Activity. |
| `exec_sysmon_1_ftp.evtx` | Binary Windows Event Log (`ElfFile`) | 69,632 bytes (~68 KB) | **Inspected File Header & Binary Strings; Not Parsed Programmatically** | Sysmon Operational log capturing process creation (Event ID 1) and network connection (Event ID 3) for command-line FTP execution (`ftp.exe -s:...`). |

> [!IMPORTANT]
> **PowerShell Telemetry Architecture Clarification:**
> PowerShell Operational logging (Event ID 4103) and Windows PowerShell engine logging (Event ID 800) are **not** stored as a separate third physical dataset file on disk. These events are embedded directly within the Mordor NDJSON artifact (`empire_mimikatz_logonpasswords_2020-08-07103224.json`). Section 4.1 of the original PRD outlined three logical sources (Windows Security, Sysmon, and PowerShell/Network); within this repository, PowerShell telemetry resides inside the primary NDJSON collection.

---

## 2. Telemetry Verification Status for Detection Test Scenarios

The following status matrix documents whether current repository data supports testing for the core attack techniques and detection rules implemented across the project.

| Detection Scenario / Technique | Target Event ID & Channel | Telemetry Observation Status | Test Result in `validate_rules.py` | Ground Truth Findings & Telemetry Constraints |
| :--- | :--- | :--- | :--- | :--- |
| **LSASS Process Handle Access** | Sysmon Event ID 10<br>`Microsoft-Windows-Sysmon/Operational` | **Observed** | **PASS** | 4 handle access records to `lsass.exe` observed in Mordor JSON. Successfully matched suspicious access: Source `C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe` requesting `GrantedAccess` `0x1010` on WORKSTATION5 at `10:32:56 UTC`. |
| **System Discovery / Whoami Execution** | Sysmon Event ID 1<br>`Microsoft-Windows-Sysmon/Operational` | **Observed** | **PASS** | 1 process creation record observed in Mordor JSON: `C:\Windows\System32\whoami.exe` executed at `14:32:45.881 UTC` spawned by parent `powershell.exe`. Verified exclusion of benign `userinit.exe` parent. |
| **PowerShell Script / Module Logging** | Event ID 4103 / 4104<br>`Microsoft-Windows-PowerShell/Operational` | **Observed** *(for 4103)*<br><br>**Not observed in current dataset** *(for 4104 & keywords)* | **FAIL** | 1,695 Event 4103 records observed. Event ID 4104 (ScriptBlock Logging) is absent. Adversary executed Empire via in-memory job handling (`Receive-AgentJob`, `Test-MemoryRangeValid`) without plaintext `Invoke-Mimikatz` strings in 4103 logs. |
| **Authentication Brute Force / Spray** | Security Event ID 4625<br>`Security` | **Not observed in current dataset** | **BLOCKED** | Event ID 4625 (An account failed to log on) is completely absent (0 records) in the Mordor JSON dataset. Automated validation blocked pending authentication failure logs. |
| **Sensitive Privilege Assignment** | Security Event ID 4672<br>`Security` | **Observed (Machine Only)**<br><br>**Not observed in current dataset (Human Admin)** | **BLOCKED** | 10 Event 4672 records observed in Mordor JSON, but ALL 10 belong to the domain controller machine account (`MONDORDC$`). These are filtered out by rule logic; non-machine human administrator telemetry is absent. |
| **Windows Service Installation** | System Event ID 7045<br>`System` | **Not observed in current dataset** | **BLOCKED** | The Windows System log channel is entirely absent from the Mordor JSON collection. Event ID 7045 records are absent (0 records). Automated validation blocked pending System channel telemetry. |
| **Temporal PowerShell-to-LSASS Correlation** | Multi-Event Sequence<br>(Sysmon 1 / PowerShell + Sysmon 10) | **Observed** *(underlying events)*<br><br>**Not parsed / not verified** *(correlation query)* | **NOT RUN** | Underlying event sequence confirmed: PowerShell execution at `10:32:45 UTC`, followed by LSASS handle access at `10:32:56 UTC` (delta: 11 seconds) on WORKSTATION5. Full correlation query requires a stateful correlation engine backend. |

### Status Category Definitions
- **Observed:** Telemetry events matching the channel and Event ID were parsed and verified in the repository datasets.
- **Not observed in current dataset:** The specific Event ID, field values, or adversary indicators are absent from the collected artifacts.
- **Not parsed / not verified:** Telemetry exists physically (e.g. EVTX binary) or underlying events exist, but automated parsing or correlation engine execution has not been completed.
- **Requires additional telemetry:** Telemetry must be collected and ingested into `data/` to enable empirical testing of corresponding detection rules.

---

## 3. Detailed Telemetry Channel & Event ID Catalog

### 3.1 Primary Artifact: `empire_mimikatz_logonpasswords_2020-08-07103224.json`
Scanned lines: **6,026** | Valid JSON events: **6,026** | Malformed lines: **0**

#### Event Distribution by Channel and Event ID

| Channel | Event ID | Count | Event Description / Telemetry Function | Relevant Detection Rules & Threat Hunts |
| :--- | :---: | :---: | :--- | :--- |
| `Windows PowerShell` | 800 | 2,940 | Pipeline Execution Details (Engine execution trace) | `rules/sysmon_net_powershell_conn.yml`, `rules/sysmon_powershell_encoded.yml` |
| `Microsoft-Windows-PowerShell/Operational` | 4103 | 1,695 | Executing Pipeline / Module Logging | `rules/sysmon_whoami_recon.yml`, `hunts/HUNT_002_CREDENTIAL_DUMPING.md` |
| `Microsoft-Windows-Sysmon/Operational` | 10 | 272 | Process Access (Handle opened to target process) | `rules/sysmon_lsass_dump.yml`, `rules/correlation_ps_lsass_dump.yml`, Hunt #002 |
| `Security` | 5156 | 211 | Windows Filtering Platform: Connection Allowed | Candidate for Network Scanning / C2 detection |
| `Security` | 5158 | 195 | Windows Filtering Platform: Bind to Local Port | Candidate for Local Port Listening / Backdoor detection |
| `Microsoft-Windows-Sysmon/Operational` | 12 | 154 | Registry Object Added or Deleted | Registry persistence and tampering investigations |
| `Microsoft-Windows-Sysmon/Operational` | 3 | 90 | Network Connection Initiated | `rules/sysmon_net_powershell_conn.yml`, `rules/sysmon_net_ftp_exfil.yml`, Hunt #001 |
| `Security` | 4658 | 86 | Handle to an Object Closed | Object lifecycle & handle tracking |
| `Microsoft-Windows-Sysmon/Operational` | 7 | 81 | Image Loaded (DLL / Module Load) | DLL sideloading, injection, and unhooking investigations |
| `Security` | 4656 | 49 | A Handle to an Object was Requested | Native Windows object access auditing |
| `Microsoft-Windows-Sysmon/Operational` | 13 | 45 | Registry Value Set | `rules/sysmon_reg_run_persistence.yml` |
| `Security` | 4663 | 43 | An Attempt was Made to Access an Object | File / object access auditing |
| `Security` | 4690 | 43 | An Attempt was Made to Duplicate a Handle | Token and handle duplication investigations |
| `Microsoft-Windows-Sysmon/Operational` | 11 | 14 | File Create (File system write) | Payload drop / staging detection |
| `Security` | 4703 | 13 | A Token Right was Adjusted | Privilege elevation and token manipulation |
| `Security` | 4689 | 11 | Process Exited | Process duration and session bounding |
| `Microsoft-Windows-Sysmon/Operational` | 5 | 11 | Process Terminated | Process lifecycle and timeline reconstruction |
| `Security` | 4672 | 10 | Special Privileges Assigned to New Logon | `rules/sysmon_valid_accounts.yml` (Filtered machine accounts) |
| `Security` | 4634 | 10 | An Account was Logged Off | Session tracking and duration reconstruction |
| `Security` | 4627 | 10 | Group Membership Information | Logon identity and group enumeration |
| `Security` | 4624 | 10 | An Account was Successfully Logged On | Logon session analysis, authentication validation |
| `Windows PowerShell` | 600 | 8 | Provider Lifecycle (Provider Started/Stopped) | PowerShell runtime tracking |
| `Security` | 4673 | 6 | A Privileged Service was Called | Sensitive privilege invocation |
| `Microsoft-Windows-Sysmon/Operational` | 18 | 5 | Named Pipe Connected | Lateral movement / IPC investigation (`psexec`) |
| `Microsoft-Windows-Sysmon/Operational` | 9 | 3 | RawAccessRead (Direct volume read) | Offline credential theft / Volume Shadow access |
| `Microsoft-Windows-Sysmon/Operational` | 17 | 2 | Named Pipe Created | C2 pipe creation / lateral movement |
| `Security` | 5145 | 2 | Network Share Object Checked for Access | SMB / admin share lateral movement (`C$`, `ADMIN$`) |
| `Microsoft-Windows-Sysmon/Operational` | 1 | 1 | Process Creation (`whoami.exe`) | `rules/sysmon_recon_whoami.yml`, `rules/sysmon_cmd_execution.yml` |
| `Microsoft-Windows-Sysmon/Operational` | 22 | 1 | DNS Query Resolution | C2 domain resolution investigation |
| `Microsoft-Windows-WMI-Activity/Operational` | 5857 | 1 | WMI Provider Activity Started | WMI execution / persistence investigation |
| `Security` | 4688 | 1 | Process Creation (Native Auditing) | Native process creation verification |
| `Security` | 4670 | 1 | Permissions on an Object were Changed | ACL modification / defense evasion |
| `Security` | 5140 | 1 | A Network Share Object was Accessed | SMB share enumeration |
| `Windows PowerShell` | 400 | 1 | Engine State (Engine Started) | PowerShell invocation monitoring |

---

### 3.2 Secondary Artifact: `exec_sysmon_1_ftp.evtx`
File format: **Windows Event Log Binary (`ElfFile`)** | Size: **69,632 bytes (~68 KB)**

#### Telemetry Profile & Inspection Findings
- **Inspection Methodology:** Binary header inspection and UTF-16LE / ASCII string extraction.
- **Observed Event Types:**
  - `Microsoft-Windows-Sysmon/Operational` Event ID 1 (Process Creation)
  - `Microsoft-Windows-Sysmon/Operational` Event ID 3 (Network Connection)
- **Observed Command Lines & Payloads:**
  - `C:\Windows\system32\cmd.exe /C c:\Windows\system32\calc.exe`
  - `"C:\Windows\System32\ftp.exe" -s:c:\users\ieuser\appdata\local\temp\script.txt`
  - Host environment: Windows 7 SP1 x64 (`win7sp1_rtm.101119-1850`), User: `IEUser`.
- **Parsing Limitation:** In the current repository environment, `python-evtx` is not installed. As a result, the binary records cannot be parsed by `pandas` or imported directly into `tests/validate_rules.py` without external dependencies.
- **Consuming Rules & Hunts:**
  - `rules/sysmon_ftp_exfil.yml` (targets CLI switches `-s:`, `-i`)
  - `rules/sysmon_net_ftp_exfil.yml` (targets outbound FTP connections)
  - `hunts/HUNT_001_C2_BEACONING.md` (cross-referenced FTP exfiltration activity)

---

## 4. Key Field Dictionary & Analytical Semantics

The following table catalogs the core telemetry fields observed across the active datasets and defines their analytical meaning for rule authors and SOC analysts.

| Field Name | Source Channel(s) | Data Type | Analytical / Detection Significance | Example Value Observed in Telemetry |
| :--- | :--- | :--- | :--- | :--- |
| `EventID` | All Channels | Integer | Unique Windows or Sysmon event type identifier. Primary key for log source routing. | `10`, `1`, `4103`, `4624`, `4672` |
| `TimeCreated` / `UtcTime` | All Channels | ISO 8601 Timestamp | Timestamp when the event occurred. Essential for chronological sequencing and temporal correlation. | `2020-08-07T14:32:56.881Z` |
| `ComputerName` / `Hostname` | All Channels | String | Name of the endpoint where telemetry was generated. Used for grouping in correlation rules. | `WORKSTATION5.shire.local` |
| `Image` / `NewProcessName` | Sysmon 1, 3, 7, 10, 11; Security 4688 | String (Path) | Full path to the executable file executing the action. Primary target for process creation filtering. | `C:\Windows\System32\whoami.exe` |
| `CommandLine` | Sysmon 1; Security 4688 | String | Complete commandline invocation string including flags and arguments. Critical for LOLBin and switch detection. | `"whoami.exe"` |
| `ParentImage` | Sysmon 1; Security 4688 | String (Path) | Full path of the parent process that spawned the subject process. Essential for detecting anomalous parent-child relationships. | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `ParentCommandLine` | Sysmon 1 | String | Full command line of the parent process. Used for contextualizing child shell executions. | `"powershell.exe -NoP -NonI -W Hidden"` |
| `TargetImage` | Sysmon 10 (`process_access`) | String (Path) | Full path to the process being accessed by the `SourceImage`. Key indicator for LSASS memory dumps. | `C:\windows\system32\lsass.exe` |
| `GrantedAccess` | Sysmon 10 (`process_access`) | Hex String | Bitmask specifying access rights requested/granted to the `TargetImage`. `0x1010` indicates `PROCESS_QUERY_LIMITED_INFORMATION` + `PROCESS_VM_READ`. | `0x1010` (Observed from PowerShell to LSASS) |
| `CallTrace` | Sysmon 10 (`process_access`) | String | Stack trace of the DLLs and memory offsets involved in handle creation. Distinguishes legitimate API calls from unhooked/injected shells. | `C:\Windows\SYSTEM32\ntdll.dll+9fb04\|...` |
| `SourceIp` / `DestinationIp` | Sysmon 3; Security 5156 | IP String | Source and destination IPv4/IPv6 addresses. Used for exfiltration, C2, and internal lateral movement tracking. | `192.168.1.105` → `192.168.1.5` |
| `DestinationPort` | Sysmon 3; Security 5156 | Integer | Port number of destination service. Evaluated in network exfiltration and service discovery rules. | `53` (DNS), `80` (HTTP), `445` (SMB), `21` (FTP) |
| `Initiated` | Sysmon 3 | Boolean | Indicates whether the local host initiated the network socket connection. | `true` |
| `TargetObject` | Sysmon 12, 13, 14 | String (Registry Key) | Full registry key path being queried, created, or modified. Used in Run key persistence detection. | `\REGISTRY\MACHINE\SOFTWARE\Microsoft\...` |
| `Details` | Sysmon 13 | String | Content or value written to the registry object. | Value payload string |
| `SubjectUserName` / `TargetUserName` | Security 4624, 4625, 4672, 4688 | String | Username of the account initiating action (`Subject`) or target of logon (`Target`). Machine accounts end with `$`. | `MONDORDC$`, `IEUser`, `Administrator` |
| `PrivilegeList` | Security 4672 | String | List of high-privilege user rights assigned to a newly created logon token. | `SeDebugPrivilege`, `SeTcbPrivilege` |
| `Payload` / `ContextInfo` | PowerShell 4103 | String | Module logging execution payload or pipeline execution text. | `Receive-AgentJob`, `Test-MemoryRangeValid` |

---

## 5. Telemetry Capabilities, Boundaries & Missing Artifacts

### What the Current Telemetry Can Defensibly Establish
1. **LSASS Credential Access via Memory Read:** The Mordor dataset conclusively establishes that `powershell.exe` requested memory read access (`0x1010`) to `lsass.exe` on `WORKSTATION5`. This provides 100% ground-truth validation for `sysmon_lsass_dump.yml`.
2. **Reconnaissance LOLBin Execution:** The dataset proves process execution of `whoami.exe` directly spawned by an interactive PowerShell session, validating `sysmon_recon_whoami.yml`.
3. **In-Memory PowerShell Post-Exploitation Pipeline:** Over 1,600 PowerShell Operational events establish the continuous execution of Empire post-exploitation modules via memory job transfers.
4. **Interactive Command-Line FTP Scripting:** The `exec_sysmon_1_ftp.evtx` artifact confirms the execution of `ftp.exe` with `-s:` script execution switches.

### What the Current Telemetry Cannot Establish (Defensive Gaps)
1. **Authentication Brute Force / Password Spraying:** Because Windows Security Event ID 4625 is absent (0 records), brute-force detection logic in `sysmon_ftp_brute_force.yml` cannot be validated against live traffic.
2. **Human Administrative Elevation:** All 10 Event 4672 records belong to the domain controller machine account (`MONDORDC$`). Legitimate human admin privilege assignment is absent.
3. **Windows Service Installation via SCM:** The Windows System event log is missing from the Mordor collection. Event ID 7045 is entirely unrepresented, blocking validation of `sysmon_service_creation.yml`.
4. **Plaintext ScriptBlock Credential Dump Strings:** Empire's evasion capabilities executed credential dumping without exposing literal `Invoke-Mimikatz` strings in scriptblock logs.
5. **Application-Layer HTTP/HTTPS C2 Beaconing:** Neither artifact contains HTTP request headers (`User-Agent`, `URI`) or proxy logs, leaving C2 beaconing analysis inconclusive.

### Required Telemetry for Future Testing Rounds
To achieve 100% validated status across the remaining rules, future testing phases must ingest:
- `winevent_security_4625_bruteforce.json` — A telemetry trace containing sequential failed interactive and network logons.
- `winevent_system_7045_service_install.json` — System event logs capturing service installations from tools like `sc.exe` and `PsExec`.
- `winevent_security_4672_human_admin.json` — Security logs recording non-machine administrative logons (`Administrator`, `svc-admin`).
- Converted or parsed JSON equivalent of `exec_sysmon_1_ftp.evtx` for automated Python evaluation.