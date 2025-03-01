# Sudden Network Slowdowns

## 1. Preparation
**Goal:** Set up the hunt by defining what you're looking for.

### Scenario:
The server team has noticed significant network performance degradation on some older devices attached to the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects internal malicious activity.

### Hypothesis:
- Could there be lateral movement in the network?
- Are large file downloads or port scanning activities occurring?
- Since all internal traffic is allowed by default, unrestricted PowerShell use could be exploited.

---
## 2. Data Collection
**Goal:** Gather relevant data from logs, network traffic, and endpoints.

### Steps:
- Inspect logs for excessive successful/failed connections.
- Pivot and inspect devices for suspicious file or process events.
- Ensure the relevant logs exist:
  - `DeviceNetworkEvents`
  - `DeviceFileEvents`
  - `DeviceProcessEvents`

---
## 3. Data Analysis
**Goal:** Analyze data to test your hypothesis.

### Analysis Questions:
- Are there excessive network connections from/to specific hosts?
- Are there patterns or indicators of compromise (IOCs)?

### Sample Query:
```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

### Findings:
- Host `rich-mde-test` showed 69 failed connection requests against itself.
- Sequential failed connection requests from `10.0.0.156` indicated a port scan.

```kusto
let IPInQuestion = "10.0.0.156";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

---
## 4. Investigation
**Goal:** Investigate any suspicious findings.

- Checked `DeviceProcessEvents` for activities around the time of the detected port scan.
- Found a PowerShell script `portscan.ps1` launching at `2025-02-28T00:37:05.8693723Z`.

```kusto
let VMName = "rich-mde-test";
let specificTime = datetime(2025-02-27T23:40:41.3159013Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 60m) .. (specificTime + 60m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

- The script was executed by the `SYSTEM` account, which is unusual.
- Device was manually inspected and found to contain `portscan.ps1`.

---
## 5. Response
**Goal:** Mitigate any confirmed threats.

### Actions Taken:
1. **Isolated the affected device** (`rich-mde-test`).
2. **Conducted malware scan** (no known malware found).
3. **Investigated for persistence mechanisms** (scheduled tasks, registry modifications, etc.).
4. **Decided to reimage/rebuild the machine** as a precaution.

---
## 6. Documentation
**Goal:** Record findings and improve future hunts.

### Identified MITRE ATT&CK TTPs:
- **Reconnaissance (TA0043)**
  - `T1595.002 – Active Scanning: Port Scanning`
  - Sequential failed connections suggest automated port scanning.
- **Discovery (TA0007)**
  - `T1046 – Network Service Discovery`
  - PowerShell script scanning active hosts and services.
- **Execution (TA0002)**
  - `T1059.001 – Command and Scripting Interpreter: PowerShell`
  - Use of PowerShell for reconnaissance.
- **Privilege Escalation (TA0004)**
  - `T1548.002 – Elevated Execution with SYSTEM`
  - Execution by SYSTEM account is highly suspicious.

---
## 7. Improvement
**Goal:** Enhance security posture and refine methods for future hunts.

### Preventative & Hardening Measures:
- **Audit Logs & Monitoring**: Enable enhanced logging for PowerShell and network activities.
- **Least Privilege Enforcement**: Restrict SYSTEM account execution.
- **Endpoint Detection & Response (EDR) Improvements**: Fine-tune security rules to detect PowerShell-based reconnaissance and port scanning.

### Summary:
- Port scan activity detected and linked to `portscan.ps1`.
- SYSTEM account execution raised red flags.
- Device was isolated, scanned, and ultimately reimaged to prevent further risks.

