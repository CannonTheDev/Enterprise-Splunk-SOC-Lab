# Detection 002 - Suspicious PowerShell Execution

## Objective

Detect potentially malicious PowerShell execution by monitoring Windows Security Event ID 4688 for common attacker techniques such as:

- Execution Policy Bypass
- Encoded Commands
- Invoke-Expression (IEX)
- Invoke-WebRequest
- DownloadString
- Hidden PowerShell
- PowerShell reconnaissance commands

---

## MITRE ATT&CK

| Technique | ID |
|-----------|----|
| PowerShell | T1059.001 |
| Command and Scripting Interpreter | T1059 |
| Ingress Tool Transfer | T1105 |
| Defense Evasion | T1562 |

---

## Data Source

- Windows Security Log
- Event ID 4688 (Process Creation)

---

## SPL Detection

See **detection.spl**

---

## Detection Logic

The search extracts:

- Username
- Parent Process
- Process Name
- Command Line

It then classifies suspicious PowerShell activity using keyword matching.

Examples include:

- ExecutionPolicy Bypass
- EncodedCommand
- IEX
- DownloadString
- Invoke-WebRequest
- Hidden PowerShell
- Get-Process (lab validation)

---

## Alert Configuration

Alert Type

Real-Time

Trigger

Number of Results > 0

Throttle

Disabled

---

## Testing

The following commands successfully generated alerts.

### Test 1

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Process
```

Result:

Execution Policy Bypass detected.

---

### Test 2

```powershell
powershell.exe -EncodedCommand <Base64>
```

Result:

Encoded PowerShell detected.

---

## Investigation Workflow

1. Review username
2. Review parent process
3. Review full command line
4. Determine whether execution was expected
5. Escalate if malicious behavior is confirmed

---

## Screenshots

- SPL Search
- Detection Dashboard
- Triggered Alert
- PowerShell Test

---

## Lessons Learned

Process Creation auditing (Event ID 4688) provides valuable visibility into PowerShell activity.

Combining process creation with keyword-based detections enables rapid identification of common attacker techniques while minimizing false positives by excluding Splunk-generated processes.
