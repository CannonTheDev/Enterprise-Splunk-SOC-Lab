# Detection 001 - Windows Brute Force Detection

## Detection Overview

This detection identifies multiple failed Windows authentication attempts against the same account from the same source within a short period. Repeated failed logons are commonly associated with brute-force attacks or password spraying.

---

## MITRE ATT&CK

| Technique | ID |
|-----------|----|
| Brute Force | T1110 |

---

## Data Source

- Windows Security Event Logs
- Event ID 4625
- Splunk Enterprise

---

## SPL Detection

```spl
source="WinEventLog:Security" EventCode=4625
| eval FailedUser=mvindex(Account_Name,1)
| where FailedUser!="-"
| stats count by host Source_Network_Address FailedUser
| where count>=5
| sort -count
```

---

## Alert Configuration

| Setting | Value |
|---------|-------|
| Alert Type | Scheduled |
| Frequency | Every 5 Minutes |
| Trigger | Number of Results > 0 |
| Trigger Once | Yes |

---

## Validation

To validate the detection:

1. Log onto the Windows 11 endpoint.
2. Enter an incorrect password multiple times.
3. Verify Windows generates Event ID 4625.
4. Confirm Splunk receives the events.
5. Verify the alert triggers after five or more failures.

---

## Sample Output

| Host | Source IP | Failed User | Count |
|------|-----------|-------------|------:|
| WIN-11 | 127.0.0.1 | soctest | 21 |

---

## Investigation Steps

When this alert triggers:

- Review the targeted account.
- Identify the source IP.
- Determine whether the activity is internal or external.
- Check for successful logons after the failures.
- Determine if additional hosts were targeted.

---

## Response

- Disable compromised accounts if necessary.
- Block malicious IP addresses.
- Reset passwords.
- Review domain controller authentication logs.
- Escalate if malicious activity is confirmed.

---

## Skills Demonstrated

- Splunk SPL
- Windows Event Logging
- Active Directory
- Detection Engineering
- SOC Monitoring
- Alert Development
- MITRE ATT&CK Mapping
