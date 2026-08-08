# Detection 004 – Remote Desktop (RDP) Logon Detection

## Objective

Detect successful Remote Desktop Protocol (RDP) logons by monitoring Windows Security Event ID 4624 with Logon Type 10.

---

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Lateral Movement | T1021.001 – Remote Services: Remote Desktop Protocol |

---

## Data Source

- Windows Security Event Log
- Event ID 4624

---

## Detection Logic

Monitor successful logon events where:

- Event ID = 4624
- Logon Type = 10

These events indicate a successful remote interactive logon, typically through Remote Desktop Protocol.

---

## Splunk Search

```spl
source="WinEventLog:Security" EventCode=4624
| rex field=Message "Logon Type:\s+(?<LogonType>\d+)"
| rex field=Message "Account Name:\s+(?<AccountName>[^\r\n]+)"
| rex field=Message "Source Network Address:\s+(?<SourceIP>[^\r\n]+)"
| search LogonType=10
| table _time host AccountName SourceIP LogonType
| sort -_time
```

---

## Test Procedure

1. Enable Remote Desktop on the target Windows system.
2. Connect from another Windows system using Remote Desktop Connection (`mstsc`).
3. Authenticate with valid credentials.
4. In Splunk, run the detection search.
5. Verify that Windows Security Event ID 4624 appears with Logon Type 10.
6. Confirm the destination host, account name, source IP address, and event time.

---

## Validated Result

The detection was validated in the Enterprise Splunk SOC Lab with the following observed event:

- Event ID: 4624
- Logon Type: 10 (Remote Interactive)
- Host: DC01
- Account: DC01$
- Source IP: 192.168.81.181
- Time: 2026-08-07 18:53:30

---

## Investigation Guidance

When this detection triggers:

1. Confirm the account was authorized to use RDP.
2. Validate that the source IP belongs to an expected administrative workstation or approved network.
3. Review nearby Event ID 4624, 4625, 4634, and 4647 events for related logon activity.
4. Check for unusual login times, new source systems, privileged accounts, or repeated failures before the successful logon.
5. Correlate the session with endpoint, firewall, and authentication telemetry.
6. Escalate if the source, account, or timing is unexpected.

---

## False Positives

Legitimate activity may include:

- System administrators using RDP for maintenance
- Help desk personnel supporting users
- Approved remote management activity
- Authorized lab testing

Reduce noise by documenting approved administrative accounts and source systems while continuing to alert on unusual combinations.

---

## Detection Status

Validated in the lab using a successful RDP connection to DC01.
