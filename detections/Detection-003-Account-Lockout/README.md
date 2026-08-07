# Detection 003 - Windows Account Lockout Detection

## Objective

Detect Windows account lockout events using Windows Security Event ID 4740.

---

## Detection Summary

This detection identifies domain user accounts that have been locked due to repeated failed authentication attempts. It also identifies the originating computer responsible for the lockout.

This detection can help identify:

- Brute-force attacks
- Password spraying
- Misconfigured services
- Stale mapped drives
- Cached credentials
- Unauthorized authentication attempts

---

## MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |

---

## Splunk Search

```spl
source="WinEventLog:Security" EventCode=4740
| rex field=Message "Account That Was Locked Out:\r?\n\s+Security ID:.*?\r?\n\s+Account Name:\s+(?<LockedAccount>[^\r\n]+)"
| rex field=Message "Caller Computer Name:\s+(?<CallerComputer>[^\r\n]+)"
| table _time host LockedAccount CallerComputer
| sort -_time
```

---

## Detection Logic

The search monitors Windows Security Event ID **4740**, generated when a user account is locked out. In an Active Directory environment, these events are recorded on Domain Controllers.

The query parses the event message to extract:

- Locked user account
- Domain Controller that recorded the event
- Source workstation that initiated the failed authentication attempts
- Time of the lockout event

---

## Lab Environment

- Splunk Enterprise
- Windows Server 2022 Domain Controllers
- Active Directory Domain Services
- Windows 11 client
- Splunk Universal Forwarder
- Sysmon

---

## Test Procedure

1. Attempt multiple failed logins against a domain account.
2. Continue until the configured account lockout threshold is reached.
3. Verify that Windows Security Event ID 4740 is generated on the Domain Controller.
4. Run the detection query in Splunk.
5. Confirm that the locked account and originating workstation are identified.

---

## Expected Results

The detection should identify:

- Locked user account
- Source workstation
- Domain Controller
- Time of the lockout event

---

## False Positives

Account lockouts are not always malicious. Common benign causes include:

- Users repeatedly entering an incorrect password
- Services running with expired credentials
- Scheduled tasks using an old password
- Stale mapped drives
- Cached credentials on another endpoint

Analysts should correlate the caller computer, lockout frequency, affected accounts, and surrounding authentication activity before escalating.

---

## Analyst Response

1. Confirm the locked account and caller computer.
2. Review nearby failed logon events, especially Event ID 4625.
3. Determine whether one source is targeting multiple accounts.
4. Contact the user or system owner when appropriate.
5. Escalate if the activity indicates brute force, password spraying, or unauthorized access.

---

## References

- [Microsoft: Event 4740 - A user account was locked out](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740)
- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

