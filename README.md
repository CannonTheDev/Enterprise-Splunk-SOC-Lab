# 🛡️ Enterprise Splunk SOC Lab

> A fully documented enterprise Security Operations Center (SOC) lab built using Microsoft Active Directory, Windows Server, Windows 11, Sysmon, Splunk Enterprise, and Universal Forwarders.

---

## 📖 Project Overview

This project documents the design, deployment, and operation of a realistic enterprise SOC environment used for security monitoring, threat hunting, and incident response.

The goal of this lab is to simulate the day-to-day responsibilities of a Security Operations Center (SOC) analyst while developing practical experience with enterprise security technologies.

This repository will continue to grow as new detections, investigations, dashboards, and attack simulations are added.

---

# 🏗️ Lab Architecture

Current Environment

```
                    Internet
                        │
                VMware Workstation
                        │
        ┌───────────────┴───────────────┐
        │                               │
   Windows Server 2022              Windows Server 2022
        DC01                            DC02
   Active Directory              Replica Domain Controller
        │                               │
        └───────────────┬───────────────┘
                        │
                 Windows 11 Endpoint
                        │
                Universal Forwarder
                        │
                 Splunk Enterprise
```

---

# 🖥️ Environment

| Component | Technology |
|-----------|------------|
| Hypervisor | VMware Workstation |
| SIEM | Splunk Enterprise 10 |
| Endpoint Agent | Splunk Universal Forwarder |
| Operating Systems | Windows Server 2022 / Windows 11 |
| Directory Services | Microsoft Active Directory |
| Logging | Windows Event Logs |
| Endpoint Telemetry | Sysmon |
| Detection Framework | MITRE ATT&CK |
| Query Language | SPL |

---

# 🎯 Lab Objectives

- Build an enterprise Active Directory environment
- Deploy multiple Domain Controllers
- Forward Windows Event Logs into Splunk
- Deploy Sysmon to all endpoints
- Perform threat hunting using SPL
- Create security dashboards
- Detect common attacker techniques
- Practice incident investigations
- Map detections to MITRE ATT&CK
- Document each investigation like a real SOC analyst

---

# 🔍 Current Data Sources

✅ Windows Security Logs

✅ Windows System Logs

✅ Windows Application Logs

✅ Microsoft Sysmon Operational Logs

More data sources will be added as the lab expands.

---

# 🔎 Sample SPL Searches

### Successful Logons (4624)

```spl
source="WinEventLog:Security" EventCode=4624
| table _time host Account_Name Logon_Type Source_Network_Address
| sort - _time
```

---

### Failed Logons (4625)

```spl
source="WinEventLog:Security" EventCode=4625
| table _time host TargetUserName Source_Network_Address Failure_Reason
| sort - _time
```

---

### Count Events by Host

```spl
source="WinEventLog:System"
| stats count by host
```

---

### Sysmon Events

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by host
```

---

# 🛠️ Completed Milestones

- [x] Installed VMware Workstation
- [x] Created Enterprise Lab Network
- [x] Installed Splunk Enterprise
- [x] Installed Universal Forwarder
- [x] Built Active Directory Domain
- [x] Configured Domain Controller (DC01)
- [x] Added Replica Domain Controller (DC02)
- [x] Added Windows 11 Endpoint
- [x] Configured Event Forwarding
- [x] Configured Sysmon
- [x] Verified Security Logs
- [x] Verified Sysmon Logs
- [x] Verified Multi-Host Log Collection

---

# 🚧 Upcoming Work

- Create Authentication Dashboard
- Build Failed Logon Dashboard
- Build Account Lockout Dashboard
- Detect PowerShell Abuse
- Detect Pass-the-Hash Activity
- Detect Credential Dumping
- Detect PsExec Execution
- Detect RDP Activity
- Detect Lateral Movement
- Detect Suspicious Services
- Detect Scheduled Tasks
- Build MITRE ATT&CK Dashboard
- Build Executive SOC Dashboard

---

# 📷 Screenshots

Coming Soon

- Lab Architecture
- Splunk Dashboards
- Search Examples
- Universal Forwarders
- Sysmon Configuration
- Active Directory
- Detection Dashboards

---

# 📚 Skills Demonstrated

- Splunk Enterprise
- Splunk Universal Forwarder
- SPL (Search Processing Language)
- Windows Event Logging
- Microsoft Sysmon
- Active Directory
- Windows Server Administration
- VMware Workstation
- Threat Hunting
- Security Monitoring
- Detection Engineering
- Incident Response
- Security Operations
- Log Analysis
- Enterprise Network Administration

---

# 🚀 Future Enhancements

- Kali Linux
- Atomic Red Team
- Sysmon Custom Rules
- Sigma Rules
- Zeek
- Suricata
- Microsoft Defender Logs
- PowerShell Logging
- Windows Event Forwarding
- SOAR Integrations

---

# 👤 Author

**James Cannon**

Aspiring Security Operations Center (SOC) Analyst

CompTIA Security+ | CompTIA CySA+

Building enterprise security labs to gain hands-on experience with threat detection, incident response, and Splunk engineering.

---

⭐ If you found this project interesting, consider giving it a star.
