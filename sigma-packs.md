# twlogeye Embedded Sigma Rule Packs Guide

twlogeye provides **7 recommended embedded Sigma rule packs (57 rules in total)** designed for high-fidelity detection with minimal false positives.
Without needing to download or manage external rule repositories, you can immediately begin monitoring and threat detection simply by specifying the desired pack names in your configuration file (`twlogeye.yaml`) or command line options.

---

## Table of Contents

1. [Overview and Usage](#1-overview-and-usage)
2. [Rule Packs Summary](#2-rule-packs-summary)
3. [Detailed Pack and Rule Reference](#3-detailed-pack-and-rule-reference)
   - [windows-essential (Windows Essential Security Events)](#windows-essential)
   - [windows-ad (Active Directory / Domain Controller Threats)](#windows-ad)
   - [windows-client (Windows Endpoint & Client Threats)](#windows-client)
   - [linux-auth (Linux Authentication & Privilege Escalation)](#linux-auth)
   - [linux-system (Linux Persistence & System Tampering)](#linux-system)
   - [network-threats (Network Devices, Firewalls & VPNs)](#network-threats)
   - [web-attacks (Web Server & Proxy Exploits)](#web-attacks)
4. [Custom Rules and Priority Override](#4-custom-rules-and-priority-override)

---

## 1. Overview and Usage

### Configuration File (`twlogeye.yaml`)
Specify the packs you wish to enable under `sigmaPacks`:

```yaml
sigmaPacks:
  - windows-essential
  - windows-ad
  - windows-client
  - linux-auth
  - linux-system
  - network-threats
  - web-attacks
```

### Command Line Flags
You can also enable packs directly when starting the server:

```bash
twlogeye start --sigmaPacks windows-essential,linux-auth
```

### CLI Inspection and Testing
```bash
# List all available embedded packs and rule counts
twlogeye sigma packs

# List loaded rules with their source information
twlogeye sigma list --sigmaPacks windows-essential,linux-auth

# Filter rules by a specific pack
twlogeye sigma list --sigmaPacks windows-essential,linux-auth --pack linux-auth

# Test rule matching against a sample log entry
twlogeye sigma test --sigmaPacks windows-essential '{"Event":{"System":{"EventID":4625}}}'
```

---

## 2. Rule Packs Summary

| Pack Name | Rules | Target Log Source | Key Detection Objectives |
| :--- | :---: | :--- | :--- |
| **`windows-essential`** | 12 | Windows Event (Security, System, Defender) | Failed logons, log clearing, service installation, Defender disabled, suspicious PowerShell |
| **`windows-ad`** | 8 | Windows Event (Security / AD DC) | Kerberoasting, AS-REP Roasting, DCSync, domain trust modifications, GPO tampering |
| **`windows-client`** | 8 | Windows Event (Security, TerminalServices) | Suspicious RDP, UAC bypass, USB removable media plugged, LSASS memory dump |
| **`linux-auth`** | 6 | Linux Syslog (sshd, sudo, useradd) | SSH brute force, invalid user login, direct root SSH, sudo authentication failures |
| **`linux-system`** | 7 | Linux Syslog (cron, systemd, shadow, ufw) | Cron modification, systemd service added, shadow file tampering, host firewall stopped |
| **`network-threats`** | 8 | Syslog (Fortinet, Cisco, Yamaha, Palo Alto) | VPN brute force, management WebUI login failure, port scan, config change audits |
| **`web-attacks`** | 8 | Web/Proxy Access Logs (Syslog / OTel) | Log4Shell, path traversal, SQL injection, webshell access, vulnerability scanners, XSS |

---

## 3. Detailed Pack and Rule Reference

### `windows-essential`
Aggregates critical Windows security events collectible from **standard Windows Event Logs without needing Sysmon or external agents**.

- **Target Logs**: Windows Event Log (`Security`, `System`, `Microsoft-Windows-Windows Defender/Operational`)
- **Objective**: Early detection of reconnaissance, credential access, defense evasion, and destructive ransomware actions.
- **Security Impact**: Rapidly stops attackers during the initial-to-intermediate stages of compromise.

#### Rules Included (12 Rules)

| Rule Title | Target Event / Filter | Level | Objective & Security Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Windows Failed Logon Attempt** | EventID 4625 (Security) | `low` | Detects brute force or password spraying attempts against Windows accounts. | T1110 (Credential Access) |
| **User Account Created** | EventID 4720 (Security) | `medium` | Detects unauthorized user account creation used for persistence/backdoors. | T1136.001 (Persistence) |
| **Member Added to Security Group** | EventID 4728, 4732, 4756 | `high` | Detects member addition to sensitive groups such as Administrators or Domain Admins. | T1098 (Privilege Escalation) |
| **Special Privileges Assigned to New Logon** | EventID 4672 (Security) | `low` | Audits logons assigned administrative rights (e.g. SeDebugPrivilege). | T1078 (Privilege Escalation) |
| **Security Event Log Cleared** | EventID 1102 (Security) | `high` | Detects anti-forensic activity when the Security log is cleared. | T1070.001 (Defense Evasion) |
| **System Event Log Cleared** | EventID 104 (System) | `high` | Detects clearing of the Windows System event log. | T1070.001 (Defense Evasion) |
| **Windows Defender Real-time Protection Disabled** | EventID 5001 (WinDefend) | `high` | Alerts when Defender real-time protection is disabled prior to malware detonation. | T1562.001 (Defense Evasion) |
| **New Windows Service Installed** | EventID 7045 (System) | `medium` | Detects installation of new services (e.g., PsExec, persistence backdoors). | T1543.003 (Persistence) |
| **Scheduled Task Created** | EventID 4698 (Security) | `medium` | Detects scheduled task registration used for persistence or execution. | T1053.005 (Persistence) |
| **Suspicious PowerShell Execution** | EventID 4688 (`-enc`, `DownloadString`, `iex`) | `high` | Detects encoded commands or in-memory script download/execution via PowerShell. | T1059.001 (Execution) |
| **Certutil Remote File Download** | EventID 4688 (`certutil` + `urlcache`) | `high` | Detects Living-off-the-Land (LOLBAS) abuse of certutil to download payloads. | T1105 (Command and Control) |
| **Volume Shadow Copies Deletion Via Vssadmin** | EventID 4688 (`vssadmin` + `delete shadows`) | `critical` | Detects shadow copy deletion typically executed by ransomware prior to encryption. | T1490 (Impact) |

---

### `windows-ad`
Focuses on **Active Directory Domain Controller threats, credential dumping, and domain lateral movement**.

- **Target Logs**: Windows Event Log (`Security`, Directory Service)
- **Objective**: Identifies Kerberos abuse, DCSync replication abuse, and unauthorized domain trust changes.
- **Security Impact**: Prevents complete takeover of the enterprise AD forest and domain credentials.

#### Rules Included (8 Rules)

| Rule Title | Target Event / Filter | Level | Objective & Security Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Potential Kerberoasting Attack** | EventID 4769 (TicketEncryptionType: 0x17) | `high` | Detects weak RC4 Kerberos service ticket requests for offline password cracking. | T1558.003 (Credential Access) |
| **Potential AS-REP Roasting Attack** | EventID 4768 (PreAuthType: 0) | `medium` | Detects TGT requests for accounts with pre-authentication disabled. | T1558.004 (Credential Access) |
| **Potential DCSync Active Directory Replication** | EventID 4662 (AccessMask: 0x100) | `high` | Detects directory replication requests (DCSync) used by tools like Mimikatz. | T1003.006 (Credential Access) |
| **Domain Trust Relationship Modified** | EventID 4706, 4716 | `high` | Detects rogue trust relationships created or altered with external domains. | T1484 (Persistence) |
| **User Password Reset Attempt** | EventID 4724 | `low` | Tracks forced password resets executed by administrators or compromised accounts. | T1098 (Persistence) |
| **User Account Unlocked** | EventID 4767 | `low` | Audits account unlocks following brute force lockout events. | T1098 (Persistence) |
| **Computer Account Created in Domain** | EventID 4741 | `low` | Detects addition of new computer accounts to Active Directory. | T1136.002 (Persistence) |
| **Group Policy Object Modified** | EventID 5136, 5137 | `medium` | Detects GPO tampering used to deploy malicious scripts across the domain. | T1484.001 (Persistence) |

---

### `windows-client`
Detects suspicious activities, lateral movement, and unauthorized devices on **workstations, laptops, and VDI clients**.

- **Target Logs**: Windows Event Log (`Security`, `System`, TerminalServices, DriverFrameworks)
- **Objective**: Identifies remote desktop compromise, UAC bypasses, unauthorized USB devices, and credential dumping.
- **Security Impact**: Isolates threat actors at the endpoint before they spread deeper into the internal network.

#### Rules Included (8 Rules)

| Rule Title | Target Event / Filter | Level | Objective & Security Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Remote Desktop (RDP) Logon Detected** | EventID 4624 (LogonType 10) | `low` | Audits and tracks successful interactive RDP network sessions. | T1021.001 (Lateral Movement) |
| **Terminal Services RDP Connection Established** | EventID 1149 (TerminalServices) | `low` | Detects initial network-level RDP connection handshakes. | T1021.001 (Lateral Movement) |
| **UAC Bypass Via Fodhelper** | EventID 4688 (`fodhelper`) | `high` | Detects execution of fodhelper.exe to silently elevate privileges without UAC prompts. | T1548.002 (Privilege Escalation) |
| **UAC Bypass Via Event Viewer** | EventID 4688 (`eventvwr.exe`) | `low` | Detects registry hijacking abuse of Event Viewer for privilege escalation. | T1548.002 (Privilege Escalation) |
| **USB Storage Device Plugged In** | EventID 20001, 20003 | `low` | Tracks connection of external USB flash drives (data exfiltration/malware vectors). | T1052.001 (Initial Access / Exfiltration) |
| **LSASS Memory Dump Attempt** | EventID 4688 (`lsass` + `dump`) | `critical` | Detects tools (e.g. procdump) targeting LSASS memory to extract plaintext passwords. | T1003.001 (Credential Access) |
| **BITSAdmin File Transfer Execution** | EventID 4688 (`bitsadmin` + `/transfer`) | `medium` | Detects abuse of BITS background transfer service for payload retrieval. | T1197 (Defense Evasion) |
| **Network Share Object Added** | EventID 5142 | `low` | Detects creation of new SMB network shares for staging or lateral file transfers. | T1021.002 (Lateral Movement) |

---

### `linux-auth`
Focuses on **SSH logins, sudo authentication, and account creation events** on Linux servers.

- **Target Logs**: Linux Syslog (`/var/log/auth.log`, `/var/log/secure`, systemd journal)
- **Objective**: Detects brute force attempts, unauthorized root logins, and privilege escalation via sudo.
- **Security Impact**: Secures external-facing jump hosts, bastion servers, and internal Linux infrastructure.

#### Rules Included (6 Rules)

| Rule Title | Target Keyword / Filter | Level | Objective & Security Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **SSH Failed Password Authentication** | `Failed password for` | `low` | Detects SSH password brute-force or spraying attacks. | T1110 (Credential Access) |
| **SSH Login Attempt With Invalid User** | `Failed password for invalid user` | `medium` | Detects username enumeration and probing attempts against SSH servers. | T1110 (Credential Access) |
| **Direct SSH Root Login Accepted** | `Accepted password for root` / `Accepted publickey for root` | `medium` | Alerts on direct root SSH logins which bypass personal accountability. | T1078.003 (Initial Access) |
| **Sudo Authentication Failure** | `authentication failure`, `incorrect password attempt` | `medium` | Detects internal privilege escalation attempts or unauthorized sudo execution. | T1548.003 (Privilege Escalation) |
| **Sudoers Configuration File Modified** | `etc/sudoers`, `visudo` | `high` | Detects tampering with sudo permissions (e.g. adding NOPASSWD directives). | T1548.003 (Privilege Escalation) |
| **New Linux User Account Created** | `new user: name=`, `useradd` | `medium` | Detects rogue user provisioning on Linux hosts. | T1136.001 (Persistence) |

---

### `linux-system`
Monitors post-exploitation activities including **persistence mechanisms, configuration tampering, and defense evasion** on Linux systems.

- **Target Logs**: Linux Syslog (`syslog`, `messages`, `daemon.log`, `kern.log`)
- **Objective**: Detects backdoor installation via cron/systemd, shadow file tampering, and host firewall disabling.
- **Security Impact**: Discovers stealthy rootkits and persistent implants that survive reboots.

#### Rules Included (7 Rules)

| Rule Title | Target Keyword / Filter | Level | Objective & Security Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Cron Job Created or Modified** | `REPLACE (`, `crontab[`, `/etc/cron` | `low` | Detects cron task scheduling used to periodically re-execute backdoors. | T1053.003 (Persistence) |
| **Systemd Service Installed or Started** | `Created symlink /etc/systemd/system/`, `systemd: Started` | `low` | Detects installation and autostart enablement of rogue systemd unit files. | T1543.002 (Persistence) |
| **Password File Modified or Password Changed** | `password changed for`, `/etc/shadow` | `low` | Audits password updates and modifications to sensitive authentication files. | T1098 (Persistence) |
| **Linux Host Firewall Stopped or Flushed** | `ufw stop`, `firewalld: stopped`, `iptables -F` | `medium` | Detects disabling or flushing of host firewall rules. | T1562.004 (Defense Evasion) |
| **Linux User Account Deleted** | `delete user`, `userdel` | `low` | Alerts on user account deletion used for sabotage or covering tracks. | T1531 (Impact) |
| **New Linux Group Created** | `new group: name=`, `groupadd` | `low` | Detects suspicious new group creation. | T1136.001 (Persistence) |
| **Unsigned or Out-of-Tree Kernel Module Loaded** | `loading out-of-tree module`, `module verification failed` | `medium` | Detects potential kernel rootkit installation via unsigned modules. | T1547.006 (Persistence) |

---

### `network-threats`
Monitors Syslog from **routers, firewalls, and UTM appliances** (Fortinet FortiGate, Cisco IOS/ASA, Yamaha RTX/NVR, Palo Alto Networks).

- **Target Logs**: Syslog (UDP/TCP port 514 received from network appliances)
- **Objective**: Real-time detection of external network scanning, VPN brute force, and appliance configuration changes.
- **Security Impact**: Protects perimeter and internal network boundaries.

#### Rules Included (8 Rules)

| Rule Title | Target Keyword / Filter | Level | Objective & Security Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **VPN Authentication Failed** | `VPN authentication failed`, `IPsec authentication failed` | `medium` | Detects brute force attempts against remote access VPN portals. | T1110 (Initial Access) |
| **FortiGate SSL VPN Authentication Failure** | `action=ssl-login-fail`, `SSL VPN login fail` | `medium` | Detects failed SSL-VPN logins on Fortinet FortiGate firewalls. | T1110 (Initial Access) |
| **Cisco Device Authentication Failure** | `%SEC_LOGIN-4-LOGIN_FAILED`, `%AAA-3-BADAUTH` | `medium` | Detects unauthorized console/SSH login attempts on Cisco routers/switches/ASAs. | T1110 (Credential Access) |
| **Yamaha Router Authentication Failure** | `Login failed`, `rejected TELNET`, `rejected SSH` | `medium` | Detects unauthorized access attempts to Yamaha network equipment. | T1110 (Credential Access) |
| **Firewall Admin Console Login Failure** | `admin login failed`, `WebUI login failed` | `medium` | Detects brute force attempts against firewall web/GUI management interfaces. | T1110 (Credential Access) |
| **Network Scan or Deny Flood** | `port scan`, `SYN flood`, `IP spoofing`, `LAND attack` | `high` | Detects external port scanning probes and DoS flooding activity. | T1046 (Discovery) |
| **Palo Alto Networks Threat Detected** | `,THREAT,`, `,vulnerability,`, `,spyware,` | `high` | Alerts when Palo Alto NGFWs trigger threat/exploit detection signatures. | T1190 (Initial Access) |
| **Network Device Configuration Changed** | `configuration changed`, `config commit`, `save config` | `low` | Audits administrative configuration changes on routers and switches. | T1565 (Defense Evasion) |

---

### `web-attacks`
Detects common exploitation payloads and web application attacks present in **Apache, Nginx, and reverse proxy access logs**.

- **Target Logs**: Web server access logs (forwarded via Syslog or OpenTelemetry)
- **Objective**: Detects exploitation of vulnerabilities, webshell persistence, and automated vulnerability scanners.
- **Security Impact**: Defends DMZ and public-facing web applications.

#### Rules Included (8 Rules)

| Rule Title | Target Keyword / Filter | Level | Objective & Security Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :--- | :--- |
| **Log4j JNDI Exploit Attempt (Log4Shell)** | `${jndi:ldap:`, `${jndi:rmi:`, `${jndi:dns:` | `critical` | Accurately catches Log4Shell (CVE-2021-44228) JNDI lookup strings. | T1190 (Initial Access) |
| **Path Traversal Attempt** | `/../`, `/etc/passwd`, `win.ini`, `%2e%2e%2f` | `high` | Detects directory traversal attempts seeking to read sensitive system files. | T1190 (Initial Access) |
| **SQL Injection Attempt** | `UNION SELECT`, `' OR 1=1`, `WAITFOR DELAY` | `high` | Detects SQL injection attack syntax targeting web backend databases. | T1190 (Initial Access) |
| **WebShell Access or Execution** | `eval(base64_decode`, `c99.php`, `r57.php`, `wso.php` | `critical` | Detects access to installed webshell scripts and remote code execution parameters. | T1505.003 (Persistence) |
| **Web Vulnerability Scanner User-Agent** | `Nikto`, `sqlmap`, `gobuster`, `dirbuster`, `Acunetix` | `medium` | Detects automated scanning tools probing for security flaws. | T1595.002 (Discovery) |
| **Cross Site Scripting (XSS) Pattern** | `<script>`, `javascript:alert(`, `<svg/onload=` | `medium` | Catches reflected/stored XSS script injection vectors in request URLs. | T1190 (Initial Access) |
| **Spring4Shell Remote Code Execution Attempt** | `class.module.classLoader` | `critical` | Detects exploits targeting Spring Framework RCE (CVE-2022-22965). | T1190 (Initial Access) |
| **PHP Information Disclosure Access (phpinfo)** | `phpinfo.php`, `info.php`, `?phpinfo=` | `low` | Detects probes targeting phpinfo files that disclose server configurations. | T1592.002 (Discovery) |

---

## 4. Custom Rules and Priority Override

You can seamlessly combine embedded rule packs with your own custom rules (`sigmaRules`) and dynamically added rules via WebAPI or MCP.

### Priority Rules
When multiple rules share the same `id` (UUID), **higher priority sources automatically override lower priority ones**:

1. **`db`** (Highest Priority: Rules added dynamically via MCP or REST API)
2. **`file:` / `embed:`** (High Priority: Custom rule files/directories specified in `sigmaRules`)
3. **`pack:`** (Standard Priority: Embedded rule packs)

### Example: Tuning an Embedded Rule
If you want to use the embedded `win_security_failed_logons` rule but need to add an exception for a specific internal service account, or change its severity level from `low` to `high`, simply place your modified YAML rule with the same ID in your custom rules directory (`sigmaRules`). **twlogeye will automatically replace the pack rule with your custom version.**
