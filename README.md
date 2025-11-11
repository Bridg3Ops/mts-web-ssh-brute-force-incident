# SSH Brute Force Attack with Root Compromise

## Incident #709 - Critical System Breach

**Classification:** CONFIDENTIAL - INTERNAL USE ONLY  
**TLP:** RED - Restricted Distribution

---

## 1. Unauthorised RDP Logon and Malicious PowerShell Execution on Domain Controller

**Incident Classification:** Confirmed Security Breach - Critical System Compromise

---

## 2. Date of Report

**2025-11-10** (November 10, 2025)

---

## 3. Reported By

**Abe O**

---

## 4. Severity Level

🔴 **CRITICAL**

---

## 5. Summary of Findings

### Executive Summary

On November 10, 2025, at **02:00:15 AM GMT**, the MTS-Web Linux server became the target of a sophisticated, large-scale automated SSH brute force attack. The attack originated from multiple IP addresses and involved **12,683 failed authentication attempts** over approximately 2 minutes and 45 seconds.

**The attack was successful.** At **02:02:45 AM GMT**, the threat actor successfully compromised the **root account** using password-based authentication from IP address **209.226.177.189**. This represents a complete system compromise, as the root account has unrestricted access to all system resources.

### Post-Compromise Activity

Following successful authentication, the threat actor:

- **Maintained Persistent Access:** 283 connection/session events detected throughout the day (02:02 AM - 08:56 PM)
- **Deployed Malware:** Multiple malware variants including EICAR test file and Multiverze malware
- **Executed Suspicious Processes:** run-parts processes (PID 17185, 17187) under root privilege
- **Established Command & Control:** C2 communication with external IP 27.74.80.167
- **Attempted Defense Evasion:** Suspicious path deletion at 02:45 AM (likely log tampering)
- **Tested Security Controls:** EICAR test file used to verify antivirus evasion capabilities

### Current Status

The MTS-Web system remains **fully compromised** as of 22:00 GMT on November 10, 2025.

The threat actor maintains root-level access and has demonstrated:
- Advanced persistent threat (APT) characteristics
- Sophisticated post-exploitation techniques
- Intent to establish long-term access
- Potential for data exfiltration or destructive actions

**Immediate containment actions are required.**

---

## 6. Investigation Timeline

### Detailed Event Timeline (All times in UTC/GMT)

| Time | Event |
|------|-------|
| 02:00:15 | SSH brute force attack initiated from multiple IPs |
| 02:00:15 - 02:02:45 | 12,683 failed authentication attempts logged |
| **02:02:45** | **🚨 ROOT COMPROMISE: Successful password auth from 209.226.177.189** |
| 02:42:00 | Microsoft Defender Alert #1: Suspicious file or content ingress |
| 02:42:00 | Microsoft Defender Alert #2: EICAR_Test_File malware prevented |
| 02:45:00 | Microsoft Defender Alert #3: Suspicious path deletion |
| 03:18:00 | Microsoft Defender Alert #4: Second suspicious file ingress |
| 03:19:00 | Microsoft Defender Alert #5: Malware or PUA observed |
| 03:19:00 | Microsoft Defender Alert #6: Multiverze malware prevented |
| 04:17:00 | Microsoft Defender Alert #7: Suspicious binary with malicious URL |
| 02:02:45 - 20:56:00 | 283 successful connection/session events from attacker IP |

---

## 7. Who, What, When, Where, Why, How

### 👤 WHO

**Compromised Entities:**
- **Primary Account:** root (UID 0 - superuser/administrator)
- **System:** MTS-Web (Production Linux Server)
- **Exposure:** High-value target with internet-facing SSH service

**Threat Actor Profile:**
- **Primary Attribution IP:** 209.226.177.189 (successful authentication source)
- **Reconnaissance IPs:** 45.78.217.122, 154.92.109.196
- **C2 Infrastructure:** 27.74.80.167
- **Sophistication Level:** Medium-High (automated tools + manual post-exploitation)
- **Intent:** Persistent access, malware deployment, potential data exfiltration

---

## 8. MITRE ATT&CK Techniques

### Mapped Tactics, Techniques, and Procedures (TTPs)

| MITRE Tactic | Technique ID | Technique Name | Evidence |
|--------------|--------------|----------------|----------|
| **Initial Access** | T1078 | Valid Accounts | Root account compromised |
| **Initial Access** | T1110.001 | Brute Force: Password Guessing | 12,683 failed SSH attempts |
| **Execution** | T1059.004 | Command and Scripting Interpreter: Unix Shell | Root shell access |
| **Persistence** | T1098 | Account Manipulation | 283 persistent connections |
| **Defense Evasion** | T1070 | Indicator Removal | Path deletion at 02:45 AM |
| **Defense Evasion** | T1562 | Impair Defenses | EICAR AV testing |
| **Command and Control** | T1071 | Application Layer Protocol | C2 to 27.74.80.167 |
| **Impact** | T1486 | Data Encrypted for Impact | Multiverze malware (potential ransomware) |

---

## 9. Impact Assessment

| Category | Details |
|----------|----------|
| **Affected System** | MTS-Web Linux Server (Domain Controller) |
| **Accounts Involved** | root (UID 0) - Full administrative privileges |
| **Scope** | Complete system compromise - No evidence of lateral movement yet |
| **Impact** | - Compromised host integrity<br>- Potential credential exposure<br>- Risk of domain-level compromise<br>- Malware deployment<br>- C2 establishment |
| **Current Status** | **CRITICAL** - System remains compromised with active attacker access |

---

## 10. Recommendations

### Immediate Actions (Priority 1 - Within 1 Hour)

1. **⚠️ ISOLATE THE SYSTEM**
   - Immediately disconnect MTS-Web from network
   - Block all inbound/outbound traffic at firewall
   - DO NOT power down (preserve volatile memory)

2. **Block Threat Actor IPs**
   - 209.226.177.189 (primary attacker)
   - 45.78.217.122, 154.92.109.196 (reconnaissance)
   - 27.74.80.167 (C2 server)

3. **Rotate Credentials**
   - Reset root password immediately
   - Rotate all service account passwords
   - Invalidate all active SSH sessions

### Short-Term Actions (Priority 2 - Within 24 Hours)

4. **System Hardening**
   - Disable direct root SSH login
   - Implement SSH key-based authentication
   - Install Fail2Ban or similar brute-force protection
   - Restrict SSH access via VPN only
   - Implement MFA for all administrative access

5. **Network Segmentation**
   - Isolate production servers from direct internet exposure
   - Implement jump boxes/bastion hosts
   - Deploy IDS/IPS for SSH traffic monitoring

### Long-Term Actions (Priority 3 - Within 1 Week)

6. **Forensic Analysis**
   - Capture memory dump before shutdown
   - Perform full disk imaging
   - Analyze all logs for additional compromise indicators
   - Review all file modifications since 02:00:15 GMT

7. **System Rebuild**
   - Rebuild MTS-Web from clean, trusted image
   - Apply all security patches
   - Restore data from pre-compromise backups
   - Verify integrity before bringing online

---

## 11. Lessons Learned

### Security Gaps Identified

1. **Weak Password Policy** - Root account used weak password vulnerable to brute force
2. **No Brute Force Protection** - System allowed 12,683 attempts without blocking
3. **Direct Root SSH Access** - Root login should be disabled over SSH
4. **No MFA** - Multi-factor authentication not implemented
5. **Internet-Facing SSH** - Production server directly exposed to internet
6. **Inadequate Monitoring** - 283 connections over 18 hours without detection

---

## 12. Conclusion

This incident represents a **complete system compromise** of a critical production server. The threat actor successfully exploited fundamental security weaknesses (weak passwords, no brute force protection, direct root SSH access) to gain unrestricted access.

The attacker demonstrated **sophisticated post-exploitation capabilities**, including:
- Malware deployment
- C2 establishment  
- Defense evasion techniques
- Persistent access over 18+ hours

**Immediate containment and remediation actions are critical** to prevent further damage, lateral movement, or data exfiltration.

---

**Report Status:** ACTIVE INCIDENT - ONGOING INVESTIGATION  
**Next Update:** After containment actions completed  
**Analyst:** Abe O | Security Operations Center
