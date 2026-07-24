# 🛡️ Security Projects & Investigations

This directory serves as a centralized log of my hands-on cybersecurity investigations, simulated incident response scenarios, and laboratory exercises. 

These technical write-ups document practical workflows and applied methodologies conducted within isolated virtual environments, demonstrating my ability to analyze, triage, and respond to various security threats.

### 🔬 Core Methodologies Demonstrated
* **SIEM Log Analysis & Threat Hunting:** Correlating endpoint telemetry and network traffic to identify persistence mechanisms and Command & Control (C2) activity.
* **Email Forensics & Phishing Analysis:** Extracting and analyzing disguised malicious payloads from spoofed emails to trace threat actor origins.
* **Malware Triage:** Safely handling and analyzing payloads within hypervisors (VMware/Hyper-V) to extract Indicators of Compromise (IOCs).
* **Incident Response:** Formulating actionable mitigation strategies, perimeter blocking recommendations, and host isolation procedures.

---

### 📂 Project Directory

Click on any of the project titles below to view the full investigation report, methodology, and technical findings.

| Project Name | Focus Area | Description |
| :--- | :--- | :--- |
| **[Phishing Investigation: The Planet's Prestige](./Phishing-Investigation-The-Planet...)** | `Email Forensics` / `Malware Triage` | Extracted and analyzed a disguised malicious payload from a spoofed email, utilizing Metadata++ and file signature analysis to identify the threat actor and C&C infrastructure. |
| **[Splunk SIEM Investigation: Endpoint Compromise](./Splunk-SIEM-Investigation-Endpoint...)** | `SIEM` / `Log Analysis` | Investigated a multi-stage endpoint compromise using Splunk and Sysmon telemetry. Correlated payload delivery, scheduled task persistence, and outbound C2 traffic into an actionable IR report. |

*(Note: More write-ups and home lab documentation are actively being added as I continue to expand my SOC training.)*
