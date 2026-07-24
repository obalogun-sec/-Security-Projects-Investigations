# Splunk SIEM Investigation: Endpoint Compromise & Persistence

## Objective
The goal of this project was to utilize Splunk SIEM to investigate a simulated endpoint compromise. By analyzing raw Sysmon telemetry, the objective was to trace the attacker's execution chain from initial payload delivery to the establishment of SYSTEM-level persistence, and extract actionable Indicators of Compromise (IOCs).

## Scenario Overview
A user reported suspicious mouse movement on their workstation. Using Splunk, I correlated endpoint and network telemetry to uncover a multi-stage intrusion. 

**Key Findings:**
*   **Initial Access:** Payload downloaded via Google Chrome.
*   **Execution:** Manual execution of a masqueraded binary (`python.exe`).
*   **Command & Control (C2):** Outbound TCP beaconing to `157.245.46.190:8888`.
*   **Persistence:** Abuse of PowerShell and Task Scheduler to create a `SYSTEM` level startup task.

## Project Artifacts
*   📄 **[Full Incident Response Report (PDF)](./SOC_Investigation_Report.pdf)** - *Contains the complete timeline, 5Ws, and containment recommendations.*
*   💻 **[Raw SPL Queries](./spl_queries.txt)** - *The exact Splunk searches used to extract the telemetry.*
