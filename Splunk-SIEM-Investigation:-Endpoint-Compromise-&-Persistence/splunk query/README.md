# 🔍 Splunk SPL Query Breakdown & Telemetry Analysis

![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Telemetry](https://img.shields.io/badge/Focus-Process_%26_Network_Analysis-orange?style=for-the-badge)

This document details the three core Search Processing Language (SPL) queries used during the investigation of endpoint `FRONTDESK-PC1` to analyze process execution, reconstruct the attack chain, and isolate network C2 traffic.

---

### 1. Process Activity Summary Query

```spl
index="lee-soc" host="FRONTDESK-PC1" sourcetype="*sysmon*" EventCode=1 | stats count by _time, Image, CommandLine
```
### 2. Parent-Child Process Reconstruction Query
```spl
index="lee-soc" host="FRONTDESK-PC1" sourcetype="*sysmon*" EventCode=1 | sort _time | table _time, Image, ParentImage, CommandLine
```
### 3. Network Connection & C2 Traffic Isolation Query
```spl
index="lee-soc" host="FRONTDESK-PC1" sourcetype="*sysmon*" EventCode=3 Image="*python.exe"
```
