# Dynamic Malware Analysis: IcedID DLL Loader (`dll.malware`)

**Analyst:** Opeyemi Balogun  
**Date:** November 23, 2026  
**Sample:** `dll.malware` (720,896 bytes)  
**Family:** IcedID (BokBot) Loader  

---

## Overview

For this lab, I analyzed a suspicious Windows dynamic link library (`dll.malware`) inside an isolated sandbox environment to see how it behaves once executed. Because a DLL cannot run on its own like a standard `.exe` program, I launched it using the native Windows utility `rundll32.exe` along with its exported entry point, `LUAYKIYBPAX`.

As soon as it ran, the sample operated completely in memory without writing any new files to the hard drive. Its main job was to profile the infected machine—grabbing the computer name, active user, and Windows version—and send regular check-in beacons over HTTP to three rotating external domains to establish Command and Control (C2) communication.

---

## Lab Environment & Setup

To keep my host machine and home network completely safe from accidental exposure, I ran the sample inside an air-gapped two-VM lab connected over an isolated VMware LAN segment (`malware analysis`):

* **Victim Machine (FlareVM – `192.168.58.200`):** Monitored with Process Monitor, Process Explorer, AutoRuns, Regshot, and Wireshark. Before running the sample, I disabled VMware Guest Isolation (clipboard sharing and drag-and-drop) so nothing could cross over to my host.
* **Analysis & Network Hub (REMnux – `192.168.58.250`):** Configured with INetSim to simulate live internet services and Burp Suite (`*:443`) to intercept and log all outbound web traffic from FlareVM.

After taking clean baseline snapshots of both virtual machines and recording a pre-execution registry snapshot with Regshot, I triggered the sample via Command Prompt:

```cmd
rundll32.exe dll.malware,LUAYKIYBPAX
```

---

## What Happened During Execution

### 1. Rotating C2 Beaconing
Within seconds of execution, Wireshark captured 15 outbound `HTTP POST` requests leaving FlareVM toward the simulated proxy on REMnux. Instead of relying on a single server, the malware cycled systematically across three different domains while hitting the exact same `/8/forum.php` path on each one:

* `hxxp://thowerteigime[.]com/8/forum.php`
* `hxxp://euvereginumet[.]ru/8/forum.php`
* `hxxp://rhopulforupse[.]ru/8/forum.php`

To blend in with normal web traffic from an older Windows workstation, every request used a hardcoded legacy Internet Explorer 11 User-Agent string:

```text
Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
```

### 2. Host Profiling & Data Exfiltration
Looking closely at the intercepted `POST /8/forum.php` requests inside Burp Suite's HTTP history showed that the malware was sending system reconnaissance details inside the body of every check-in beacon:

```text
&UID=4081551E1E7300A8&CS=0&BUILD=1001_x64&OBJ=0&PC=DESKTOP-BGUJ060\mydfir&IP=0.0.0.0&TYPE=1&WIN=10.0(x64)
```

Breaking down those parameters gives a clear picture of what the loader reports back to its operators:

* **`UID` (`4081551E1E7300A8`):** A unique bot ID generated to track this specific infected machine.
* **`BUILD` (`1001_x64`):** The campaign and 64-bit architecture tag for this loader build.
* **`PC` (`DESKTOP-BGUJ060\mydfir`):** The compromised machine's hostname and currently logged-in user account.
* **`WIN` (`10.0(x64)`):** The operating system version and architecture.

In a live attack, the C2 server uses this fingerprint to decide which second-stage payload—such as a credential stealer, banking module, or ransomware—to send down next.

### 3. System & Registry Changes
Comparing the before-and-after Regshot snapshots confirmed that the loader stayed entirely memory-resident during its initial check-in phase. Regshot recorded zero files or folders created on disk and 40 minor registry modifications (`1` key added, `1` key deleted, `2` values added, and `36` values modified), all tied to routine Windows networking and proxy activity rather than noisy file drops.

---

## Indicators of Compromise (IOCs)

| Indicator Type | Value | Notes |
| :--- | :--- | :--- |
| **Sample File** | `dll.malware` (720,896 bytes) | IcedID DLL loader binary |
| **Export Function** | `LUAYKIYBPAX` | DLL entry point invoked via `rundll32.exe` |
| **C2 Endpoint 1** | `hxxp://thowerteigime[.]com/8/forum.php` | Primary C2 check-in URL (`HTTP POST`) |
| **C2 Endpoint 2** | `hxxp://euvereginumet[.]ru/8/forum.php` | Secondary rotating C2 URL (`HTTP POST`) |
| **C2 Endpoint 3** | `hxxp://rhopulforupse[.]ru/8/forum.php` | Tertiary rotating C2 URL (`HTTP POST`) |
| **User-Agent** | `Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko` | Hardcoded IE 11 header used for C2 traffic |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | How It Was Observed |
| :--- | :--- | :--- |
| **Defense Evasion** | `T1218.011` – System Binary Proxy Execution: Rundll32 | Executed the malicious DLL using built-in `rundll32.exe` and the custom export `LUAYKIYBPAX`. |
| **Discovery** | `T1082` – System Information Discovery | Collected the victim's computer name, username, OS version, and architecture. |
| **Command & Control** | `T1071.001` – Application Layer Protocol: Web Protocols | Sent host reconnaissance data out via `HTTP POST` requests. |
| **Command & Control** | `T1568` – Dynamic Resolution / C2 Rotation | Cycled check-in beacons across three separate `.com` and `.ru` domains. |

---

## Detection & Takeaways

### YARA Rule
```yara
rule IcedID_DLL_Loader_DynamicLab {
    meta:
        description = "Detects dll.malware IcedID loader via export name, C2 URI, and User-Agent"
        author = "Opeyemi Balogun"
        date = "2026-11-23"
    strings:
        $mz = { 4D 5A }
        $export = "LUAYKIYBPAX" nocase
        $uri = "/8/forum.php" ascii wide
        $ua = "Trident/7.0; rv:11.0" ascii wide
    condition:
        $mz at 0 and ($export or ($uri and $ua))
}
```

### Key Takeaways for Defenders
This sample is a great example of how attackers abuse trusted Windows binaries like `rundll32.exe` to run memory-resident loaders that avoid noisy disk writes. To catch this behavior in a real environment:

* **Watch `rundll32.exe` Execution:** Alert whenever `rundll32.exe` loads a DLL from user-writable folders (`Desktop`, `Downloads`, `Temp`, or `AppData`) or calls unusual, randomized export names.
* **Inspect Outbound HTTP Traffic:** Flag unencrypted `HTTP POST` requests carrying system hostnames (`PC=`) or OS strings (`WIN=`) in the body, and block newly registered or uncategorized `.ru` and `.com` domains at the web proxy.