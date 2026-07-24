# 📧 Phishing Investigation: The Planet's Prestige (CoCanDa)

### 🛠️ Tools & Environment Used
![Notepad++](https://img.shields.io/badge/Notepad++-90E59A?style=for-the-badge&logo=notepadplusplus&logoColor=black)
![Microsoft Excel](https://img.shields.io/badge/Microsoft_Excel-217346?style=for-the-badge&logo=microsoftexcel&logoColor=white)
![Metadata++](https://img.shields.io/badge/Metadata++-005571?style=for-the-badge)
![CyberChef](https://img.shields.io/badge/CyberChef-800000?style=for-the-badge)
![File Signatures](https://img.shields.io/badge/Gary_Kessler_File_Sigs-000000?style=for-the-badge)
![Hyper-V](https://img.shields.io/badge/Hyper--V-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![VMware](https://img.shields.io/badge/VMware-60B932?style=for-the-badge&logo=vmware&logoColor=white)

---

## 📊 Findings

* **Time of Activity:** 2026-06-18 16:00:44 EDT
* **Source IP:** `93.99.104.210`
* **Domains Involved:** `@microapple.com` (Spoofed), `@pashter.com` (Reply-To/C&C)
* **Email Service Used:** Emkei.cz
* **Reply-To Address:** `negeja3921@pashter.com`
* **Malicious Attachment:** Disguised as a PDF, but identified via file signature analysis as a `.zip` archive
* **SHA256 Hash (EML File):** `324bce4c780335b24d7ade48b3a6c734589576f18aa902e433ff398975e27cdc`
* **Threat Actor Name:** Pestero Negeja *(Extracted via Metadata++)*
* **Attacker Location:** The Martian Colony, Beside Interplanetary Spaceport *(Extracted via hidden text in .xlsx payload)*
* **Probable C&C Domain:** `pashter.com`

---

## 📝 Investigation Summary

*Note: Conducted as part of the BTLO challenges"The Planet's Prestige"*

Analysis of a suspicious email file (`A Hope to CoCanDa.eml`) safely isolated within a VMware machine revealed the use of the `Emkei.cz` spoofing service to impersonate `billjobs@microapple.com`. Manual header analysis confirmed an SPF validation failure from source IP `93.99.104.210`.

The attacker disguised a `.zip` archive as a PDF attachment, which was verified using the Gary Kessler File Signature database. Extracting the archive revealed an `.xlsx` spreadsheet alongside decoy files. Utilizing **Metadata++**, the threat actor's name ("Pestero Negeja") was successfully extracted. 

<img width="500" height="251" alt="image" src="https://github.com/user-attachments/assets/b143f286-d056-434e-8448-1adbb5bb2cac" />


Further analysis of the spreadsheet revealed the information hidden in Sheet 3 using white text (The Martian Colony, Beside Interplanetary Spaceport). Header analysis identified the true Reply-To address as `negeja3921@pashter.com`, pointing to `pashter.com` as the probable Command and Control (C&C) domain intended to manage autonomous bots upon successful payload execution.

## 

* **WHO:** Threat actor identified via file metadata as Pestero Negeja.
* **WHAT:** Attempted delivery of a malicious `.zip` attachment (disguised as a PDF) via a spoofed phishing email originating from `Emkei.cz`.
* **WHEN:** 16:00:44 EDT 
* **WHERE:** The phishing attempt was delivered to the inbox of a CoCanDa representative (Army Major) stationed on Earth.
* **WHY:** The email was sent to threaten the recipient and demand a ransom, using social engineering to bait them into opening the payload and establishing a foothold.
* **HOW:** The attacker utilized an open email spoofing service (`Emkei.cz`) to bypass initial sender verification. They disguised a `.zip` archive as a PDF and manipulated the `Reply-To` address to ensure any responses or autonomous bot callbacks were redirected to their C&C infrastructure (`pashter.com`). Additionally, they utilized basic steganography (white text on a white background) to hide configuration data within an `.xlsx` file.

---

## 🛡️ Recommendations

1. **Perimeter Blocking:** Immediately block the Source IP (`93.99.104.210`), the probable C&C domain (`pashter.com`), and the Reply-To address (`negeja3921@pashter.com`) across the Secure Email Gateway (SEG) and network firewalls.
2. **SIEM Query:** Run a historical query in the SIEM and email logs searching for the provided SHA256 hash (`324bce4c780335b24d7ade48b3a6c734589576f18aa902e433ff398975e27cdc`), Source IP, or the `pashter.com` domain to identify if any other hosts in the environment received this payload.
3. **Authentication Review:** Ensure strict enforcement of SPF, DKIM, and DMARC policies to automatically quarantine or reject emails failing validation checks (such as the spoofed `microapple.com` domain observed here).
4. **Host Isolation:** If telemetry indicates any user successfully downloaded and extracted the `.zip` file, immediately isolate the affected host from the network. Consider a full forensic investigation to determine the blast radius, or perform a complete machine wipe to ensure the removal of any persistent artifacts.
