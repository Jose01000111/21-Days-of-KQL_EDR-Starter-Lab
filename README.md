<h1 align="center">📅 21-Days of KQL/MS Defender Starter Lab – ☁️ Cyber Range</h1>


<p align="center">
  <img src="https://github.com/user-attachments/assets/235880af-458a-484e-b10e-800d06cc5695" alt="dO3hmFI" width="429" height="398" />
</p>


> ## I am practicing this 21-day KQL Starter+ lab inside Josh Madakor’s Cyber Range 🖥️, working hands-on with EDR telemetry from an internet-exposed Windows VM. The focus is on building practical KQL hunting skills 🔍 using Microsoft Sentinel 🛡️ and Microsoft Defender for Endpoint 💻 to investigate activity, detect threats, and understand real-world security workflows in a controlled lab environment.

## [👉📝Daily Lab Notes](https://github.com/Jose01000111/21-Days-of-KQL_EDR-Starter-Lab/blob/main/21-Days-of-KQL_Notes.pdf)

## [👉📝Daily Lab Instructions](https://github.com/Jose01000111/21-Days-of-KQL_EDR-Starter-Lab/blob/main/KQL_EDR_21_Day_Lab.pdf)

---

# 🟢 WEEK 1 — BASELINES & CORE KQL
**Week Goal:** Learn Defender tables and establish what “normal” looks like before hunting threats.

---

### 📅 Day 1 – Process Telemetry Familiarization
**Goal:** Learn what raw endpoint process telemetry looks like and how analysts start investigations.  
**Tech Stack:**  
> 💻 EDR: `DeviceProcessEvents | take 30`  
> 🔍 KQL: `DeviceProcessEvents | project Timestamp, DeviceName, FileName | take 30`

**Screenshot:** ![Temp Screenshot](#)  

**Notes:**  
> • Endpoint Telemetry: Data collected from processes, files, network, logons  
> • Process Execution: Programs running on a system  
> • Threat hunting starts with understanding raw data

---

### 📅 Day 2 – Time-Based Scoping
**Goal:** Practice narrowing investigations to relevant time windows to reduce noise.  
**Tech Stack:**  
> ⏱️ EDR: `DeviceProcessEvents | where Timestamp > ago(24h)`  
> 🔍 KQL: `DeviceProcessEvents | where Timestamp > ago(1h)`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Time Scoping: Focus on a defined period to reduce noise  
> • Telemetry Noise: Benign events can obscure threats  
> • Most investigations start with “when” something happened

---

### 📅 Day 3 – Baseline: What Runs Normally
**Goal:** Identify common processes to establish a normal execution baseline.  
**Tech Stack:**  
> 📊 EDR: `DeviceProcessEvents | summarize Count=count() by FileName | order by Count desc`  
> 🔍 KQL: `DeviceProcessEvents | summarize Count=count() by DeviceName`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Baseline: Picture of normal behavior in the environment  
> • Frequency Analysis: How often events occur  
> • Cannot label activity suspicious without knowing normal

---

### 📅 Day 4 – Suspicious Process Awareness
**Goal:** Begin identifying high-risk processes commonly abused by attackers.  
**Tech Stack:**  
> ⚠️ EDR: `DeviceProcessEvents | where FileName == "powershell.exe"`  
> 🔍 KQL: `DeviceProcessEvents | where FileName == "cmd.exe"`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Scripting Engines: PowerShell, CMD, etc.  
> • Dual-Use Tools: Legitimate tools abused by attackers  
> • Modern attackers rely on built-in utilities

---

### 📅 Day 5 – Execution Context Matters
**Goal:** Understand how command lines, parents, and users provide investigation context.  
**Tech Stack:**  
> 🧩 EDR: `DeviceProcessEvents | project Timestamp, DeviceName, FileName, ProcessCommandLine`  
> 🔍 KQL: `DeviceProcessEvents | project FileName, ParentProcessName, AccountName`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Command Line: Full arguments used to start a process  
> • Parent Process: Reveals how a process was launched  
> • Context often reveals malicious intent

---

### 📅 Day 6 – Sorting for Signal
**Goal:** Learn to prioritize events by time when triaging activity.  
**Tech Stack:**  
> ⏳ EDR: `DeviceProcessEvents | order by Timestamp desc`  
> 🔍 KQL: `DeviceProcessEvents | order by Timestamp asc`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Triage: Prioritize relevant events  
> • Recency: Newer events often matter most  
> • SOC analysts rarely read logs sequentially

---

### 📅 Day 7 – Clean Host Baseline
**Goal:** Establish a known-good system baseline for comparison against noisy environments.  
**Tech Stack:**  
> 🧹 EDR: `DeviceProcessEvents | where DeviceName == "WIN10-CLEAN" | summarize Count=count() by FileName | order by Count desc`  
> 🔍 KQL: `DeviceProcessEvents | where DeviceName == "WIN10-CLEAN" | project FileName, ProcessCommandLine`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Known-Good Host: Clean control system  
> • Comparative Analysis: Compare systems to detect anomalies  
> • Reduces false positives in noisy environments

---

# 🟡 WEEK 2 — DEVIATIONS & ATTACKER TRADECRAFT
**Week Goal:** Detect deviations from baseline and recognize common attacker behaviors.

---

### 📅 Day 8 – Command-Line Threat Indicators
**Goal:** Identify suspicious command-line patterns used by attackers.  
**Tech Stack:**  
> ⚠️ EDR: `DeviceProcessEvents | where ProcessCommandLine contains "http"`  
> 🔍 KQL: `DeviceProcessEvents | where ProcessCommandLine contains "-enc"`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Threat Indicators: Patterns associated with malicious activity  
> • Obfuscation: Hides attacker intent  
> • Command lines often reveal intent directly

---

### 📅 Day 9 – Keyword-Based Hunting
**Goal:** Detect high-risk PowerShell behaviors using keyword logic.  
**Tech Stack:**  
> 📝 EDR: `DeviceProcessEvents | where ProcessCommandLine has "Invoke-"`  
> 🔍 KQL: `DeviceProcessEvents | where ProcessCommandLine has "FromBase64String"`  
**Screenshot:** ![Temp Screenshot](#)  
**Notes:**  
> • Keyword Matching: Detect known attack functions  
> • PowerShell frameworks reuse verbs and functions  
> • Foundational SOC detection technique

---

### 📅 Day 10 – Script & Payload Detection
**Goal:** Identify script-based execution used in initial access and persistence.  
**Tech Stack:**  
> ⚡ EDR: `DeviceProcessEvents | where
