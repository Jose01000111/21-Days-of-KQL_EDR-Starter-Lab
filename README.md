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

## 🟢 Task A: Recent Process Execution Activity

## 🟢 Task B: Key Process Fields Visibility

### 📝 Notes
> • Endpoint Telemetry: Data from processes, files, network, logons  
> • Process Execution: Programs running on a system  
> • Threat hunting starts with understanding raw data

---

### 📅 Day 2 – Time-Based Scoping
**Goal:** Practice narrowing investigations to relevant time windows to reduce noise.  
**Tech Stack:**  
> ⏱️ EDR: `DeviceProcessEvents | where Timestamp > ago(24h)`  
> 🔍 KQL: `DeviceProcessEvents | where Timestamp > ago(1h)`
> 
## ⏰ Task A: Process Activity (Last 24 Hours)

## ⏰ Task B: Process Activity (Last 1 Hour)

### 📝 Notes
> • Time Scoping: Focus on a defined period  
> • Telemetry Noise: Benign events obscure threats  
> • Most investigations start with “when” something happened

---

### 📅 Day 3 – Baseline: What Runs Normally
**Goal:** Identify common processes to establish a normal execution baseline.  
**Tech Stack:**  
> 📊 EDR: `DeviceProcessEvents | summarize Count=count() by FileName | order by Count desc`  
> 🔍 KQL: `DeviceProcessEvents | summarize Count=count() by DeviceName`

## 📊 Task A: Most Frequently Executed Processes

## 📊 Task B: Process Activity Volume per Device

### 📝 Notes
> • Baseline: Picture of normal behavior  
> • Frequency Analysis: How often events occur  
> • Cannot label activity suspicious without knowing normal

---

### 📅 Day 4 – Suspicious Process Awareness
**Goal:** Begin identifying high-risk processes commonly abused by attackers.  
**Tech Stack:**  
> ⚠️ EDR: `DeviceProcessEvents | where FileName == "powershell.exe"`  
> 🔍 KQL: `DeviceProcessEvents | where FileName == "cmd.exe"`  

## ⚡ Task A: PowerShell Execution Activity

## ⚡ Task B: Command Prompt Execution Activity

### 📝 Notes
> • Scripting Engines: PowerShell, CMD  
> • Dual-Use Tools: Legitimate software abused by attackers  
> • Modern attackers rely on built-in utilities

---

### 📅 Day 5 – Execution Context Matters
**Goal:** Understand how command lines, parents, and users provide investigation context.  
**Tech Stack:**  
> 🧩 EDR: `DeviceProcessEvents | project Timestamp, DeviceName, FileName, ProcessCommandLine`  
> 🔍 KQL: `DeviceProcessEvents | project FileName, ParentProcessName, AccountName`  

## 🖥️ Task A: Process Command-Line Context

## 🖥️ Task B: Parent Process and User Context

### 📝 Notes
> • Command Line: Arguments used to start a process  
> • Parent Process: Reveals process lineage  
> • Context often reveals malicious intent

---

### 📅 Day 6 – Sorting for Signal
**Goal:** Learn to prioritize events by time when triaging activity.  
**Tech Stack:**  
> ⏳ EDR: `DeviceProcessEvents | order by Timestamp desc`  
> 🔍 KQL: `DeviceProcessEvents | order by Timestamp asc`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Triage: Prioritize relevant events  
> • Recency: Newer events often matter most  
> • SOC analysts rarely read logs sequentially

---

### 📅 Day 7 – Clean Host Baseline
**Goal:** Establish a known-good system baseline for comparison against noisy environments.  
**Tech Stack:**  
> 🧹 EDR: `DeviceProcessEvents | where DeviceName == "WIN10-CLEAN" | summarize Count=count() by FileName | order by Count desc`  
> 🔍 KQL: `DeviceProcessEvents | where DeviceName == "WIN10-CLEAN" | project FileName, ProcessCommandLine`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
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
> ⚡ EDR: `DeviceProcessEvents | where ProcessCommandLine contains "http"`  
> 🔍 KQL: `DeviceProcessEvents | where ProcessCommandLine contains "-enc"`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Threat Indicator: Patterns associated with malicious behavior  
> • Obfuscation: Hiding intent to evade detection  
> • Command lines often expose attacker intent

---

### 📅 Day 9 – Keyword-Based Hunting
**Goal:** Detect high-risk PowerShell behaviors using keyword logic.  
**Tech Stack:**  
> ⚡ EDR: `DeviceProcessEvents | where ProcessCommandLine has "Invoke-"`  
> 🔍 KQL: `DeviceProcessEvents | where ProcessCommandLine has "FromBase64String"`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Keyword Matching: Strings linked to attacks  
> • PowerShell attack frameworks reuse verbs  
> • Keyword hunting is a core SOC detection technique

---

### 📅 Day 10 – Script & Payload Detection
**Goal:** Identify script-based execution used in initial access and persistence.  
**Tech Stack:**  
> ⚡ EDR: `DeviceProcessEvents | where ProcessCommandLine endswith ".ps1"`  
> 🔍 KQL: `DeviceProcessEvents | where ProcessCommandLine endswith ".bat"`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Script Execution: Interpreted code  
> • Payloads: Malicious code delivered to systems  
> • Script-based attacks dominate initial access

---

### 📅 Day 11 – Parent / Child Abuse
**Goal:** Detect malicious execution chains such as Office spawning scripts.  
**Tech Stack:**  
> ⚡ EDR: `DeviceProcessEvents | where ParentProcessName in~ ("winword.exe","excel.exe","outlook.exe") | where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")`  
> 🔍 KQL: `DeviceProcessEvents | where FileName == "powershell.exe" and ProcessCommandLine contains "-enc"`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Process Chains: Sequence of spawned processes  
> • Office apps shouldn’t spawn shells  
> • Office-to-script execution is a high-signal alert

---

### 📅 Day 12 – Living-off-the-Land Binaries (LOLBins)
**Goal:** Detect legitimate binaries commonly abused for malicious activity.  
**Tech Stack:**  
> ⚡ EDR: `DeviceProcessEvents | where FileName in ("powershell.exe","mshta.exe","rundll32.exe","regsvr32.exe")`  
> 🔍 KQL: `DeviceProcessEvents | where FileName in ("wscript.exe","cscript.exe")`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • LOLBins: Trusted binaries abused by attackers  
> • Detection is harder since they are signed  
> • Attackers prefer trusted tools over malware

---

### 📅 Day 13 – Rare Process Hunting
**Goal:** Identify low-frequency processes that may indicate compromise.  
**Tech Stack:**  
> ⚡ EDR: `DeviceProcessEvents | summarize Hosts=dcount(DeviceName), Events=count() by FileName | order by Hosts asc, Events asc`  
> 🔍 KQL: `DeviceProcessEvents | summarize count() by FileName | order by count_ asc`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Outliers: Rare activity deviating from baseline  
> • Rare processes may indicate custom malware  
> • Rarity is a strong hunting signal

---

### 📅 Day 14 – User Behavior Deviations
**Goal:** Identify unusual user behavior that deviates from normal activity.  
**Tech Stack:**  
> ⚡ EDR: `DeviceProcessEvents | summarize count() by AccountName`  
> 🔍 KQL: `DeviceProcessEvents | summarize count() by AccountName, FileName`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Behavioral Deviations: Inconsistent activity  
> • MDE links process execution to users  
> • Credential compromise often appears here first

---

# 🟠 WEEK 3 — CORRELATION & ANALYST THINKING
**Week Goal:** Correlate telemetry across tables and think like a real threat hunter.

---

### 📅 Day 15 – Network Telemetry Awareness
**Goal:** Understand outbound network visibility from endpoints.  
**Tech Stack:**  
> 🌐 EDR: `DeviceNetworkEvents | take 30`  
> 🔍 KQL: `DeviceNetworkEvents | project Timestamp, DeviceName, RemoteIP, RemotePort`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Egress Traffic: Outbound device traffic  
> • Malware must communicate externally  
> • Network telemetry validates endpoint activity

---

### 📅 Day 16 – Suspicious Egress Traffic
**Goal:** Identify potentially malicious outbound connections.  
**Tech Stack:**  
> 🌐 EDR: `DeviceNetworkEvents | where RemoteIPType == "Public"`  
> 🔍 KQL: `DeviceNetworkEvents | summarize count() by RemotePort`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Beaconing: Periodic outbound calls  
> • Public IPs provide stronger signals  
> • Network activity supports threat confirmation

---

### 📅 Day 17 – File Drop Detection
**Goal:** Detect payload staging and post-execution artifacts.  
**Tech Stack:**  
> 💾 EDR: `DeviceFileEvents | where ActionType == "FileCreated" | where FolderPath has_any (@"\AppData", @"\Temp", @"\Users\Public", @"\ProgramData")`  
> 🔍 KQL: `DeviceFileEvents | summarize count() by FolderPath`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Payload Drop: Malicious files written to disk  
> • Common directories: AppData, Temp  
> • Disk artifacts enable deeper forensics

---

### 📅 Day 18 – Authentication Sanity Checks
**Goal:** Identify suspicious or unexpected logon behavior.  
**Tech Stack:**  
> 🔐 EDR: `DeviceLogonEvents | summarize count() by DeviceName, AccountName, LogonType`  
> 🔍 KQL: `DeviceLogonEvents | where ActionType == "LogonFailed"`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Logon Type: How users authenticate  
> • Credential Abuse: Unauthorized use  
> • Identity is the new perimeter

---

### 📅 Day 19 – Time-Based Behavior Patterns
**Goal:** Detect abnormal bursts of activity.  
**Tech Stack:**  
> ⏱️ EDR: `DeviceProcessEvents | summarize count() by bin(Timestamp, 30m)`  
> 🔍 KQL: `DeviceNetworkEvents | summarize count() by bin(Timestamp, 1h)`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Burst Activity: Sudden spike in events  
> • Automated tools produce consistent patterns  
> • Humans are inconsistent; malware is predictable

---

### 📅 Day 20 – Cross-Table Correlation
**Goal:** Connect process execution with network activity to confirm malicious behavior.  
**Tech Stack:**  
> 🔗 EDR: `Correlate suspicious PowerShell with outbound traffic`  
> 🔍 KQL: `Analyze process-to-network relationships using time proximity`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Correlation: Link events across tables  
> • Single events lie; correlated evidence doesn’t  
> • Cross-table analysis confirms threats

---

### 📅 Day 21 – Analyst Confidence Day
**Goal:** Apply baseline knowledge, deviation detection, and correlation skills independently.  
**Tech Stack:**  
> 🕵️ EDR: `Run one baseline-driven hunt and interpret findings`  
> 🔍 KQL: `Optimize and explain one correlation-based query`  

**Screenshot:**  


![Temp Screenshot](#)  


### 📝 Notes
> • Threat Hunt: Search for adversary activity proactively  
> • Hypothesis-Driven Hunting: Start with suspicion  
> • Think like a real SOC analyst

---

