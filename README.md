<h1 align="center">📅 28-Days of KQL Mastery Lab – Azure ☁️ Cyber Range</h1>


<p align="center">
  <img src="https://github.com/user-attachments/assets/235880af-458a-484e-b10e-800d06cc5695" alt="dO3hmFI" width="429" height="398" />
</p>


## I am practicing this 28-day KQL lab inside **Josh Madakor’s Azure Cyber Range** 🖥️, focusing on hands-on security monitoring and log analysis. My goal is to master **Kusto Query Language (KQL)** 🔍 for threat detection, anomaly investigation, and incident analysis. I am using **Microsoft Sentinel** 🛡️ for SIEM operations and **Microsoft Defender for Endpoint** 💻 to collect and analyze endpoint telemetry, simulating real-world cybersecurity workflows in a controlled environment.  

## Week 1 – Understanding Tables & Basic Queries 📊

| Day | Description |
|-----|-------------|
| [Day 1 – KQL and Workspace Introduction 📝]() | Review the tables in your environment (SecurityEvent, Heartbeat, Syslog, AzureActivity). Examine column types and log formats. Take random samples to familiarize yourself with log structures. |
| [Day 2 – Column Selection 📑](#) | Concentrate on fields like time, user, IP address, and event ID. Compare results when selecting all columns versus only necessary ones. |
| [Day 3 – Basic Filtering 🔍](#) | Apply filters for single conditions (e.g., failed logins or service restarts). Observe patterns and identify the most active users or computers. |
| [Day 4 – Sorting & Limiting Results 📈](#) | Sort events by timestamp or severity to prioritize recent or critical activities. Limit output to grasp patterns without data overload. |
| [Day 5 – Counting & Summarizing Events 🧮](#) | Count specific events, such as failed logins per user or machine. Identify the most common event types in your system. |
| [Day 6 – Time-Based Filters ⏱️](#) | Filter logs by recent hour, day, week, or month. Compare activities across different time frames. |
| [Day 7 – Mini Challenge 🏆](#) | Combine filtering, selecting, and sorting to list the top 10 failed logins in the last 24 hours. Reflect on insights gained about your environment. |

## Week 2 – Aggregation & Trend Analysis 📊

| Day | Description |
|-----|-------------|
| [Day 8 – Grouping & Summarizing 🗂️](#) | Summarize events by user, device, or event category. Look for recurring failed logins or system errors. |
| [Day 9 – Aggregations ➕➖](#) | Calculate averages, minimums, and maximums for numeric fields (e.g., uptime, CPU usage). Spot outliers in performance or unusual activities. |
| [Day 10 – Multi-field Summarization 📋](#) | Summarize using multiple fields to detect trends, such as event counts by user and type. Identify top users or devices generating most events. |
| [Day 11 – Time Binning 🕒](#) | Break down events into hourly or daily segments. Visualize trends to identify activity peaks or suspicious timing. |
| [Day 12 – Top N Analysis 🏅](#) | Find top event sources, like devices with most errors or users with most failed logins. Compare with previous days to observe changes. |
| [Day 13 – Combining Filters & Summarization 🔗](#) | Create queries filtering by time and event type while summarizing results. Detect recurring problems or high-risk accounts. |
| [Day 14 – Mini Challenge 🏆](#) | Identify the top 3 users or IPs with failed logins in the last 48 hours. Note if failed logins cluster by time, location, or system. |

## Week 3 – Parsing, Strings, and Data Extraction 🧩

| Day | Description |
|-----|-------------|
| [Day 15 – Text Filtering 🔤](#) | Search for usernames, IPs, or process names using partial matches. Focus on administrative or service accounts generating events. |
| [Day 16 – Parsing Messages 🛠️](#) | Extract specific fields like usernames and IP addresses from raw log messages. Validate parsed data against structured columns. |
| [Day 17 – Pattern Matching 🔎](#) | Use regular expressions to detect log patterns such as failed SSH attempts or unusual process names. Identify repeated or suspicious activities across logs. |
| [Day 18 – Creating Calculated Fields 🧮](#) | Add new fields based on existing data, e.g., “FailedAttempts” or “Duration.” Analyze trends using these calculated metrics. |
| [Day 19 – Case Normalization & Text Cleanup ✨](#) | Standardize usernames and IPs for consistent formatting. Detect duplicates or inconsistencies. |
| [Day 20 – Multi-value Field Expansion 🔄](#) | Expand arrays or multi-value fields to display all values clearly. Identify all IPs or user accounts involved in single events. |
| [Day 21 – Mini Challenge 🏆](#) | Parse failed login messages, summarize top offenders, and document findings. Look for patterns related to time, location, or account type. |

## Week 4 – Joins, Lookups & Incident Simulation 🛡️

| Day | Description |
|-----|-------------|
| [Day 22 – Joining Tables 🔗](#) | Merge data from multiple tables, such as login events with Heartbeat or Syslog. Analyze which users or devices have the most correlated events. |
| [Day 23 – Enrichment & Lookups 🧩](#) | Add context like location, department, or IP reputation. Compare enriched data with raw events for clearer insights. |
| [Day 24 – Investigating Suspicious Activity 🚨](#) | Detect failed logins followed by successful ones in short intervals. Identify unusual login patterns like off-hours or multiple IP addresses. |
| [Day 25 – Detecting Anomalies ⚠️](#) | Count events per user or IP over time to spot spikes or deviations. Note unexpected trends for further review. |
| [Day 26 – Building Visualizations 📊](#) | Create charts or tables in Log Analytics to highlight trends and anomalies. Practice telling stories with data visuals. |
| [Day 27 – Combined Queries & Advanced Filtering 🛠️](#) | Develop queries that filter, project, summarize, and visualize in one process. Use multiple conditions to isolate significant security events. |
| [Day 28 – Mini Incident Simulation 🏁](#) | Conduct a small security investigation: identify top 3 source IPs with failed logins, determine affected users and systems, and document findings and workflow, simulating a real SOC report. |

