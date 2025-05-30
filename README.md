# Brute-Force-Detection-with-Microsoft-Sentinel

🎯 Lab Overview
This project demonstrates how I used Microsoft Sentinel to detect brute force login attempts and investigate the activity using logs, KQL, and MITRE ATT&CK integration.

⚙️ Tools Used
Microsoft Sentinel

KQL (Kusto Query Language)

Windows Event Logs (Event ID 4625)

MITRE ATT&CK (built-in Sentinel feature)

AbuseIPDB (for IP reputation check)

🔍 What I Did
Set up a honeypot-style virtual machine in Azure

Simulated failed RDP login attempts

Monitored log data using Sentinel’s built-in connector

Created a custom KQL query to detect repeated failed logins

Built an analytics rule to trigger an incident

Used MITRE ATT&CK mapping in Sentinel to categorize the alert

Mapped activity to T1110 – Brute Force under the Initial Access tactic

📌 MITRE ATT&CK Mapping
Tactic: Initial Access

Technique: T1110 – Brute Force

Sentinel automatically highlighted this in the MITRE ATT&CK panel, helping visualize the stage of attack

This allowed me to investigate and classify the incident more effectively using a known threat model

📊 Sample KQL Query
kql
Copy
Edit
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress, Account, bin(TimeGenerated, 1h)
| sort by Attempts desc
🛡️ Simulated Response
Identified source IP and researched via AbuseIPDB

Would recommend blocking the IP and resetting targeted account credentials

Documented all findings and saved the incident for lessons learned

📸 Screenshots
