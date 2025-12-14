# 🛡️ TryHackMe: SOC Level 1 Learning Path

![TryHackMe](https://img.shields.io/badge/TryHackMe-SOC%20Level%201-blue?style=for-the-badge\&logo=tryhackme)
![Status](https://img.shields.io/badge/Status-Started-green?style=for-the-badge)

*A structured learning journal documenting my progress, notes, labs, tools, and reflections throughout the entire TryHackMe SOC Level 1 defensive security track.*

---

## 📘 Overview

This repository contains my complete journey through the **TryHackMe SOC Level 1 Learning Path**.
It includes summaries, personal notes, concepts learned, tools used, and progress across all SOC-oriented modules.

The purpose of this README is to show progression from **zero experience** to becoming a job-ready **SOC Analyst (Tier 1)**.

---

## 🎯 Goals

* Build a strong foundation in **defensive security and SOC operations**
* Learn how real SOC analysts detect, triage, analyze, and respond to threats
* Gain hands-on experience with SIEM, EDR, threat intelligence, and log analysis
* Improve analytical thinking, alert triage workflow, and investigative skills
* Prepare for cyber security roles such as:

  * SOC Analyst – Tier 1
  * Cyber Security Analyst
  * Threat Intelligence Apprentice
  * Incident Response Intern

---

## 📊 Progress Tracker

| Module                          | Status         |
| ------------------------------- | -------------- |
| Blue Team Introduction          | 🟢 Completed   |
| SOC Team Internals              | 🟢 Completed   |
| Core SOC Solutions              | 🟡 In Progress |
| Cyber Defence Frameworks        | 🔴 Not Started |
| Phishing Analysis               | 🔴 Not Started |
| Network Traffic Analysis        | 🔴 Not Started |
| Network Security Monitoring     | 🔴 Not Started |
| Web Security Monitoring         | 🔴 Not Started |
| Windows Security Monitoring     | 🔴 Not Started |
| Linux Security Monitoring       | 🔴 Not Started |
| Malware Concepts for SOC        | 🔴 Not Started |
| Threat Analysis Tools           | 🔴 Not Started |
| SIEM Triage for SOC             | 🔴 Not Started |
| SOC Level 1 Capstone Challenges | 🔴 Not Started |

**Legend:** 🔴 Not Started | 🟡 In Progress | 🟢 Completed

---

# 📚 Learning Modules & Progress

Below are all modules in the SOC Level 1 path, each following the format:
**Status → Concepts Learned → Tools Used → Labs → Reflections**

---

## 1️⃣ Blue Team Introduction

**Status:** 🟢 Completed

### 🔍 Key Concepts

* What is the Blue Team?
* Role of defensive security in modern organizations
* Types of cyber attacks & prevention strategies
* Importance of SOC (Security Operations Center)
* Overview of monitoring, detection, and response
* Discussed Threat actors and Threat Vectors

### 🛠️ Tools used

* TryHackMe learning environment

### 🧪 Labs & Practical Activities

* Practical phishing examples and how to detect them and identify
* Practical implementation of what policies to use to mitigate attacks
* Finding solutions to attacks based on situational scenarios by defining the problem and what is the correct course of action
* Simple defensive tasks

### 📝 Notes / Reflections

* Just a quick introduction on SOC and begginer labs that have labs of situational scenarios and how to solve them, practical phishing, policies, solutions.

---

## 2️⃣ SOC Team Internals

**Status:** 🟢 Completed

### 🔍 Key Concepts

* Learned more about SOC alerts and build a systematic approach to efficiently triaging them. From investigating the ticket, to assigning its severity then closing the ticket after giving a verdict based on research on the details presented in the scenario.
* Objectively made my alert reporting better with the use of 5WS(Who, What, When, Where, Why). Had a good practical SOC Simulator Lab wherein I did the escalation process thoroughly from closing tickets to escalating some of them to tier 2 SOC. With this I learned Alert reporting, Escalation, and Communication. 
* Tackled workbooks and its importance to L1 SOC Analysts, through the help of the diagrams it was easily understable and it goes to show how efficiently a team works with a workbook in place. Also tackled network diagrams as this helps in the investigation of alerts. And finally assets and Identities, the list of all records partaining to either assets or identities(This records are of Role, Name, Access, etc..)
* Learned about the SOC Core Metrics (Alert Count, False Positive Rate, Alert Escalation Rate, Threat Detection Rate).
* Studied how SLA works and parts of it like MTTD, MTTA, MTTR. These metrics are really important for the SLA.
* Alert triage workflow
* Severity levels & classification
* Communication & escalation procedures

### 🛠️ Tools Used

* Ticketing systems (From TryHackMe)
* Basic SIEM dashboards (SPLUNK)

### 🧪 Labs

* Simulated alert triage through the TryHackMe SIEM Simulator
* Made Alert reporting(5Ws), Escalated alerts to L2, all through a SIEM Simulator
* Workbook practice(what steps to do in an investigation but will vary depending on the company)
* Simulated a SOC Managers POV on reports regarding SOC performance identifying the problems, looking at the things to improve, and act upon these information to improve the SOC team.
* Phishing Simulation using TryHackMe SOC Simulator, in this lab we I used SPLUNK as my SIEM as it was begginer friendly. I achieved a 100% TPR(True Positive Rate)
* <img width="1216" height="849" alt="image" src="https://github.com/user-attachments/assets/b2316051-dd4a-4fba-a7a5-a373b9e3caed" />


### 📝 Notes / Reflections

*Had a chance to work in a Simulated SOC Invironment, from learing triaging to closing alerts and then had a practical scenario to top it all of. The last lab was legit great for experience and exposure.

---

## 3️⃣ Core SOC Solutions

**Status:** 🟡 In Progress

### 🔍 Key Concepts

* **EDR** (Endpoint Detection and Response)
* Learned the main features of EDR which are Visibility, Detection, and Response. Throughtout this walktthrough each of these features are discussed extensively, Visibility feature lets the SOC Analyst have a detailed data overrview on the endpoint which includes process modifications, registry modifications, file and folder modifications, user actions, etc. aside from this there's also the process tree feature to make it easier to see process in which an action went through. The Detection feature clearly provides analyst with a severity score, host name, file name, etc... which are good information for threat hunting and solving cases, most importantly this feature includes Signature-based and Behaviour-based detection which makes EDR more potent as a solution. The response feature greatly indicates the ability to take action immedietly against detected threats, empowers analysts to take action.
* Tackled the types of telemetry and this information is the reason how an EDR asses a certain activity in an endpoint.
* Learnt the detection techniques that the EDR uses(Behavioural, Anomoly, IoC matching, Machine Learning, MITRE ATT&CK Mapping)
* After learning about detection this walkthrough proceeds in discussing response techniques and this included Isolate Host, Quarantine, Terminate process, Remote Access, and Artefacts Collection. All these techniques makes the EDR whole, a further than that techniques may differ per organization and technology advances.
* Understood how the SIEM works, from Centralization of logs to Normalizing logs and then the Correlation of logs this process is what makes SEIM a really good tool for SOC Analysts. 
* Differenciated Host-centric vs. Netwrok centric logs, how these logs are then analyzed by L1,L2,L3 analysts from a SIEM.
* Talked about log sources and ingestion, how and where the logs are ingested from endpoints to a SIEM solution. In this case the example shows Splunk as the SIEM for the manual upload of logs
* Studied how detection logs are created through rules, then a practical Lab featuring a SIEM from THM to have handson experience on Alerts.
* Practical overview of Splunk, its features, components and how it works.
* Learned how to manually upload logs to Splunk and did a Lab in Splunk investigating VPN_Logs
* The ELK Stack, how SOC Analysts use this and what are the components of it. Elastic search, Logstash, Kibana, Beats.  
* **SOAR** (Security Orchestration Automation and Response)
* How these systems work together in a SOC environment

### 🛠️ Tools Used

* Elastic SIEM
* Tryhackme EDR Dashboard
* Wazuh (possible)
* CrowdStrike / Windows Defender examples
* Splunk (conceptual exercises)

### 🧪 Labs

* Investigating alerts on EDR(Practical EDR Dashboard from tryhackme)
* Exploring EDR alerts
* Understanding automated responses
* SIEM Simulation
* Splunk practical manual log upload and VPN_Logs investigation

### 📝 Notes / Reflections

*To be filled in once completed.*

---

## 4️⃣ Cyber Defence Frameworks

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* MITRE ATT&CK
* Cyber Kill Chain
* Pyramid of Pain
* Defense-in-depth strategies
* How frameworks help with detection & response

### 🛠️ Tools Expected to Use

* MITRE ATT&CK Navigator
* Threat intel enrichment tools
* CyberChef

### 🧪 Labs

* Mapping alerts to MITRE techniques
* Understanding adversary behavior

### 📝 Notes / Reflections

*To be filled in once completed.*

---

## 5️⃣ Phishing Analysis

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* Types of phishing emails
* Analyzing headers
* Detecting malicious attachments/URLs
* Social engineering detection
* Identifying indicators of compromise

### 🛠️ Tools Expected to Use

* VirusTotal
* URLscan.io
* OTX (Open Threat Exchange)
* Email header analyzers

### 🧪 Labs

* Phishing email dissection
* Malicious link investigation

### 📝 Notes / Reflections

*To be filled in once completed.*

---

## 6️⃣ Network Traffic Analysis

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* Basics of packets, protocols, and network flows
* Understanding PCAPs
* Identifying malicious traffic
* Common attacks (port scans, brute force, MITM)

### 🛠️ Tools Expected to Use

* Wireshark
* Tcpdump
* Zeek (conceptual)

### 🧪 Labs

* Analyzing sample PCAP files
* Detecting suspicious network behavior

### 📝 Notes / Reflections

*To be filled in once completed.*

---

## 7️⃣ Network Security Monitoring

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* IDS/IPS systems
* Network perimeter monitoring
* Log types & analysis
* Detecting exfiltration, discovery, MITM

### 🛠️ Tools Expected to Use

* Suricata
* Zeek
* SIEM log dashboards

### 🧪 Labs

* Investigating network-based attacks
* Identifying malicious patterns

### 📝 Notes / Reflections

*To be added later.*

---

## 8️⃣ Web Security Monitoring

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* How web apps are attacked
* Detecting web-based threats:

  * XSS
  * SQLi
  * Directory traversal
  * RCE attempts
* Log interpretation (Apache/Nginx logs)

### 🛠️ Tools Expected to Use

* Web server logs
* SIEM queries
* WAF (Web Application Firewall) concepts

### 🧪 Labs

* Real-world web log analysis
* Detecting malicious requests

### 📝 Notes / Reflections

*To be added.*

---

## 9️⃣ Windows Security Monitoring

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* Windows Event Logs
* Detecting lateral movement
* RDP brute force signs
* Registry changes
* PowerShell logging
* Common Windows attacks

### 🛠️ Tools Expected to Use

* Event Viewer
* Sysinternals Suite
* Windows logging tools
* Elastic/Splunk dashboards

### 🧪 Labs

* Analyzing Windows logs for attacks
* Hands-on threat detection scenarios

### 📝 Notes / Reflections

*To be added.*

---

## 🔟 Linux Security Monitoring

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* Syslog basics
* Auth logs & command history
* SSH brute force detection
* Common Linux attack patterns

### 🛠️ Tools Expected to Use

* Syslog viewer
* SIEM queries
* Bash/Linux CLI

### 🧪 Labs

* Detecting Linux intrusion attempts
* Investigating privilege escalation attempts

### 📝 Notes / Reflections

*To be added.*

---

## 1️⃣1️⃣ Malware Concepts for SOC

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* Malware categories (Trojan, Worm, RAT, Ransomware, etc.)
* Indicators of malware
* Static vs dynamic analysis
* LOLBins (Living off the Land binaries)

### 🛠️ Tools Expected to Use

* VirusTotal
* CyberChef
* Sandbox tools (Hybrid Analysis / AnyRun)

### 🧪 Labs

* Basic malware signature identification
* File behavior analysis

### 📝 Notes / Reflections

*To be added.*

---

## 1️⃣2️⃣ Threat Analysis Tools

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* Threat intelligence lifecycle
* IOC enrichment
* Pivoting techniques
* Identifying malicious IPs/domains/hashes

### 🛠️ Tools Expected to Use

* OTX
* VirusTotal
* Shodan
* AbuseIPDB
* MalwareBazaar

### 🧪 Labs

* Enriching indicators
* Investigating adversary infrastructure

### 📝 Notes / Reflections

*To be added.*

---

## 1️⃣3️⃣ SIEM Triage for SOC

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* SIEM alert investigation
* Correlating logs
* Building attack timelines
* Identifying false positives
* Writing detection logic fundamentals

### 🛠️ Tools Expected to Use

* Elastic SIEM
* Splunk (conceptual)

### 🧪 Labs

* Investigating SIEM alerts
* Hands-on detection exercises

### 📝 Notes / Reflections

*To be added.*

---

## 1️⃣4️⃣ SOC Level 1 Capstone Challenges

**Status:** *Not Started*

### 🔍 Key Concepts to Learn

* End-to-end incident investigations
* Applying everything learned in previous modules
* Multi-stage attack analysis
* Full SOC analysis workflow

### 🛠️ Tools Expected to Use

* SIEM platform
* Threat intel tools
* Log analysis platforms

### 🧪 Labs

* Full investigation challenges
* Final SOC analyst exam-style tasks

### 📝 Notes / Reflections

*To be added.*

---

# 📁 Additional Resources

* MITRE ATT&CK Navigator
* SOC Analyst Cheat Sheets
* Log analysis references
* Threat intel lookup sites

---

# 🧠 Weekly Progress Log

*Week 1: Completed the first set of rooms from TryHackMe that introduced SOC Level 1.*

---

# 🎓 Skills Acquired (as progress continues)

### Technical Skills

* [ ] Log analysis
* [ ] Phishing investigation
* [ ] SIEM alert triage
* [ ] Network traffic analysis
* [ ] Windows/Linux attack detection
* [ ] Malware basics
* [ ] Threat intelligence investigations
* [ ] Incident response fundamentals

### Soft Skills

* [ ] Analytical thinking
* [ ] Clear communication
* [ ] Proper escalation handling
* [ ] Prioritization
* [ ] Report writing

---
