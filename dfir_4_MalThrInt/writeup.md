# MalThrInt

**CTF:** Srdnlen CTF 2025\
**Category:** Misc - Digital Forensics Incident Response\
**Difficulty:** Easy\
**Solves:** TBA\
**Authors:** [@slsanna]() (Silvia Sanna) 
---

## Description

> We have been notified of an attack in one of our machines. This is a real forensics investigation and you have to retrieve Threat Intelligence data from VirusTotal using the last answered hash of DFIR-3-RAMsomwhere and answer to the related questions. At the end you will get the flag when you answer everything correct.

> NOTE: This is a real malware. Do not execute nothing. Pay attention and be careful. Srdnlen denies every damage on your infrastructure.

> This is a remote challenge, you can connect to the service with: nc dfir4.challs.srdnlen.it 1987
> 
> Author: slanna
> 

> ```

---

## Overview

In this challenge we have to answer specific questions using VirusTotal and looking for the hash found in the last question of DFIR 3: 0002bdf0923262600d3ef66d1ec6b2396a434e6f7626a9d70241a5663ee2f736
This is inspired by real incident response techniques where you have to use Threat Intelligence tools to retrieve information from the attack vector, that is the parent process who generated the attack (see DFIR 3 for more details).
The hash could be also found in different ways without waiting to answer to the last question of DFIR 3 but with that answer you would be 100% sure of its meaning.

## Solution

We will present answers for each question. All the answers correspond to the moment of the CTF. If the sample has been re-analyzed with the VirusTotal option, some answers can change.

### 1. What is the VT detection score?

By inserting the hash in VirusTotal "https://www.virustotal.com/gui/home/upload", selecting "Search", we can see the detection score in the red circle. "62/72" (means detected as malicious by 62 antiviruses over 72 available). This is the score at the moment of the CTF but can change during the time because of "Reanalyze" option that everyone can click on. During the CTF it did not change.

### 2. Give the popular threat label.

In the "Detection" tab, one of the first printed results is "Popular threat label", which is "virus.virlock/polyransom".

### 3. When was it created?

In the "Details" tab, there is a section "History" with a field "Creation Time" whose value is the answer (just copy and paste it): "2018-06-26 16:16:29 UTC"

### 4. What is the target machine?

In the "Details" tab, there is a section "Header" with a field "Target Machine" whose value is "Intel 386".

### 5. Which dlls are used? Give just the name without .dll extension. If more than one put a comma (e.g. 1, 2)

In the "Details" tab, there is a section "Imports" listing the imported dlls: "kernel32, user32".

### 6. What is the malicious IP address?

In the "Relations" tab, there is a section "Contacted IP addresses" and in this list, one IP address is flagged in red by one anti-virus machine (it is the only one malicious, the others are green meaning not detected as malicious): "144.76.195.253".

### 7. What is the registrar of the domain related to the previous bitcoin address?

This refers to the bitcoin domain found in DFIR 3 "1yQBzAaZx7FojqMmTtHPTfZ42T4t6Q1Uh" belonging to "charts01.bitcoincharts.com". In the "Relations" tab, there is a section "Contacted Domains" and the registrar of that domain is "Hetzner Online GmbH"

### 8. Which persistence techniques according to MITRE does it have? If more than one put a comma (e.g. 1, 2)

In the "Behaviour" tab we can see information during execution. There is a subsection called "Activity Summary" containing "MITRE ATT&CK Tactics and Techniques". Hence, the answer is the list of Techniques (called by MITRE with this convention "T" and a progressive number, e.g. "T001") and retrieving their number by clicking on each of them (with the "+" button) and reading all the Techniques numbers. As the question says if more than one write (1, 2), this also means that we have to put them in ascending order, separated by comma. The answer is: "T1053, T1542, T1542.003, T1547, T1547.001, T1574, T1574.002".

### 9. Which defence/evasion techniques according to MITRE does it have? If more than one put a comma (e.g. 1, 2)

In the "Behaviour" tab, under "MITRE ATT&CK Tactics and Techniques", there is the list of the most common behaviours grouped by MITRE Techniques. One of the listed behaviour is "Defence Evasion TA0005". By clicking on the "+" botton, we can see the list of the techniques. As the question says if more than one write (1, 2), this also means that we have to put them in ascending order, separated by comma. Hence, the answer is "T1014, T1027, T1027.002, T1036, T1055, T1112, T1202, T1497, T1542, T1542.003, T1548, T1548.002, T1562, T1562.001, T1562.006, T1564, T1564.001, T1574, T1574.002".

### 10. Which anti-behavioral analysis techniques according to MITRE does it have? If more than one put a comma (e.g. 1, 2)

In the "Behaviour" tab, under "Malware Behavior Catalog Tree", there is the list of the malware behaviours. By clicking on "Anti-Behavioral Analysis" (the first one) using the "+" button, we can see the answer. As the question says if more than one write (1, 2), this also means that we have to put them in ascending order, separated by comma. Hence, the answer is "B0007, B0007.008, F0001".

### 11. Which anti-static analysis technique according to MITRE does it have?

In the "Behaviour" tab, under "Malware Behavior Catalog Tree", there is the list of the malware behaviours. By clicking on "Anti-Static Analysis" (the second one) using the "+" button, we can see the answer. As the question says if more than one write (1, 2), this also means that we have to put them in ascending order, separated by comma. Hence, the answer is "F0001".

### Flag.

By answering in the correct way to all the questions, the flag is printed: srdnlen{DFIR4:VirusTotal4PPID_ThreatIntelligence}



