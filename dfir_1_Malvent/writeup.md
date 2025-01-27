# Malvent

**CTF:** Srdnlen CTF 2025\
**Category:** Misc - Digital Forensics Incident Response\
**Difficulty:** Medium\
**Solves:** TBA\
**Authors:** [@slsanna]() (Silvia Sanna) 
---

## Description

We have been notified of an attack in one of our machines. This is a real forensics investigation and you have to analyse the given evtx files and answer to the related questions. At the end you will get the flag when you answer everything correct.

NOTE: **This is a real malware**. Do not execute nothing. Pay attention and be careful. Srdnlen denies every damage on your infrastructure.

This is a remote challenge, you can connect to the service with: `nc dfir1.challs.srdnlen.it 1984`


> Author: slanna


---

## Overview

In this challenge we have to answer specific questions by analysing the given evtx files by using Windows Event Visualizer. With this tool you can find the answer to the questions realted to "give the event ID" because it shows every event and its ID (general Windows enumeration for specific events and assigning them a specific number according to the "class" they belong to) with a time and a description of what happened.
We are sorry if some questions where ill-posed.

## Solution

We will present answers for each question.

## NOTE: these questions can be answered with "System.evtx" file.

### 1. What is the name of the suspicious service installed?

Analysing the System.evtx file, we can see a service in autostart related to event ID 7045. The answer is "QcUcMElh".

### 2. From which process it has been generated? Give also the extension

In the same event found for the previous answer with ID 7045, we can see the process name: "lmIcgUEQ.exe".

### 3. What is its event ID?

As described in answer 1, the event ID is 7045.

### 4. Give the events IDs corresponding to unsecured data (e.g. cryptography). If more than one put a comma (e.g. 1, 2)

First of all we are sorry for the ill-posed question that we clarified with the hints. We referred to wrong data cryptography management (e.g. cryptography) whose service is managed by TPM. Hence, by filtering on these events, we can find the answer (also because they are flagged as "error" by Windows): "15, 18" as the question was specifying if more than one separate with a comma (e.g. 1, 2), also meaning the ascending order.

### 5. Which event ID is related to the state of the account protection?

First of all we are sorry for the ill-posed question that we clarified with the hints. We referred again to the wrong password management. The answer is "16977" because it says that the password of the account does not have the minimum password length (this is not secure, no check on the password length).

### 6. Give the compromised CLSID stating that malicious code could be executed. If more than one, put a comma (e.g. str1, str2)

The question is referred to DistributedCOM events with ID 10016, the answer is "Windows.SecurityCenter.SecurityAppBroker, Windows.SecurityCenter.WscBrokerManager" (separated by comma and in chronological order).

### 7. What is the port number listening for remote control?

By filtering on rdp (remote desktop protocol for remote control), the answer is "3387".

### 8. Give the event ID related to the manipulation of specific data (e.g. registry key manipulation, deletion, creation, modification)

By inspecting deeply the event, all the actions asked in the example given in the question, are related to event ID "16".

## NOTE. The following questions can be answered with Application.evtx
We are sorry, we could have specified better to guide you in the analysis.

### 9. Give the application name whose corruption could depend from the malware. (First letter uppercase, add also the extension).

As stated by the question, to answer you have to analyse the Application.evtx file. There is only one event related to an error, an application error and depending on an application crash: "Widgets.exe" with event ID 1000.

### 10. Is Windows Defender on?

Events with ID 15 managed by Security Center stated that Windows Defender was on, answer: "yes".

### 11. What is the event ID stating this?

As described in the previous answer is "15".

### 12. Give the event ID related to the wrong management of different sessions and users in remote desktop.

It is related to Winlogon and event with ID "6003" cannot manage the sessions in a critical way.

## NOTE. The following questions can be answered with Security.evtx
We are sorry, we could have specified better to guide you in the analysis.

### 13. Which event ID states that the malware could have read the credentials?

This question is related more to the security and by inspecting Security.evtx, all events with ID "5379" are related to the notification that a user read the credentials stored in the Credential Management System and by analysing the time of the event notification, it is strange that a user wants to read so many times the credential, so this can be imputed to the malware.

### Flag.

By answering in the correct way to all the questions, the flag is printed: srdnlen{DFIR1:evtx4system_mngmnt&malwan}



