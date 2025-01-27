# MalNet

**CTF:** Srdnlen CTF 2025\
**Category:** Misc - Digital Forensics Incident Response\
**Difficulty:** Easy\
**Solves:** TBA\
**Authors:** [@slsanna]() (Silvia Sanna) 
---

## Description

> We have been notified of an attack in one of our machines. This is a real forensics investigation and you have to analyse the given pcap file and answer to the related questions. At the end you will get the flag when you answer everything correct.

> NOTE: This is a real malware. Do not execute nothing. Pay attention and be careful. Srdnlen denies every damage on your infrastructure.

> This is a remote challenge, you can connect to the service with: `nc dfir2.challs.srdnlen.it 1985`


> Author: slanna

---

## Overview

In this challenge we have to answer specific questions by analysing the given pcap file by using Wireshark or other tools like tshark or whatever you prefer.
We are sorry if some questions where ill-posed.

## Solution

We will present answers for each question.

### 1. Which packet contains the header of an executable file?

An executable file (.exe) starts always with "MZ ... This file cannot be run in DOS mode". Hence, by looking at this syntax in the pcap file with `tcp contains DOS`, we have only one packet containing this string: "2137".

### 2. To which flow does it correspond? (PROTOCOLO FLOW_ID, e.g. HTTP 1)

By selecting the packet and in Wireshark right click, Follow, TCP flow, we have the answer: "TCP 40".

### 3. Into how many parts is the executable fragmented? Give the total number of files

In Wireshark, using "File/Export Objects/HTTP" and selecting only files with type "application/octet-stream" and with the same name "7d9cd93c-1d5e-449b-9ad7-f1e8d6b90509" (it is the name of the resource containing the target executable) we have the answer "29". This means that the executable file has been divided into 29 pieces.

### 4. What is the resource name accessed in the GET resource containing the executable file?. Give the complete name (e.g. /myfile/file1/this-is-the-file?A0=something&A1=other%3d%3d)

In the TCP flow 40 containing the executable file, we can see the GET request (at the beginning of the flow, the red one): /filestreamingservice/files/7d9cd93c-1d5e-449b-9ad7-f1e8d6b90509?P1=1736543287&P2=404&P3=2&P4=A4bbVZMC2rLzoHuEoqkGyn%2bfjFNZYtKNVXsPbIbY5Amz3v4r%2bQitB5Uc%2fXCKOEvShr8HAJPOsSVdpx2t0DGgKQ%3d%3d

### 5. What is the sha256 of the first part of the executable file?

In Wireshark, use "File/Export Objects/HTTP" and save all the files belonging to the resource "7d9cd93c-1d5e-449b-9ad7-f1e8d6b90509". Then, use strings in all of them to find the file with the PE (executable) header "MZ ... This Program cannot be run in DOS mode ...". It belongs to the third extracted file (its name is the name of the resource answered in question 4 with a progressive number because the name is repeated). By computing the sha256sum of the third file, we have the answer "b56b0ee4af8f4395455ed4f83b2d25498444c939fcf77d49ec9ec83c68983e52".

### 6. To which of the extracted files does it correspond? As done by Wireshark, use the enumeration starting from 0

As explained in the previous answer to question 5, the number is "2" (it is the third but starts with 0).

### 7. What is the sha256sum of the reconstructed file?

This question can be approached differently. You could reconstruct the whole executable file starting from the extracted 29. 
The most efficient way is by reading the content of file "pieceshash", found at packet 740, TCP flow 40. The file contains the base64 of the reconstructed hash "HashOfHashes": "JvZyinMn7LiBqNeYmy7JPeu8Kn4chEzksqZUnwB2Pg4=", whose value in hex is the answer to this question: "26f6728a7327ecb881a8d7989b2ec93debbc2a7e1c844ce4b2a6549f00763e0e". This can be confirmed because converting the first element in list "Pieces" from base64 to hex, we find the sha256 of the first part of the executable (question 5).

### 8. How many downloaded chrome extensions are not corrupted?

By saving all files with type "application/x-chrome-extension" and by opening them with a zip extractor such as WinRAR, we can see that some are corrupted: "5".

### 9. Which packet is related to cryptomining?

With the filted "tcp contains crypto" we can see it is packet "290".

### 10. To which flow does it correspond? (PROTOCOLO FLOW_ID, e.g. UDP 0)

With right click on it, Follow Flow: "HTTP 8"

### 11. What is the resource name? Give the complete name (e.g. /myfile/file1/this-is-the-file?A0=something&A1=other%3d%3d)

As done for question 4, here the answer is "/filestreamingservice/files/dfeb2940-49d3-4f29-8fd8-d984a787dc6e?P1=1736222766&P2=404&P3=2&P4=H1jtSvldNZpuTpd5fP9uKkWsRR%2f5pXzccLVud6a0mJoxofqoKB34dNqF4qXGEwhkbPhjKQoon413psf1XzNktA%3d%3d"

### 12. Give the sha256 of the file related to cryptocurrency.

By extracting this file, which is a Chrome Extension and computing its sha256sum, we have the answer "364dfe0f3c1ad2df13e7629e2a7188fae3881ddb83a46c1170112d8d3b5a73de".

### Flag.

By answering in the correct way to all the questions, the flag is printed: srdnlen{DFIR2:network_analysis_R34L_malware}



