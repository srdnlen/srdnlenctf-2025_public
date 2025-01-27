# RAMsomwhere

**CTF:** Srdnlen CTF 2025\
**Category:** Misc - Digital Forensics Incident Response\
**Difficulty:** Hard\
**Solves:** TBA\
**Authors:** [@slsanna]() (Silvia Sanna) 
---

## Description

> We have been notified of an attack in one of our machines. This is a real forensics investigation and you have to analyse the given elf file and answer to the related questions. At the end you will get the flag when you answer everything correct.

> You can download the file from this link: [https://tinyurl.com/srdnlenCTF24-dfir3](https://tinyurl.com/srdnlenCTF24-dfir3)

> NOTE: **This is a real malware**. Do not execute nothing. Pay attention and be careful. Srdnlen denies every damage on your infrastructure.

> This is a remote challenge, you can connect to the service with: `nc dfir3.challs.srdnlen.it 1986`

> Author: slanna
> 

---

## Overview

In this challenge we have to answer specific questions by analysing the given dump of the RAM captured during the attack. The challenge can be solved using Volatility 3: https://github.com/volatilityfoundation/volatility3
First of all we have to understand the running OS to use the correct plugins and in case of Linux construct or find online the file with the symbols. This can be done with the command `strings capture.elf | grep "Windows"` but also, as we are given previously the .evtx files belonging to Windows OS, we already know we have to use the Windows plugins.
This is a real malware analysis using the capture of the RAM, hence we did not made anything new. The RAM contains the behaviour of the real malware and we are not responsible for any strange behaviour. We are sorry if some questions have been misinterpreted or illposed.
All the analysis is focused on two suspected processes not analysed previously on the challenge. As DFIR 1 focused on "lmIcgUEQ.exe", we did not focus on it.

## Solution

We will present answers for each question.

### 1. What is the PID of the process found in the evtx analysis?

It refers to the process found in the System.evtx file analysis of DFIR 1, which was "lmIcgUEQ.exe". This answer can be found in the RAM by using volatility plugin `windows.pstree` which lists the tree of the processes running at the moment of the RAM capture.
The complete command is `python3 vol.py capture.elf windows.pstree`. We have a list of the tree with all the running processes and by looking at the target "lmIcgUEQ.exe" (with a grep), the first number is its process ID: "2240".

### 2. Which IP does not compare in the given pcap file?

This refers to the pcap file given for DFIR 2. With volatility we can list the connections created by each process and the used IP addresses with the plugin `windows.netscan`. By comparing the result of this plugin and the list of IP addresses in the given pcap with Wireshark "Statistics/Conversations/IPv4" (but you can also use a script or other tools), the answer is "127.0.0.1".

### 3. What is the name in the manifest of the chrome extension found in the pcap and not in the RAM?

Also this pcap refers to the one given for DFIR 2. Each chrome extension has a manifest file "manifest.json" containing a field called "name" with a specific value, characterizing the name of the chrome extension.
To solve this question we have to extract all the chrome extensions in the pcap. With Wireshark "File/Export Objects/HTTP" and save the files with Content Type "application/x-chrome-extension". To analyse the manifest.json file, you can open it with a zip extractor such as WinRAR.
We also have to extract the manifest.json files from the RAM and with volatility we can use the plugin `windows.filescan` to list all the files opened at the moment of the RAM acquisition and then a grep to print only the manifest.json files. Hence the command is `volatility3 -f capture.elf windows.filescan | grep "manifest.json"`. When listing them, the first given result is the memory offset where the file can be found.
To analyse them, we have to extract the files (dump) with the plugin `windows.dumpfiles` giving the virtual address of the memory offset where the file is found. Hence the complete command for each of the previously printed manifest files, is `volatility3 -f capture.elf windows.dumpfiles ‑‑virtaddr OFFSET`. This can be scripted or done manually.
The manifest.json file can be read with a simple `cat` command and by comparing the results with the manifest extracted from the pcap, the answer is "AutofillCore".

### 4. Give the PID of the displayed suspicious processes (do not consider does already analysed, neither their sons). If more than one put a comma (e.g. 1, 2)

By using the plugin `windows.pstree` or `windows.pslist` we can see the list of the running processes and in this list two names (except for "lmIcgUEQ.exe" that we already mantioned) seem stranges and not belonging to legitimate or default Windows processes. Their PID is the first number. The answer to this question is "6444, 1236" according to chronological order.

### 5. What is the directory of the file related to process 6444? Give the complete path from the root directory to the extension. (e.g. C:\\path\\my\\process.extension)

This answer can be found by using the plugin `windows.cmdline` to look for its execution but the more correct one is `windows.filescan` as it prints the path storing the file belonging to each process. With a grep of the target process name, we can see the directory: "C:\\Users\\User\\kOIUsMQU\\MEMYUoYU.exe"

### 6. What is the directory of the file related to process 1236? Give the complete path from the root directory to the extension. (e.g. C:\\path\\my\\process.extension)

This answer can be found by using the plugin `windows.cmdline` to look for its execution but the more correct one is `windows.filescan` as it prints the path storing the file belonging to each process. With a grep of the target process name, we can see the directory: "C:\\ProgramData\\hwQkYMwk\\ceIcEMkw.exe"

### 7. What is the parent PID of the malicious processes?

Both processes have been generated by the same process, found in the second column of the output generated by the command `windows.pstree` and the answer is "4680".


## NOTE: from now on the answers can be found using the plugin `windows.malfind` as we are looking for the malicious behaviours of the suspected processes. 
We are sorry, we could have specified it more clearly to guide you better in the analysis.
### 8. How many files have been encrypted?

 This answer can be approached in two ways. The longest one is using the `windows.filescan` command and looking for suspicious extensions. This is the main feature of encrypted files: a double extension or a suspicious (meaning not common, not official) extension. This is the longest way because we do not know the extension.
 The shortest way is by using the `windows.malfind` command and analysing its output. As the output is very long, it is better to save in a file and analyse it carefully. As we are interested in the encrypted files, we look in the output file, to the related target processes "MEMYUoYU" and "ceIcEMkw".
 By reading carefully at the malfind output of the target processes, we noticed that both open with notepad a file "ZcgU.txt" just after the start of their execution (this is how malfind plugin works: lists suspicious instructions one after the other during execution). This could mean that they look for the content of this file to know which files to encrypt. (To leave this answer less intuitive, we could have inverted question 9 with question 8).
 Hence we look for the file in `windows.malfind` and we find it. By dumping this file with `volatility3 -f capture.elf  windows.dumpfiles ‑‑virtaddr 0xbd0c78962190` and with `cat` command on the file, we can see a list of files with the entire path. If we look with `windows.filescan` on those files, we can see that in their original extension (e.g. jpg) a ".exe" has been added. So, with a `cat ZcgU.txt | wc -l` we can count the number of encrypted files and the answer is "288".

### 9. Give the filename of the file containing the list of the files to be encrypted. (only the filename not the whole path).

Because of the previous question, the answer here is "ZcgU.txt".

### 10. Which cryptocurrency is used?

By analysing malfind output, we can find the answer: "BitCoin". 

### 11. Which GET request is not present in the pcap? Give the whole request (METHOD resource, e.g. POST /accessed/resource)
First of all we are sorry that the example with POST could have give some doubts according to the question asking for the GET. Then, we know that the dump contains many GET requests, some of them not present in the pcap given for DFIR 2 challenge, so we could have specified more clearly that we were looking for a GET request generated by the malicious process.
After clarifying this in some tickets and releasing the hint, by using the `windows.malfind` plugin, there was only one GET request and the answer is "GET /maps/api/staticmap?center=32.33597550,-111.04410110&zoom=14"

## NOTE: from now on the answers can be found using the plugin `windows.memmap` as we are looking for specific contents generated by the malware and that can be found with the memory dump of the target process. 
We are sorry, we could have specified it more clearly to guide you better in the analysis.
It is important to distinguish between the dump of the process and the dump of the memory of a process. The first one simply dumps the executable with the used dlls. The second one dumps the content of the memory of the process during the execution. As we are interested on retrieving data of the process execution and not on the executable itself (the file.exe), we will use memmap.

### 12. Why did you have to pay a fine?

First, we have tp dump the memory content of process "6444" with the command `volatility3 -f capture.elf -o OUTPUT_DIR windows.memmap ‑‑dump ‑‑pid 6444`. Then, we have to analyse the memory content simply with `strings -el pid.6444.dmp` (the memory works in little endian) and with a grep on a part of the given question `pay a fine` we can find different results such as "here are two ways to pay a fine:". By repeating the previous command but adding the option "-A N" with N a number of lines we want to display after that match, we can find the answer to the question. This is because of how the memory works, so we can find the continue of the string, some lines after. So, with the command `strings -el pid.6444.dmp | grep "pay a fine" -A 5`, we find as first result the answer to the question: "unauthorized or pirated software".

### 13. What is the amount of fine? (e.g. €10,000)

We are sorry that the euro symbol confused some of you but it was just an example. With the approach described previously for question 12, we can find the answer "$250,000".

### 14. Which forum is used to ask for BitCoin AMT?

First of all, sorry for the typo AMT but it was ATM as we clarified later.
Using the memory dump of process 6444 leads to nothing. So, by dumping the memory process of 1236 `volatility3 -f capture.elf -o OUTPUT_DIR windows.memmap ‑‑dump ‑‑pid 1236` and by analysing it with strings, we can find some questions on reddit.com asking for how to find the nearest BitCoin ATM. Hence, the answer is "reddit.com".

### 15. What is the BitCoin address at charts01.bitcoincharts.com?

By analysing the memory dump of process 1236, with a grep on the given URL in the question and using the option -A N to display the following N lines, on the third occurrence, we can find the address "1yQBzAaZx7FojqMmTtHPTfZ42T4t6Q1Uh".

### 16. From which directory does process 6444 come from? Give only the local path with directory name (NOT the absolute path, i.e. without Desktop, e.g. mydirectory)

To answer to this question we can analyse the memory dump of the process 6444 but it is somehow misleading because of the different printed results. Hence, the plugin `windows.handles --pid 6444` can help us. The handles plugin enumerates the open handles (e.g. files, registry keys, mutexes...) associated with processes in a memory dump. For this reason it can contain the name of the file that generated the processes (the file with PID 4680) and the directory storing it. By analysing the output of handles plugin, we have the answer "ch2".

### 17. What is the filename of the process which executed the two malware with PID 4680? Give only the filename with extension (e.g. myfile.ext)

From the previous question we know that the executable is in directory "ch2", but handles did not print the parent name. We can check in the memory dump of the process "6444" the occurrences of the path "\Users\User\Desktop\ch2" and check if it contains the name of the executable. Neither filescan on that path produces a result, this can depend on and is related with the time of the capture of the RAM and the fact that probably the OS already deleted its traces. In fact, with the memory dump of 6444, we can see that the file was "0002bdf0923262600d3ef66d1ec6b2396a434e6f7626a9d70241a5663ee2f736.exe".
This could have been found at every moment and that is why you could solve DFIR4 independently.

### Flag.

By answering in the correct way to all the questions, the flag is printed: srdnlen{DFIR3:Windows_RAMsomware}



