---
title: "7 — Lab-by-Lab Guide"
tags:
  - training
  - incident-response
  - pcap
---

# 7 — Lab-by-Lab Guide { #lab-guide }

!!! abstract "What this page is"
    The eight labs share most of their questions. This page lists what is **new** in each lab and links every question to the section that answers it. Questions are paraphrased.

## What each lab adds { #overview }

| Lab | New skill |
| --- | --- |
| 1 | Network inventory: DC, active hosts, and fingerprinting Ubuntu, Android, Amazon Fire and other devices |
| 2 | Spread to the DC over SMB, executables disguised as `.png`, hashes of SMB files |
| 3 | Following one download through Zeek logs with its UID ("Bro UID") |
| 4 | Delivery method (email, link, exploit kit) and post-infection C2 |
| 5 | Full URL, file size, and when malicious traffic started |
| 6 | Handling a malicious document safely, macro analysis, public IP |
| 7 | Any OS, download direction (internal/external), and the tool that started a download |
| 8 | Six executables, a failed SMB attempt on the DC, and writing a Snort rule |

## Lab 1 — Network inventory and device fingerprinting { #lab-1 }

Several kinds of device share the network; one Windows host is infected with two families.

- **Q1** — Which IP is the DC? → [Finding the Domain Controller](host-identification.md#domain-controller)
- **Q2–3** — How many other hosts are active, and their IPs? → [Active hosts on the LAN](host-identification.md#active-hosts)
- **Q4** — Which IP is Ubuntu? → [Fingerprinting devices](host-identification.md#device-fingerprinting)
- **Q5** — What type of device is a given IP? → [Fingerprinting devices](host-identification.md#device-fingerprinting) (MAC vendor + DHCP + DNS/User-Agent)
- **Q6** — Which IP is an Amazon Fire tablet? → [Fingerprinting devices](host-identification.md#device-fingerprinting)
- **Q7** — Which three Windows hosts talk to the DC? → [Windows user account](host-identification.md#user-account) (computer accounts ending `$`) and [Finding the Domain Controller](host-identification.md#domain-controller)
- **Q8** — Which Windows host shows a two-family infection? → [Reading Snort alerts](malware-delivery-and-c2.md#snort-alerts), [Commonly reported patterns](malware-delivery-and-c2.md#patterns)
- **Q9–10** — Which IP is Android 8.0.0, and what brand/model? → [Fingerprinting devices](host-identification.md#device-fingerprinting) (User-Agent model code, DHCP `android-dhcp-8.0.0`)
- **Q11** — Brand and type of another device → [Fingerprinting devices](host-identification.md#device-fingerprinting) (add mDNS/SSDP)
- **Q12** — Explain the compromise → [Two families](report-templates.md#two-families-template)

!!! tip "Lab 1 tip"
    One question in the original sheet shows an IP with a missing digit (`172.6.3.x` where every other address is `172.16.3.x`). Check for typos against the real address list before answering.

## Lab 2 — Spread to the DC over SMB { #lab-2 }

A Word document leads to a first executable, more executables disguised as `.png`, and then a copy to the DC.

- **Q1** — Time and date of infection → [Timeline](setup-and-workflow.md#timeline), [Listing downloads](files-and-hashes.md#listing-downloads) (time of the document download)
- **Q2–5** — IP, hostname, MAC, user account → [IP, MAC and hostname](host-identification.md#ip-mac-hostname), [Windows user account](host-identification.md#user-account)
- **Q6** — Hashes of the Word document → [Hashing](files-and-hashes.md#hashing)
- **Q7** — Hashes of the first malware binary → [Identifying the real file type](files-and-hashes.md#file-type), [Hashing](files-and-hashes.md#hashing)
- **Q8** — When was the DC infected? → [Lateral movement to the DC](dc-smb-and-snort-rules.md#smb-lateral)
- **Q9** — Hashes of the binaries disguised as images → [Identifying the real file type](files-and-hashes.md#file-type) (compare the two hashes: same file or different?)
- **Q10** — Hashes of the two SMB files → [Extracting files](files-and-hashes.md#extracting), [Lateral movement to the DC](dc-smb-and-snort-rules.md#smb-lateral)
- **Q11** — The two malware families → [Malware family and type](malware-delivery-and-c2.md#malware-type)
- **Q12** — Which family infected the DC? → compare SMB hashes with HTTP hashes ([Hashing](files-and-hashes.md#hashing), `uniq -w64 -D`)
- **Q14–15** — Key network information → [Key network information](host-identification.md#network-info), [template](report-templates.md#network-info-template)
- **Q16** — Explain the compromise → [Spread to the Domain Controller](report-templates.md#dc-template)

## Lab 3 — Following a download by Zeek UID { #lab-3 }

- **Q1–4** — IP, MAC, hostname, user account → [Finding the infected host](host-identification.md#infected-host), [IP, MAC and hostname](host-identification.md#ip-mac-hostname), [Windows user account](host-identification.md#user-account)
- **Q5** — Hashes of the executable → [Extracting files](files-and-hashes.md#extracting) (Zeek `extract-all-files`), [Hashing](files-and-hashes.md#hashing)
- **Q6** — Bro UID of the executable traffic → [Zeek UID and fuid](files-and-hashes.md#zeek-uid)
- **Q7** — Files correlated with the UID → [Zeek UID and fuid](files-and-hashes.md#zeek-uid) (`grep -l`)
- **Q8** — Key information for the download → [Key information for a download](files-and-hashes.md#download-key-info), [template](report-templates.md#download-template)
- **Q9** — Explain the compromise → [Generic infection](report-templates.md#generic-template)

## Lab 4 — Delivery method and post-infection traffic { #lab-4 }

- **Q1–2** — IP, MAC, hostname, user account → [Finding the infected host](host-identification.md#infected-host), [IP, MAC and hostname](host-identification.md#ip-mac-hostname)
- **Q3** — Delivery method → [Delivery method](malware-delivery-and-c2.md#delivery)
- **Q4** — IP used for delivery → [Delivery method](malware-delivery-and-c2.md#delivery)
- **Q5** — Hashes of the EXE → [Identifying the real file type](files-and-hashes.md#file-type) (exploit-kit payloads may be encrypted in transit)
- **Q6** — Malware type from the alerts → [Reading Snort alerts](malware-delivery-and-c2.md#snort-alerts), [Malware family and type](malware-delivery-and-c2.md#malware-type)
- **Q7–8** — Post-infection IP and domain → [Post-infection traffic](malware-delivery-and-c2.md#post-infection)
- **Q9** — Explain the compromise → [Delivery via exploit kit, link or email](report-templates.md#delivery-template)

## Lab 5 — Malicious URL, size and start time { #lab-5 }

- **Q1** — When did the malicious traffic start? → [Generating Snort alerts](setup-and-workflow.md#snort) (`-y -U`), [Timeline](setup-and-workflow.md#timeline). Use the earlier of the first alert and the first request in the chain.
- **Q2–4** — MAC, hostname, user account → [IP, MAC and hostname](host-identification.md#ip-mac-hostname), [Windows user account](host-identification.md#user-account)
- **Q5** — URL that returned an executable → [Full URL and file size](files-and-hashes.md#url-and-size)
- **Q6** — Size of that file → [Full URL and file size](files-and-hashes.md#url-and-size) (declared vs carved size)
- **Q7** — Hashes → [Hashing](files-and-hashes.md#hashing)
- **Q8** — Malware type → [Malware family and type](malware-delivery-and-c2.md#malware-type)
- **Q9** — Explain the compromise → [Generic infection](report-templates.md#generic-template)

## Lab 6 — Safe document handling and public IP { #lab-6 }

- **Q1** — Time and date of infection → time of the document download ([Listing downloads](files-and-hashes.md#listing-downloads))
- **Q2–5** — IP, hostname, MAC, user account → [IP, MAC and hostname](host-identification.md#ip-mac-hostname), [Windows user account](host-identification.md#user-account)
- **Q6** — Safely hash the Word document and explain the steps → [Handling samples safely](files-and-hashes.md#safe-handling), [template](report-templates.md#safe-handling-template)
- **Q7** — Type of malware in the initial infection → [Malicious Word documents and macros](files-and-hashes.md#macros), [Malware family and type](malware-delivery-and-c2.md#malware-type)
- **Q8** — Public IP of the client → [Public IP](host-identification.md#public-ip)
- **Q9** — Key network information → [Key network information](host-identification.md#network-info)
- **Q10** — Explain the compromise → [Malicious Word document](report-templates.md#macro-template)

## Lab 7 — Direction and download tool { #lab-7 }

The compromised host is not assumed to be Windows.

- **Q1–3** — IP, MAC, hostname → [Finding the infected host](host-identification.md#infected-host), [IP, MAC and hostname](host-identification.md#ip-mac-hostname) (also mDNS/LLMNR)
- **Q4** — Operating system → [Operating system](host-identification.md#operating-system)
- **Q5–6** — What was downloaded, how many, from where → [Listing downloads](files-and-hashes.md#listing-downloads), [Extracting files](files-and-hashes.md#extracting) (HTTP, SMB, TFTP, FTP, raw TCP)
- **Q7** — Internal or external source → [Internal or external source](malware-delivery-and-c2.md#direction), [template](report-templates.md#source-template)
- **Q8** — Information that could inform further investigation → [Key information for a download](files-and-hashes.md#download-key-info)
- **Q9** — Anything else after the download → [Post-infection traffic](malware-delivery-and-c2.md#post-infection)
- **Q10** — What started the downloads → [What started the download](malware-delivery-and-c2.md#download-tool)
- **Q11** — Explain the compromise → [Downloads, direction and tool](report-templates.md#direction-template)

## Lab 8 — Six executables, a failed SMB attempt and a Snort rule { #lab-8 }

- **Q1–4** — IP, MAC, hostname, user account → [Finding the infected host](host-identification.md#infected-host), [IP, MAC and hostname](host-identification.md#ip-mac-hostname), [Windows user account](host-identification.md#user-account)
- **Q5** — The six URLs that returned executables → [Full URL and file size](files-and-hashes.md#url-and-size)
- **Q6** — Hashes of the six executables → [Hashing](files-and-hashes.md#hashing) (loop over PE files), [template](report-templates.md#hashes-template)
- **Q7** — Type of infection, from researching the files → [Malware family and type](malware-delivery-and-c2.md#malware-type), [template](report-templates.md#infection-type-template)
- **Q8** — Explain the compromise → [Multiple executables and a failed DC attempt](report-templates.md#multi-exe-template)
- **Q9** — What was attempted against the DC on 445 → [Failed attempts on TCP 445](dc-smb-and-snort-rules.md#failed-445)
- **Q10** — A Snort rule for this kind of 445 traffic → [Snort rule syntax](dc-smb-and-snort-rules.md#snort-rules), [Example rules](dc-smb-and-snort-rules.md#example-rules), [Testing rules](dc-smb-and-snort-rules.md#testing-rules)

!!! note "About these pages"
    Personal study notes. Not official guidance of any organisation.
