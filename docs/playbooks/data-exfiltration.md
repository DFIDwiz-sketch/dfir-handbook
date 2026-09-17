---
title: Data Exfiltration
tags:
  - playbook
  - exfiltration
---

# Data Exfiltration

<div class="dfir-meta" markdown>
**Scenario:** Suspected theft of data — large uploads, staging archives, DLP alert · **Last updated:** 2026-09-17
</div>

!!! abstract "When to use this"
    A DLP alert, an unusual large outbound transfer, a staging archive appearing in a temp folder, or a double-extortion ransom threat. The investigative goals are specific: **what data left, how much, by what channel, to where, and when** — because those answers drive legal/regulatory notification and the scope of harm.

## 1. Triage (first 15 minutes)

- Establish the **channel**: web upload (HTTPS to cloud storage), a cloud-sync client (rclone/MEGA/Dropbox), email attachments, DNS tunnel, an SSH/SFTP session, or physical (USB).
- Establish **rough volume and time window** from network/host telemetry — is it ongoing?
- Identify the **staging** (attackers usually collect and compress before sending) and the **destination**.
- If active, contain the channel (block the destination, kill the session) after capturing enough to prove what went.

## 2. Collect

| Source | What it shows | Where |
|---|---|---|
| [SRUM](../windows/srum.md) | **Bytes sent per application per hour**, with user | The single best host-side exfil artifact |
| [$MFT / $UsnJrnl](../windows/mft-usn.md) | Staging archive creation (`.zip/.7z/.rar`) then deletion; what was collected | `FileCreate` + `DataExtend` on archives, then `FileDelete` |
| [Zeek `conn.log`](../network/zeek/conn-log.md) | `orig_bytes` per pair — who uploaded how much where | Network-side volume |
| [Zeek `files.log`](../network/zeek/files-log.md) / [http.log](../network/zeek/http-log.md) | `is_orig=T` uploads, hashes, destinations | What files, to where |
| [Zeek `dns.log`](../network/zeek/dns-log.md) | DNS-tunnel volume | If channel is DNS |
| [Arkime](../network/arkime/hunting-workflows.md#workflow-6-exfiltration) | Full sessions + pcap for the transfer | Proof + content |
| Cloud/proxy/DLP logs | Uploads to sanctioned & unsanctioned SaaS | Proxy, CASB, M365/Google audit |
| USB artifacts | Device + files copied to removable media | [Registry USB keys](../windows/registry-keys.md#usb-removable-devices-system), [LNK to E:\\](../windows/lnk-jumplists.md) |

## 3. Analyse

- **What was staged**: `$UsnJrnl` shows the archive being created and its size ([MFT/USN exfil pattern](../windows/mft-usn.md)); the files created just before it are the collection. If the archive still exists, its contents tell you exactly what was taken; if deleted, `$MFT` may retain size and name.
- **How much left, and where**: [SRUM](../windows/srum.md) gives bytes-per-app-per-hour with the user; correlate with [Zeek `conn.log` `orig_bytes`](../network/zeek/conn-log.md) per destination. A tool like `rclone.exe`/`megasync.exe`/`winscp.exe`/`curl.exe` sending hundreds of MB at night is the candidate.
- **The channel & destination**: [http.log](../network/zeek/http-log.md) POST/PUT to cloud storage, [ssl.log SNI](../network/zeek/ssl-x509.md) (mega.nz, dropbox, drive.google, a VPS), [dns.log](../network/zeek/dns-log.md) for tunnelling, or SSH/SFTP long sessions. Pull the pcap in [Arkime](../network/arkime/index.md) if you need to prove content.
- **Timeline**: SRUM's hourly buckets + `$J` timestamps + Zeek `ts` give a precise "data left between X and Y" for the report.
- **USB path**: if removable media, [MountPoints2 / USBSTOR](../windows/registry-keys.md#usb-removable-devices-system) tie a device to the user, and [LNK files](../windows/lnk-jumplists.md) to `E:\` show files opened/copied there.

## 4. Contain / Eradicate

- Block the destination domain/IP at egress; disable the account or session used; if a cloud-sync tool was installed, remove it and revoke any token/app it used.
- If exfil accompanied a broader intrusion (it usually does), pivot to the [lateral movement / domain playbook](lateral-domain.md) and reset the involved credentials.
- Preserve everything — exfil incidents frequently become legal/regulatory matters; maintain chain of custody on the archive, the logs, and the pcap.

## 5. Recover & lessons

- Determine notification obligations based on **what data** left (personal data, regulated data). In Australia, assess against the **Notifiable Data Breaches** scheme (OAIC) and any sector-specific rules; involve legal/privacy early.
- Harden: DLP on egress, block/monitor unsanctioned cloud-storage and tunnelling tools, alert on large `orig_bytes` per host and on archive-then-upload patterns, restrict/monitor USB, and baseline normal upload volumes so anomalies stand out.

## Useful queries

```spl
index=botsv3 sourcetype=stream:tcp
| where NOT cidrmatch("10.0.0.0/8",dest_ip) AND NOT cidrmatch("192.168.0.0/16",dest_ip) AND NOT cidrmatch("172.16.0.0/12",dest_ip)
| stats sum(bytes_out) as out, sum(bytes_in) as in by src_ip, dest_ip, dest_port
| eval out_MB=round(out/1048576,1), ratio=round(out/(in+1),1)
| where out_MB > 100 AND ratio > 5
| sort - out_MB
```

Sums outbound vs inbound bytes per internal→external pair. `ratio` = sent divided by received; a host that sent 5× more than it received, in the hundreds of MB, to an external IP is uploading. `out_MB` quantifies it for the report.

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=11 TargetFilename IN ("*.zip","*.7z","*.rar","*.tar","*.gz")
| where match(TargetFilename,"(?i)\\\\(temp|users\\\\public|programdata|windows\\\\temp|perflogs|appdata)\\\\")
| table _time, host, User, Image, TargetFilename
| sort 0 _time
```

Sysmon `11` = file created. Archives written to staging directories (`Temp`, `Public`, `ProgramData`) are the collection step before exfil — the process (`Image`) that created them and the timing point to the actor and the "what was taken".

## References

- [MITRE ATT&CK — Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010/) · [Collection (TA0009)](https://attack.mitre.org/tactics/TA0009/)
- [OAIC — Notifiable Data Breaches (AU)](https://www.oaic.gov.au/privacy/notifiable-data-breaches)
- Pages: [SRUM](../windows/srum.md) · [MFT/USN](../windows/mft-usn.md) · [Zeek conn/http/dns](../network/index.md) · [Arkime exfil workflow](../network/arkime/hunting-workflows.md) · [Beaconing & C2](../network/beaconing-c2.md)
