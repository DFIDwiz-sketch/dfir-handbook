---
title: "5 — SMB Attacks on the DC and Writing Snort Rules"
tags:
  - training
  - incident-response
  - smb
  - lateral-movement
  - snort
---

# 5 — SMB Attacks on the DC and Writing Snort Rules { #dc-smb-and-snort-rules }

!!! abstract "Scope of this page"
    - Proving that malware spread from a client to the Domain Controller over SMB, and when
    - Telling apart three kinds of failed attempts on TCP 445: MS17-010 (EternalBlue), logon guessing, ADMIN$ access
    - Snort 2 rule syntax, line by line
    - Example rules for each case, adding them to `local.rules`, and testing them against the PCAP

## Lateral movement to the DC over SMB { #smb-lateral }

The DC is infected when the infected client copies an executable to it over SMB (TCP 445, Windows file sharing) and runs it remotely. The time of that write is "when was the DC infected"; the files that crossed SMB are the "files in the SMB traffic".

```bash
zeek-cut -u ts id.orig_h id.resp_h action path name size < zeek_out/smb_files.log
tshark -r case.pcap -Y "smb2.filename || smb.file" -T fields -e frame.time_utc -e ip.src -e ip.dst -e smb2.cmd -e smb2.filename -e smb.file | sort -u | grep -i -E "\.exe|\.dll"
tshark -r case.pcap -Y "svcctl" -T fields -e frame.time_utc -e ip.src -e ip.dst -e _ws.col.Info
```

- `action` `SMB::FILE_WRITE`: a file was written. A `path` of `\\<DC>\ADMIN$` or `C$` is an administrative share.
- `smb2.filename` / `smb.file`: file names in SMB2 and the older SMB1. `smb2.cmd` 5 = Create, 9 = Write.
- `svcctl`: the remote Service Control protocol. `CreateServiceW` and `StartServiceW` mean the copied file was started as a service (PsExec-style).

```text
2019-xx-xxTxx:xx:xx  <client IP>  <DC_IP>  SMB::FILE_WRITE  \\<DC>\ADMIN$  <random>.exe  xxxxxx
```

Strong confirmation: after that time, the DC itself starts talking to the internet.

```bash
zeek-cut -u ts id.orig_h id.resp_h id.resp_p service < zeek_out/conn.log | awk -F'\t' '$2=="<DC_IP>" && $3 !~ /^172\.|^10\.|^192\.168\./'
```

Carve and hash the SMB files with `--export-objects smb,objs_smb` and compare their SHA256 with the HTTP downloads (`uniq -w64 -D`, see [Hashing](files-and-hashes.md#hashing)). The family whose file reached the DC is the one that infected the DC.

Wireshark: filter `smb2.filename contains ".exe" || smb.file contains ".exe"` → `Create Request File: <name>.exe` then `Write Request`; filter `svcctl`; **File → Export Objects → SMB**; for DC outbound traffic, `ip.src==<DC_IP> && !(ip.dst==172.16.0.0/12 || ip.dst==10.0.0.0/8 || ip.dst==192.168.0.0/16)`.

!!! note "Export Objects → SMB"
    Only files captured completely are saved correctly. A file much smaller than expected was only partly captured; say so in the answer.

## Failed attempts on TCP 445 { #failed-445 }

SMB commands and the DC's status codes tell the three common cases apart. Decide from the PCAP, not from the list.

| Candidate | What the traffic shows | Sign of failure |
| --- | --- | --- |
| MS17-010 exploit (EternalBlue) | Old SMB1; large/many `NT Trans` and `Trans2 Secondary` requests; `Trans2 SESSION_SETUP` (checking for the DoublePulsar backdoor) | DC refuses SMB1, or is patched and returns errors |
| Logon guessing (password spraying/brute force) | Repeated Session Setup requests | `STATUS_LOGON_FAILURE` (0xc000006d) |
| Copy and remote execution (PsExec-style) | Tree Connect to `\\DC\ADMIN$` or `C$`, `.exe` write, `svcctl` | `STATUS_ACCESS_DENIED` (0xc0000022) |

```bash
grep "<DC_IP>:445" snort_out/alert | grep -oE "\] ET [^\[]*" | sort | uniq -c
tshark -r case.pcap -Y "ip.addr==<DC_IP> && tcp.port==445 && (smb || smb2)" -T fields -e frame.number -e frame.time_utc -e ip.src -e _ws.col.Info -e smb.nt_status -e smb2.nt_status
tshark -r case.pcap -Y "ip.dst==<DC_IP> && (smb.cmd == 0xa0 || smb.cmd == 0x33 || smb.trans2.cmd == 0x000e)" -T fields -e frame.number -e frame.time_utc -e ip.src -e _ws.col.Info
tshark -r case.pcap -Y "ip.src==<DC_IP> && (smb.nt_status != 0 || smb2.nt_status != 0)" -T fields -e frame.time_utc -e ip.dst -e _ws.col.Info | sort | uniq -c
zeek-cut -u ts id.orig_h id.resp_h path service share_type < zeek_out/smb_mapping.log
```

- Line 1: alert names with `ETERNALBLUE`, `MS17-010` or `DOUBLEPULSAR` point to the first candidate.
- Line 2: every SMB packet to/from the DC. `smb` = SMB1 (EternalBlue uses SMB1), `smb2` = SMB2/3. `_ws.col.Info` prints Wireshark's Info column. `nt_status` `0x00000000` = success; anything else is a failure code.
- Line 3: `smb.cmd == 0xa0` NT Trans (EternalBlue's large payload), `0x33` Trans2 Secondary (continuation), `smb.trans2.cmd == 0x000e` Trans2 SESSION_SETUP (DoublePulsar check).
- Line 4: every error the DC returned, counted.
- Line 5: shares the client tried to connect to. Also check `zeek_out/notice.log`.

Wireshark: filter `ip.addr==<DC_IP> && tcp.port==445` and read the Info column; **Statistics → Service Response Time → SMB / SMB2** for command counts; **Analyze → Expert Information** for error responses; **Follow → TCP Stream** on the suspicious packets. Answer template: [failed attempt](report-templates.md#failed-attempt-template).

## Snort rule syntax { #snort-rules }

```text
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"..."; flow:to_server,established; content:"|FF|SMB"; offset:4; depth:4; classtype:attempted-admin; sid:1000001; rev:1;)
```

A rule is a **header** (before the brackets) and **options** (inside).

- `alert`: raise an alert when everything matches.
- `tcp`: TCP packets only.
- `$HOME_NET any`: source IP and port. `$HOME_NET` is the internal-network variable in `snort.conf`; `any` = any port.
- `->`: direction (left to right).
- `$HOME_NET 445`: destination IP and port. Use `<DC_IP> 445` to watch only the DC.
- `msg:"..."`: the alert name.
- `flow:to_server,established`: only packets sent to the server on an established connection (fewer false positives).
- `content:"|FF|SMB"`: bytes that must be present. Inside `| |` is hex, outside is text. `FF 53 4D 42` starts an SMB1 header, `FE 53 4D 42` (`|FE|SMB`) an SMB2 header.
- `offset:4; depth:4`: look from byte 4 (counting from 0) of the TCP payload, within 4 bytes. On port 445 the first 4 bytes are the NetBIOS session (length) header, then the SMB header starts.
- `classtype`: alert category. `sid`: rule ID (1,000,000 and above for your own rules). `rev`: revision.
- Every option ends with `;`, and the whole rule is one line.

## Example rules { #example-rules }

Use the rule that matches what you found in [Failed attempts on TCP 445](#failed-445).

**A. MS17-010 (EternalBlue) attempt**: SMB1 NT Trans requests, or the Trans2 SESSION_SETUP used by DoublePulsar.

```text
alert tcp any any -> $HOME_NET 445 (msg:"LOCAL SMBv1 NT Trans request - possible MS17-010 EternalBlue"; flow:to_server,established; content:"|FF|SMB|A0|"; offset:4; depth:5; classtype:attempted-admin; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET 445 (msg:"LOCAL SMBv1 Trans2 SESSION_SETUP - possible DoublePulsar check"; flow:to_server,established; content:"|FF|SMB|32|"; offset:4; depth:5; content:"|0E 00|"; offset:65; depth:2; classtype:attempted-admin; sid:1000002; rev:1;)
```

- `|FF|SMB|A0|`: SMB1 marker + command `A0` (NT Trans). `|FF|SMB|32|`: command `32` (Trans2).
- `|0E 00|` at `offset:65`: Trans2 subcommand `0x000e` (SESSION_SETUP), little-endian. 65 = NetBIOS 4 + SMB1 header 32 + word count 1 + the 28 bytes of parameters before the setup word. Check it in Wireshark by clicking the `Subcommand` field and reading its position in the bytes pane.

**B. Repeated logon failures**: alert when the DC returns `STATUS_LOGON_FAILURE` many times in a short period.

```text
alert tcp $HOME_NET 445 -> any any (msg:"LOCAL SMB2 repeated logon failures from server"; flow:from_server,established; content:"|FE|SMB"; offset:4; depth:4; content:"|6D 00 00 C0|"; offset:12; depth:4; detection_filter:track by_dst, count 5, seconds 60; classtype:unsuccessful-user; sid:1000003; rev:1;)
```

- `flow:from_server`: this time watch the DC's responses.
- `|6D 00 00 C0|` at `offset:12`: the SMB2 header's status field, `0xC000006D` written little-endian.
- `detection_filter:track by_dst, count 5, seconds 60`: alert once the same destination (the client that is guessing) gets more than 5 in 60 seconds.

**C. Access to the ADMIN$ share**: an SMB2 Tree Connect to `ADMIN$`.

```text
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"LOCAL SMB2 Tree Connect to ADMIN$ share"; flow:to_server,established; content:"|FE|SMB"; offset:4; depth:4; content:"|03 00|"; offset:16; depth:2; content:"A|00|D|00|M|00|I|00|N|00|$|00|"; classtype:policy-violation; sid:1000004; rev:1;)
```

- `|03 00|` at `offset:16`: SMB2 command 3 (Tree Connect).
- `A|00|D|00|…`: Windows sends paths as UTF-16 (2 bytes per character), so a `00` sits between the letters.

!!! warning "Test before you submit"
    The offsets above come from the SMB header layouts. Always confirm them against the real packets in Wireshark and run the rule over the PCAP before handing it in.

## Testing rules { #testing-rules }

```bash
sudo nano /etc/snort/rules/local.rules
grep -n "local.rules" /etc/snort/snort.conf
sudo snort -T -c /etc/snort/snort.conf
sudo snort -q -k none -A console -r case.pcap -c /etc/snort/snort.conf | grep LOCAL
```

- Line 1: paste the rule into `local.rules` and save (nano: Ctrl+O, then Ctrl+X).
- Line 2: check `snort.conf` includes `local.rules`. Remove a leading `#` if it is commented out.
- Line 3: `-T` is test mode. It reports the line of any syntax error; `Snort successfully validated the configuration!` means the rules load.
- Line 4: `-A console` prints alerts to the screen; `grep LOCAL` shows only your rules.

```text
xx/xx-xx:xx:xx.xxxxxx  [**] [1:1000001:1] LOCAL SMBv1 NT Trans request - possible MS17-010 EternalBlue [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 172.xx.xx.xx:49xxx -> <DC_IP>:445
```

No alert? Compare the bytes and offsets in your rule with the real packet, check `$HOME_NET` covers the lab network (`grep "ipvar HOME_NET" /etc/snort/snort.conf`), and increase `rev` each time you change a rule.

## Finding rule bytes in Wireshark { #bytes-in-wireshark }

1. Click the attack packet you found.
2. In Packet Details, click `SMB Header → SMB Command` (or SMB2 `Command`, `NT Status`). The bytes pane highlights those bytes.
3. Right-click → **Copy → …as Hex** and paste into `content:"|…|"`.
4. The **NetBIOS Session Service** line is the start of the TCP payload (offset 0). Count bytes from there to get `offset`.

!!! note "About these pages"
    Personal study notes. Not official guidance of any organisation.
