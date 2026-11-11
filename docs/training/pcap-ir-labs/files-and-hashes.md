---
title: "3 — Downloads, Files and Hashes"
tags:
  - training
  - incident-response
  - zeek
  - file-extraction
  - hashing
---

# 3 — Downloads, Files and Hashes { #files-and-hashes }

!!! abstract "Scope of this page"
    - Listing every download, with full URL and size
    - Extracting files from HTTP, SMB, TFTP, FTP and email without opening them
    - Safe handling, real file type, and the MD5/SHA1/SHA256 workflow
    - Zeek `uid` and `fuid`: following one download across logs ("Bro UID" questions)
    - The key facts to record for each download, and reading macros in Word documents

## Listing downloads { #listing-downloads }

Zeek decides a file's type from its **content**, not its name. A Windows executable renamed `radiance.png` still shows as `application/x-dosexec`.

```bash
zeek-cut -u ts id.orig_h id.resp_h host uri resp_fuids resp_mime_types < zeek_out/http.log | grep -i -E "dosexec|msword|officedocument|zip|octet"
zeek-cut -u ts source mime_type filename seen_bytes md5 < zeek_out/files.log
zeek-cut -u ts id.orig_h id.resp_h command arg file_size < zeek_out/ftp.log
```

- `resp_mime_types`: the real type of what the server returned. `dosexec` = Windows executable, `msword`/`officedocument` = Word document.
- `resp_fuids`: the file ID of that response (see [Zeek UID and fuid](#zeek-uid)).
- `files.log` `source`: which protocol carried the file (HTTP, FTP_DATA, SMB…). `seen_bytes`: how many bytes Zeek saw.
- `ftp.log`: `RETR <file>` is an FTP download.

Counting downloads: count only files of concern (executables, scripts, archives, documents). The same file fetched twice has the same hash, so count it once and say so.

Wireshark: **File → Export Objects → HTTP / SMB / TFTP** and read Hostname, Content Type, Size and Filename. **Statistics → HTTP → Request Sequences** shows which page led to which request.

## Full URL and file size { #url-and-size }

```bash
zeek-cut host uri resp_mime_types < zeek_out/http.log | grep dosexec | awk -F'\t' '{print "http://"$1$2}' | sort -u
zeek-cut -u ts host uri status_code response_body_len resp_mime_types < zeek_out/http.log | grep dosexec
tshark -r case.pcap -Y 'http.response && http.content_type contains "application"' -T fields -e frame.number -e http.response_for.uri -e http.content_type -e http.content_length
stat -c "%s bytes  %n" "http_objs/<file>"
```

- Line 1: build answer-ready URLs: `http://` + host + uri. `sort -u` removes duplicates.
- `response_body_len`: body size the server sent (bytes).
- `http.response_for.uri`: the full URL a response belongs to. `http.content_length`: the size the server declared.
- `stat -c "%s bytes %n"`: the real size of the carved file. If the declared and carved sizes differ, part of the transfer is missing from the capture; report both.
- In Wireshark, the Packet Details of a request show **[Full request URI]**; right-click → **Copy → Value**.

## Extracting files { #extracting }

```bash
for p in http smb tftp imf; do mkdir -p objs_$p; tshark -r case.pcap -q --export-objects $p,objs_$p; done
ls -l objs_*
```

- `--export-objects <protocol>,<folder>`: write every transferred file to the folder, without opening it.
- `imf`: email messages, saved as `.eml` (read them as text to see sender, subject and attachment names).

Zeek can carve files too, and names them with the file ID:

```bash
mkdir zeek_x && cd zeek_x
zeek -C -r ../case.pcap local frameworks/files/extract-all-files
ls extract_files/          # extract-<time>-HTTP-<fuid>
cd ..
```

FTP sends commands on port 21 and file contents on a separate data connection. tshark finds the file names; Wireshark saves the contents:

```bash
tshark -r case.pcap -Y 'ftp.request.command == "RETR"' -T fields -e frame.time_utc -e ip.src -e ip.dst -e ftp.request.arg
```

Wireshark: **File → Export Objects → HTTP / SMB / TFTP / IMF** → **Save** or **Save All**. For FTP data or raw TCP (for example netcat): filter `ftp-data` (or find the large stream in **Statistics → Conversations → TCP**) → **Follow → TCP Stream** → **Show data as: Raw** → **Save as…**.

## Handling samples safely { #safe-handling }

"Safely get the hash" means you never open or run the file and you work where a mistake cannot hurt anything.

1. **Isolated analysis VM**: Linux, no internet or LAN access, snapshot taken first. Linux has no Microsoft Office, so even a double-click cannot run a macro.
2. **Extract, do not open**: carve the file from the PCAP with tshark, Zeek or Export Objects.
3. **Rename and remove execute permission** so nothing opens or runs it by accident.
4. **Check the real type by content.**
5. **Hash** (MD5, SHA1, SHA256).
6. **Look up the hash only** on VirusTotal. Uploading the file can tip off the attacker and can expose internal data inside the document.
7. **Store** it in a password-protected zip and **revert the snapshot** when finished.

```bash
mkdir -p ~/case/doc && cd ~/case/doc
tshark -r ~/case/case.pcap -q --export-objects http,objs
file objs/* | grep -i -E "word|composite|zip|pe32"
cp "objs/<name>" evidence.bin
chmod a-x evidence.bin
md5sum evidence.bin; sha1sum evidence.bin; sha256sum evidence.bin
zip -P infected evidence.zip evidence.bin
```

- `cp … evidence.bin`: a `.bin` extension stops the desktop opening it in Word. Renaming does not change the content, so the hash is the same.
- `chmod a-x`: remove (`-`) execute (`x`) for all users (`a`).
- `zip -P infected`: the industry convention for sharing malware samples; stops antivirus deleting it and people opening it by accident.

The [safe-handling answer template](report-templates.md#safe-handling-template) turns these steps into a written answer.

## Identifying the real file type { #file-type }

```bash
file objs_http/*
```

```text
objs_http/<doc>        : Composite Document File V2 Document ...      ← old .doc
objs_http/<docx>       : Microsoft Word 2007+                          ← .docx/.docm
objs_http/<file>       : PE32 executable (GUI) Intel 80386, for MS Windows
objs_http/radiance.png : PE32 executable ...                           ← exe disguised as an image
objs_http/<payload>    : data                                          ← possibly encrypted
```

- A name ending `.png` with `PE32 executable` content is an executable disguised as an image.
- `data` with a size of hundreds of KB, from an exploit kit server, is often an **encrypted payload**: the victim decrypts it after download, so the PCAP alone cannot give the real EXE hash. Say "hash of the payload as transferred" in the answer, and ask whether a host-recovered EXE exists.
- In **Follow → HTTP Stream**, a Windows executable body starts with `MZ` (and contains "This program cannot be run in DOS mode"); a real PNG starts with `.PNG`.

## Hashing { #hashing }

```bash
for f in objs_http/*; do if file "$f" | grep -q PE32; then echo "== $f"; md5sum "$f"; sha1sum "$f"; sha256sum "$f"; fi; done > exe_hashes.txt
zeek-cut fuid mime_type md5 sha1 < zeek_out/files.log | grep -i -E "dosexec|msword|officedocument"
sha256sum objs_http/* objs_smb/* | sort | uniq -w64 -D
```

- Loop: for each file, if `file` says `PE32` (`grep -q` only answers yes/no), print a separator and the three hashes; save everything to `exe_hashes.txt`.
- Zeek with `local` already computed MD5 and SHA1; they must match yours (SHA256 is not on by default).
- Last line: `uniq -w64 -D` prints every line whose first 64 characters (a SHA256) repeat, i.e. the same file seen over HTTP **and** SMB. This is how you prove which download was later copied to another host.
- Windows: `Get-FileHash -Algorithm MD5 <file>` (also SHA1, SHA256).

Wireshark has no hash function: save from Export Objects, then hash in a terminal. Quote file names with special characters (`%`, `&`, `?`).

## Zeek UID and fuid { #zeek-uid }

Bro is Zeek's old name (renamed in 2018), so a "Bro UID" is Zeek's `uid` field. Zeek gives every **connection** a `uid` starting with `C` and every **file** a `fuid` starting with `F`. These IDs join the logs together.

```bash
zeek-cut -u ts uid id.orig_h id.resp_h host uri resp_fuids resp_mime_types < zeek_out/http.log | grep -i dosexec
zeek-cut fuid conn_uids mime_type < zeek_out/files.log | grep dosexec    # Bro / Zeek 5 and older
zeek-cut fuid uid mime_type < zeek_out/files.log | grep dosexec          # Zeek 6+
cd zeek_out && grep -l <UID> *.log && grep <UID> *.log
grep -l <fuid> *.log; ls ../zeek_x/extract_files/ | grep <fuid>
```

- `uid` in the `http.log` line of the executable = the connection that carried it (the "Bro UID").
- `grep -l <UID> *.log`: names of every log that mentions that connection, typically `conn.log`, `http.log`, `files.log`.
- Following the `fuid` adds `files.log`, `pe.log` (Zeek's analysis of a Windows executable: compile time, 32/64-bit) and the carved file `extract-…-<fuid>`.

```text
conn.log
files.log
http.log
```

Wireshark has no Zeek UID, but numbers each TCP connection with `tcp.stream`:

1. Get the client port of that UID: `zeek-cut uid id.orig_p < zeek_out/conn.log | grep <UID>`.
2. Filter `ip.addr==<infected IP> && tcp.port==<id.orig_p>`.
3. Read **Transmission Control Protocol → [Stream index: N]**.
4. Filter `tcp.stream eq N`: the same connection as the Zeek UID.

## Key information for a download { #download-key-info }

Time, source IP/port, destination IP/port, protocol and bytes are all in the `conn.log` line of the download's UID; protocol details are in `http.log` with the same UID.

```bash
zeek-cut -u ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes < zeek_out/conn.log | grep <UID>
zeek-cut -u ts uid method host uri status_code user_agent response_body_len resp_mime_types < zeek_out/http.log | grep <UID>
tshark -r case.pcap -q -z "conv,tcp,tcp.stream eq N"
tshark -r case.pcap -Y "http.response && ip.dst==<infected IP>" -T fields -e http.server -e http.last_modified -e http.content_type | sort -u
```

- `id.orig_h/p` = source IP/port (the infected host); `id.resp_h/p` = destination IP/port (the server).
- `proto` = transport (tcp); `service` = application protocol (http).
- `orig_bytes` / `resp_bytes` = bytes sent / received; `resp_bytes` should be close to the file size.
- `-z "conv,tcp,<filter>"`: tshark's conversation table for just that stream (start time, duration, bytes each way).
- `Server` and `Last-Modified` headers describe the attacker's infrastructure.

For further investigation, record per download: UTC time, full URL, domain, server IP and port, file name, size, real type, MD5/SHA1/SHA256, User-Agent, server headers, and (outside the VM) who owns the server IP. These are the IOCs used to search proxy/firewall logs and EDR for other victims. Template: [download key information](report-templates.md#download-template).

Wireshark: filter `tcp.stream eq N` → **Statistics → Conversations → TCP** with **Limit to display filter** shows Address A/B, Port A/B, Bytes A→B / B→A, Rel Start and Duration in one row.

## Malicious Word documents and macros { #macros }

Malicious documents usually carry a VBA macro that runs when the document opens and downloads the next stage. **oletools** reads macros without running anything. Use it inside the isolated VM.

```bash
pip install oletools
oleid evidence.bin
olevba -a evidence.bin
olevba --decode evidence.bin
```

- `oleid`: whether the document has VBA macros, encryption, external links.
- `olevba -a`: only the analysis table, without the full code. `--decode`: also decode obfuscated strings (Base64, hex…).

```text
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|Shell               |May run an executable file or a system command|
|Suspicious|CreateObject        |May create an OLE object                     |
|IOC       |http://<domain>/<p> |URL                                          |
```

- `AutoExec` (`AutoOpen`, `Document_Open`): runs on open.
- `Shell`, `WScript.Shell`, `powershell`: runs Windows commands.
- `URLDownloadToFile`, `XMLHTTP`, an `IOC` URL: downloads from the internet.
- Together these mean a **macro downloader**. Match the IOC URL to the next download in the PCAP:

```bash
zeek-cut -u ts id.orig_h host uri resp_mime_types < zeek_out/http.log | awk -F'\t' '$2=="<infected IP>"' | grep -A5 -i -E "msword|officedocument"
```

`grep -A5` prints the document line and the 5 lines after it. In Wireshark, compare the User-Agent of requests after the document: macro or PowerShell downloads often have a non-browser User-Agent or none.

!!! note "About these pages"
    Personal study notes. Not official guidance of any organisation.
