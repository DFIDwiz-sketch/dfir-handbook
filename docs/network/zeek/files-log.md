---
title: files.log & pe.log
tags:
  - artifact
  - network
  - zeek
  - files
---

# Zeek `files.log` & `pe.log`

<div class="dfir-meta" markdown>
**Category:** Network · **Source:** Zeek · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    Every file Zeek sees moving through any protocol it understands (HTTP, SMTP, FTP, SMB, IRC, TLS certs…) gets a row here with its sniffed type, size, hashes and the connection(s) it rode in on; `pe.log` adds Windows-executable header details — so this is where "what was downloaded/uploaded/copied over the network, and is it malicious" gets answered without touching a pcap.

## `files.log` fields

| Field | Meaning | Analyst notes |
|---|---|---|
| `ts` | When the file was first seen | |
| `fuid` | File unique ID | Join key: `http.log resp_fuids/orig_fuids`, `smtp.log fuids`, `ssl.log cert_chain_fuids`, `smb_files.log fuid`, `pe.log id` |
| `uid` (Zeek 6+) / `conn_uids` (older) | Connection(s) that carried it | → [`conn.log`](conn-log.md) |
| `id.orig_h`, `id.resp_h` (6+) / `tx_hosts`, `rx_hosts` (older) | Sender / receiver | For HTTP download: `tx` = server, `rx` = client |
| `source` | Protocol: `HTTP`, `SMTP`, `FTP_DATA`, `SMB`, `SSL` (certs), `IRC_DATA`, `KRB` | |
| `depth` | Nesting depth (e.g. inside MIME) | |
| `analyzers` | Analyzers attached: `MD5`, `SHA1`, `SHA256`, `PE`, `EXTRACT`, `X509` | If hashes are blank, the analyzer wasn't loaded |
| `mime_type` | **Sniffed** type by magic bytes | Trust this over the HTTP header / filename |
| `filename` | From `Content-Disposition`, URI, SMB path, MIME | Often blank for HTTP |
| `duration` | Transfer time | |
| `local_orig` | Whether the sender is local | |
| `is_orig` | File sent by connection originator? | `T` = **upload** from client, `F` = download |
| `seen_bytes` / `total_bytes` | Bytes Zeek saw / declared size | Different → truncated (`missing_bytes`, `overflow_bytes`) |
| `missing_bytes`, `overflow_bytes`, `timedout` | Gaps / oversize / timeout | Hash is unreliable if any are non-zero |
| `parent_fuid` | Container file | e.g. attachment inside an email |
| `md5`, `sha1`, `sha256` | Hashes (if analyzers on) | **Search threat intel with these** |
| `extracted` | Path of extracted copy (if `EXTRACT` on) | `extract_files/HTTP-FdvK1A3z4tPEujBU9c.exe` |
| `extracted_cutoff`, `extracted_size` | Truncation info for extraction | |

## `pe.log` fields (Windows PE files only)

| Field | Meaning | Analyst notes |
|---|---|---|
| `id` | = `fuid` | |
| `machine` | `I386`, `AMD64`, `ARM64` | |
| `compile_ts` | PE header timestamp | Future / very old / matches other samples → forged or family marker |
| `os`, `subsystem` | `Windows XP`+, `WINDOWS_GUI` / `WINDOWS_CUI` (console) | A "GUI" app that is actually a console loader; `NATIVE` = driver |
| `is_exe`, `is_64bit` | | `is_exe=F` = DLL/driver |
| `uses_aslr`, `uses_dep`, `uses_code_integrity`, `uses_seh` | Security mitigations | Malware & old tools often lack ASLR/DEP |
| `has_import_table`, `has_export_table`, `has_cert_table`, `has_debug_data` | Presence of tables | No import table → packed; `has_cert_table=T` → signed (check the sig on host) |
| `section_names` | Section names | `.text .rdata .data .rsrc .reloc` normal; `UPX0`, `.vmp0`, `.themida`, random names → packed |

## Enabling hashes and extraction

By default only MD5 runs (sometimes nothing, depending on distro). In `local.zeek` or on the command line:

```zeek
@load policy/frameworks/files/hash-all-files      # md5 + sha1 + sha256 for every file
@load policy/frameworks/files/extract-all-files   # write every file to extract_files/ (disk!)
# Or extract only executables:
event file_sniff(f: fa_file, meta: fa_metadata) {
    if ( meta?$mime_type && meta$mime_type == "application/x-dosexec" )
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
}
redef FileExtract::prefix = "/data/zeek/extract/";
redef FileExtract::default_limit = 50000000;      # 50 MB cap per file
```

```bash
zeek -C -r capture.pcap local policy/frameworks/files/hash-all-files policy/frameworks/files/extract-all-files
ls extract_files/            # HTTP-F..., SMTP-F..., SMB-F...  (named by source + fuid)
```

## Quick queries

=== "zeek-cut / shell"

    ```bash
    # All executables, scripts, archives and Office docs that crossed the wire
    zeek-cut -d ts fuid source id.orig_h id.resp_h mime_type filename total_bytes sha256 < files.log \
      | grep -E 'x-dosexec|x-msdownload|x-executable|zip|x-rar|x-7z|msword|officedocument|vnd.ms-|x-shellscript|hta|javascript|x-powershell'

    # Uploads (is_orig = T) leaving the network — exfil / web-shell uploads
    zeek-cut -d ts source id.orig_h id.resp_h mime_type total_bytes filename < files.log | awk -F'\t' '$0 ~ /\tT\t/'   # (add is_orig to the cut)

    # SMB file copies between internal hosts (lateral movement, staging)
    zeek-cut -d ts id.orig_h id.resp_h filename mime_type total_bytes < files.log | awk -F'\t' '$1 ~ /SMB/ || 1' | grep -F 'SMB'
    # better: smb_files.log
    zeek-cut -d ts id.orig_h id.resp_h action path name size < smb_files.log | grep -E 'WRITE|OPEN' | grep -iE '\.(exe|dll|ps1|bat|vbs|sys)\b'

    # Hash list for VT / intel lookup
    zeek-cut sha256 mime_type < files.log | awk '$2 ~ /dosexec|zip|msword|officedocument/ && $1!="-" {print $1}' | sort -u > hashes.txt

    # PE: unusual sections / no ASLR / console apps downloaded via HTTP
    zeek-cut id machine compile_ts subsystem uses_aslr has_import_table section_names < pe.log \
      | awk -F'\t' '$5=="F" || $6=="F" || $7 !~ /\.text/'

    # From a file back to the URL that served it
    grep -F 'FdvK1A3z4tPEujBU9c' http.log | zeek-cut -d ts id.orig_h host uri user_agent
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:files mime_type IN ("application/x-dosexec","application/x-msdownload","application/zip","application/x-rar","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    | stats values(filename) as names values(source) as proto dc(id.resp_h) as receivers count by sha256, mime_type, total_bytes
    | sort - count
    ```

    Groups every risky file type by its hash, listing the filenames it travelled under (`values(filename)`) and how many machines received it (`dc(id.resp_h)`). One hash arriving at many hosts under different names is a worm or a tool being pushed around during lateral movement.

    ```spl
    index=zeek sourcetype=zeek:files is_orig=true local_orig=true
    | eval MB=round(total_bytes/1024/1024,2)
    | stats sum(MB) as total_MB count by id.orig_h, id.resp_h, source
    | where total_MB > 50
    ```

    `is_orig=true` means the *client* sent the file (an upload); `local_orig=true` means that client is inside your network. Summing uploaded megabytes per internal→external pair and keeping those over 50 MB is a simple exfiltration hunt.

## Analysis tips

!!! tip "Hash → intel → host, in that order"
    Pull `sha256` for every executable/archive/Office file in the window, check them against VirusTotal/MISP/your EDR, then take each bad hash to **Amcache** (same SHA-1 — use `sha1` from `files.log`) and **Prefetch** on the receiving host to prove it landed and ran. That is a complete download→execution chain without opening a pcap.

- **Sniffed MIME is the truth**; the `filename` and HTTP `Content-Type` are attacker-controlled. `mime_type=application/x-dosexec` with `filename=invoice.pdf` is the finding.
- **Partial files**: if `missing_bytes > 0` or `timedout = T`, the hash will not match VT — the sensor dropped packets. Say so instead of claiming "unknown file".
- **SMB copies show up twice**: `files.log` (`source=SMB`, if the file analyzer fires) and `smb_files.log` (`action=SMB::FILE_WRITE/OPEN/CLOSE`, `path=\\host\C$`, `name`). A `WRITE` of `*.exe` to `ADMIN$` followed by `dce_rpc.log` `CreateServiceW` / `StartServiceW` = **PsExec-style lateral movement** (see Adversary section).
- **Email attachments**: `source=SMTP`, `parent_fuid` set, `filename` from MIME; join to `smtp.log` (`mailfrom`, `rcptto`, `subject`, `fuids`) to get sender → recipient → attachment → hash in one line.
- **Certificates are files too** (`source=SSL`, `mime_type=application/x-x509-user-cert`) — that's why `x509.log` joins on `fuid`. Filter them out when counting "real" files.
- **`pe.log` fast red flags**: `compile_ts` within hours of `ts` (freshly built), section names not in the standard set, `has_import_table=F`, `uses_aslr=F` on a 64-bit binary, `subsystem=WINDOWS_CUI` for something that claimed to be an installer.
- **Extraction hygiene**: extracted malware is live malware — extract to an isolated analysis box, and remember `extract_files/` can fill a disk fast on a busy sensor; prefer the MIME-filtered extraction script above in production.
- **Missing everything?** Check `analyzers` — if it only says `X509` or is blank, the hash policies weren't loaded when the logs were generated. Re-run Zeek on the pcap with them.

## Correlation

| Question | Then look at |
|---|---|
| Where did it come from / go to? | `uid` → [`conn.log`](conn-log.md); `fuid` → [`http.log`](http-log.md) (`host`, `uri`), `smtp.log`, `smb_files.log`, `ftp.log` |
| Did it execute on the receiving host? | [Prefetch](../../windows/prefetch.md), [Amcache](../../windows/amcache.md) (SHA-1), `4688`/Sysmon `1`; `Zone.Identifier` in [$MFT](../../windows/mft-usn.md) carries the download URL |
| Is it known-bad? | VirusTotal, MalwareBazaar, MISP; Suricata file rules (`fileinfo` events in `eve.json` share md5/sha256) |
| Did it spread? | `stats … by sha256` across `id.resp_h`; SMB writes to `ADMIN$`/`C$` in `smb_files.log` |
| What does it do? | Static/dynamic analysis of `extract_files/<fuid>`; `pe.log` for a first look |

## References

- [Zeek docs — files.log](https://docs.zeek.org/en/master/scripts/base/frameworks/files/main.zeek.html) · [pe.log](https://docs.zeek.org/en/master/scripts/base/files/pe/main.zeek.html)
- [Zeek File Analysis Framework](https://docs.zeek.org/en/master/frameworks/file-analysis.html)
- [MalwareBazaar (abuse.ch) — hash lookup](https://bazaar.abuse.ch/)
