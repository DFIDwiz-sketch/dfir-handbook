---
title: File Analysis
tags:
  - training
  - blue-team
  - files
  - file-analysis
---

# File Analysis { #file-analysis }

!!! abstract "In one line"
    Sooner or later every alert hands you a file — a download pulled from a capture, an email attachment, something an EDR quarantined — and the first questions are always "what is this really?" and "is it dangerous?". This section answers them without trusting names, extensions or `Content-Type`: identifying files by their bytes (`file`, hex dumps, magic bytes, nested files, polyglots, encodings), extracting clues with `strings`, handling suspect files safely, the file types attackers use most (executables, scripts, Office, RTF, PDF), hashing and code signatures, and quick triage of good vs bad.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Identifying Files — Bytes, the file Command, Magic Bytes, Nested Files, Polyglots, Unicode and Encodings](file-identification.md) | A file is just bytes; name, extension and `Content-Type` are claims; reading `hexdump -C`, `xxd` and PowerShell `Format-Hex` column by column; `file *` on six samples (PE32+, ELF, PNG, SVG, PDF, DLL) line by line, text and scripts, `-i`/`-k`/`-z`/`--extension`, how `file` decides and how it is fooled; magic-byte table (MZ, PK, gzip, %PDF-, {\rtf1, PNG, ELF, OLE, LNK, ISO at 0x8001); MZ/DOS stub/PE header and compile time byte by byte; DOCX = ZIP with `unzip -l`; spotting a ZIP inside a `.doc`, `grep -obUaP`, `dd` carving, binwalk/foremost/scalpel and false positives (T1027.009, T1036.008); polyglots, MalDoc in PDF and 2025 polyglot campaigns; Unicode code points, UTF-8/16/32 bytes, how 学 becomes `E5 AD A6`, BOMs and UTF-16LE, mojibake, look-alikes and right-to-left override (T1036.002); a triage routine; practice questions |
| 2 | [Strings — Printable Runs, the strings Command, Encodings and Byte Order, and How Strings Help Triage](strings.md) | What a string is (a run of printable bytes; ~37% of random bytes look printable), plaintext vs binary files; `strings` options (`-n`, `-t x`, `-e s/S/l/b/L/B`, `-a`, `-f`) and Sysinternals Strings; worked example line by line (DOS stub, `MSVBVM60.DLL`, a unique marker, Run key T1547.001, fake IE8 user agent) and why ASCII mode misses UTF-16LE in the hex dump; byte order and the `-e l` second pass (C2 URL T1071.001, look-alike drop path T1036.005); IOC grep habit, `--unicode`; IOC categories table; static vs dynamic analysis; why sandboxes show memory-scraped strings; packing (UPX, T1027.002), string obfuscation (T1027, T1140) and compression (gzip/DOCX); strings on PCAPs, PDFs, images and memory; recap of file identification; practice questions |
| 3 | [Handling Suspect Files Safely — Analysis Environment, Moving Malware, and the Dangerous File Types](safe-handling-file-types.md) | Four rules for a safe lab (expendable machine, isolated network, hardened host, snapshot-and-revert VM with `VBoxManage` line by line); analysing on an OS that can't run the file (mismatch table, PowerShell 7 on Linux); moving samples in an `infected` AES ZIP with `7z`, what `7z l -slt` still leaks and `-mhe=on`; which file types are dangerous and why; the PE family (`.scr`, `.cpl`, `.dll`, `.ocx`, `.sys`, `.efi`, `.ax`, `.acm`, `.mui`, `.tsp`, `.com`) with `file` output and a 4688 for `rundll32 Control_RunDLL` (T1218.002); MSI/MSP (T1218.007), SFX and `.jar` with `unzip -l`; scripts and their interpreters (T1059.x, T1218.005), an obfuscated `.js` fragment and `wscript.exe` from `Temp1_*.zip`; Office: links, embedded objects, exploits (CVE-2017-11882, Follina, T1221) and macros, OLE vs OOXML, `file` metadata, `olevba` output line by line, `WINWORD.EXE` → `powershell -enc`, Mark of the Web `Zone.Identifier` and the 2022 macro block, what attackers did next; triage routine; practice questions |
| 4 | [RTF, PDF and Other Files as Exploits — and Quickly Sorting Good from Bad](rtf-pdf-misc-triage.md) | RTF without macros but with OLE objects, links and exploits; `.doc` that is really RTF and `file` output; the test RTF in hex and line by line (control words, groups, `\*` destinations, `\object`/`\objemb`/`\objclass Package`/`\objdata`, `\objupdate`, `\*\template` T1221, the `{\rt` header trick); decoding the OLE1 header and grepping hex for `4d5a9000` and the DOS sentence; `rtfobj` output line by line; CVE-2017-0199, -11882/-0802, -8570, -21716 and a 4688 for `WINWORD.EXE` → `mshta.exe` (T1203, T1218.005); PDF weaponisation (links, QR, embedded files, JavaScript, `/OpenAction`/`/AA`/`/Launch`, Flash, forms); PDF structure; `strings` on a test PDF object by object, `grep http` and a compressed stream that hides a URL; `pdfid` output line by line, hex-escaped names, `pdf-parser`; PDF attacks in endpoint logs; why pictures, fonts, media and email can be exploits (kernel font parsing, preview panes, CVE table incl. libwebp and Outlook CVE-2023-23397); `.lnk` launchers parsed field by field (T1204.002, T1547.009, T1027.012) and CVE-2025-9491; the six-step good-vs-bad routine applied to both test files; practice questions |
| 5 | [Hashing and Code Signatures — Hash Lookups, Authenticode, sigcheck, and Whether Signed Means Safe](hashing-signatures.md) | Cryptographic hashes (deterministic, avalanche, one-way, collision-resistant; the meat-grinder picture and the pigeonhole principle); `md5sum`/`sha1sum`/`sha256sum` on two files one byte apart, the empty-input hash, `Get-FileHash` and `certutil -hashfile`; hashes in Sysmon, EDR and Zeek; reading a lookup (known bad, known with no detections and the first-seen date, unknown); a deny list, not a clean verdict; what lookups and uploads reveal; MD5 vs SHA-1 vs SHA-256, chosen-prefix collisions, imphash and fuzzy hashes; Authenticode step by step (certificate, Authenticode hash, signing, PKCS#7 certificate table, timestamp, chain to Trusted Root vs Trusted Publishers), CVE-2013-3900, revocation, catalog signing, script signature blocks; `sigcheck -a -h -vt` line by line incl. a lone ML false positive and a renamed unsigned look-alike (T1036.003, T1036.005); `Get-AuthenticodeSignature` line by line; Sysmon 7 and code-integrity events; does signed mean safe (own, stolen, abused-service and collision routes, T1553.002, T1588.003, T1587.002, T1195.002; 2022 wiper, 2017 research, 2009 MD5 demo, Flame, rogue drivers, cloud signing abuse); practice questions |

!!! info "Coming next"
    Visual inspection, detecting malicious scripts, files that contribute to malicious behaviour, and the section summary.

## Things to remember { #must-know }

1. The bytes are the evidence. Names, extensions and `Content-Type` are claims an attacker controls.
2. `file` first, then a hex view: confirm the magic bytes with your own eyes.
3. Know `MZ`, `PK\x03\x04`, `%PDF-`, `\x7fELF`, `\x89PNG`, `{\rtf1`, `1F 8B` and `D0 CF 11 E0` on sight.
4. DOCX/XLSX/PPTX are ZIPs; old `.doc`/`.xls` are OLE.
5. `file` sees only the start. Scan for signatures anywhere to find nested files, and validate each hit.
6. One file can be two valid types. What it "is" depends on the program that opens it.
7. Windows strings are usually UTF-16LE; always run `strings` twice (`-e s` and `-e l`), and treat few strings as a packing warning, not a clean bill.
8. Identify files on an isolated analysis machine, never by opening them.

## Related { #related }

- [HTTP(S) Analysis & Attacks](../http-analysis/index.md) — file extraction, sandboxes and Base64
- [Important Events](../important-events/index.md) — process creation when a file runs
- [Zeek files.log & pe.log](../../../network/zeek/files-log.md)
- [Phishing delivery & initial execution](../../../adversary/phishing-delivery.md)
