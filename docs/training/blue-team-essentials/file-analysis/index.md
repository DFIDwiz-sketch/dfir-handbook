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

!!! info "Coming next"
    Safe handling of suspect files and dangerous file types (executables, scripts, Office documents), RTF/PDF/misc files and quick triage, hashing and code signatures, visual inspection and malicious scripts.

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
