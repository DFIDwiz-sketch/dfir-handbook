---
title: "Strings — Printable Runs, the strings Command, Encodings and Byte Order, and How Strings Help Triage"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
---

# Strings — Printable Runs, the strings Command, Encodings and Byte Order, and How Strings Help Triage { #strings }

!!! abstract "What this page covers"
    The cheapest way to make a suspicious file **talk without running it**. We define what a **string** is (a continuous run of bytes that all decode to printable characters), why "plaintext" and "binary" files behave so differently under the `strings` command, and then run `strings` on a small harmless test executable and read every output line — what is noise, what is a giveaway, and what is worth turning into a detection. We look at the same file in a hex dump to see **why** some text never shows up, then fix it with the encoding and byte-order options (`-e l`, `-e b`, `-e S`, `-t x`), because Windows stores most text as UTF-16 little-endian. Then we cover **how strings help** in practice: IOCs (domains, URLs, IPs, file paths, registry keys, user agents), static vs dynamic analysis, why sandboxes show strings you can't reproduce, what **packing** and **compression** do to strings, and using strings on PCAPs, PDFs and images. We close with a recap of the whole "file contents and identification" block. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs). The sample "executable" on this page is a harmless test file built for this page: it has a PE-like header and some planted text, and does nothing.

## The 8 key points { #key-points }

1. Every byte is a number from 0 to 255. An **encoding** (ASCII, UTF-8, UTF-16…) maps some of those numbers to characters. A **string** is a continuous run of bytes that all decode to **printable** characters; it ends at the first byte that doesn't.
2. A **plaintext** file (`.txt`, `.ps1`, `.vbs`, `.js`, `.bat`, `.svg`) is printable from start to end, so `strings` just gives you the file back. A **binary** file (`.exe`, `.dll`, `.zip`, `.docx`, `.jpg`) mixes printable runs with unprintable bytes, and that is where `strings` earns its keep.
3. `strings -n N` sets the minimum length. Short runs are mostly **coincidence** (random bytes that happen to be printable). Raise `-n` to cut noise; lower it when you are hunting for short indicators.
4. Most `strings` output is junk. You are scanning for a handful of **giveaways**: the DOS stub sentence (it's a Windows executable), imported DLL names (what it was built with, what it can do), URLs, domains, IPs, file paths, registry keys, user agents, and **unusual unique words** you can later hunt for.
5. **ASCII mode will never find UTF-16 text.** Windows programs store a lot of text as UTF-16LE (`h\0t\0t\0p\0`), which looks like single letters separated by nulls. Always run a second pass with `-e l` (16-bit little-endian), and know `-e b`, `-e L`, `-e B` and `-e S`.
6. Reading strings without running the file is **static analysis** — safe and fast. Running it in a sandbox is **dynamic analysis**. Sandboxes often show strings scraped from **memory** that `strings` on disk cannot see.
7. **Packed**, **encrypted** and **compressed** content hides strings. Few readable strings plus a packer marker (for example `UPX0`/`UPX1`) is itself a finding (T1027.002). Decompress archives first; use memory or a deobfuscating tool (FLOSS) for packed code.
8. `strings` works on almost anything: PCAPs (hosts, URLs, user agents, cookies), PDFs, images (metadata), memory dumps. It is a triage tool: every interesting string is a **lead to verify**, not a verdict.

## Why this matters in a SOC { #why }

Picture the alert from the previous page. A user downloaded `invoice_tool` from `files-share.example`, the bytes start with `MZ`, and `file` says it is a 32-bit Windows executable. You now know **what** it is. The next question is **what it does**: what will it contact, what will it drop, where will it hide? You want those answers **before** anyone double-clicks a second copy, and ideally without running it yourself.

A program has to carry its "addresses" with it. If malware is going to beacon to a URL, write itself into a Run key, or drop a file in `%APPDATA%`, that URL, key path and file name must be stored **somewhere inside the file** (or be built at run time from pieces that are). `strings` pulls every readable run of characters out of the file in seconds. It's like holding a sealed envelope up to a bright lamp: you can't read the whole letter, but the address, a phone number and a few words shine through. Technically, you are decoding the file's bytes with one encoding at a time and printing the runs that are long enough to be meaningful.

That gives you, very quickly:

- **Indicators** to block or hunt for (domains, IPs, URLs, file paths, registry keys, mutex names, user agents).
- **Capabilities** hinted at by imported libraries and API names (`WinHttpOpen`, `CreateRemoteThread`, `CryptEncrypt`).
- **Family clues**: odd unique words, debug paths (`C:\Users\dev\...\Release\loader.pdb`), version strings.
- **Warnings that something is hidden**: almost no strings, or packer section names.

## What strings are { #what-are-strings }

### Bytes, encodings and "printable" { #printable }

A file is a row of bytes, each a number from `0x00` to `0xFF`. On its own a byte isn't a letter. An **encoding** is the agreed table that says "this number means this character". In ASCII, for example:

| Character | `t` | `e` | `s` | `t` | `S` | `O` | `C` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Byte (hex) | `74` | `65` | `73` | `74` | `53` | `4F` | `43` |

ASCII only defines 128 values (`0x00`–`0x7F`), and of those only `0x20` (space) to `0x7E` (`~`) are **printable** characters. `0x00`–`0x1F` and `0x7F` are control codes (null, tab, newline, bell, escape…), and `0x80`–`0xFF` aren't ASCII at all. So in any random stretch of binary data, a byte has roughly a 37% chance (95 out of 256) of looking printable. That number explains everything about `strings` noise.

A **string** is a **continuous run of printable characters** in that byte sequence. The run stops at the first byte that isn't printable. Take these 11 bytes:

```
00 01 02 03 74 65 73 74 04 05 06
```

- `00 01 02 03` — control codes, not printable.
- `74 65 73 74` — `t`, `e`, `s`, `t`: four printable characters in a row.
- `04 05 06` — not printable, so the run ends.

The only string here is `test`. If one more printable byte had happened to sit right before it (say `41`, `A`), the string would be `Atest` — `strings` has no idea where a "word" starts; it only sees where printability starts and stops. You will see exactly this effect in the real output below.

### Plaintext vs binary files { #plaintext-binary }

People call files "plaintext" or "binary". The terms are about **printability**, not about danger:

- A **plaintext** file contains only printable characters (plus newlines and tabs) for some encoding. Scripts (`.ps1`, `.vbs`, `.js`, `.bat`, `.sh`), `.txt`, `.csv`, `.html`, `.svg`, `.xml`, most logs. Running `strings` on one gives you the file back, line by line — nothing gained. Just read it (safely, in a text viewer — see the next pages).
- A **binary** file contains bytes that are not text in any standard encoding: machine code, compressed data, image pixels, structured headers. Executables, DLLs, ZIP/DOCX/XLSX, JPEG/PNG, PCAPs. Here the readable bits are islands in a sea of unprintable bytes, and `strings` finds the islands for you.

Remember from the previous page that "plaintext" does not mean "harmless". A PowerShell script is plaintext and can do anything.

### The `strings` command { #strings-command }

On Linux, `strings` comes with GNU binutils. Basic use:

```
$ strings suspicious_file
```

It reads the file, and every time it finds a run of at least **4** printable characters (the default), it prints that run on its own line. Options you will use constantly:

| Option | What it does | When to use it |
| --- | --- | --- |
| `-n N` (or `-N`) | Minimum run length. Default 4 | `-n 8` or `-n 10` to cut noise on big binaries; `-n 4` when looking for short things |
| `-t x` / `-t d` / `-t o` | Print the **offset** of each string in hex / decimal / octal | When you want to jump to the string in a hex dump or carve around it |
| `-e s` | 7-bit single-byte characters (ASCII). **The default** | First pass |
| `-e S` | 8-bit single-byte characters (bytes `0x80`–`0xFF` count as printable too) | Latin-1/Windows-1252 text, raw UTF-8 bytes |
| `-e l` | 16-bit **little-endian** | **Windows UTF-16 text.** Always do this pass on Windows files |
| `-e b` | 16-bit big-endian | Java, some network formats, some non-x86 files |
| `-e L` / `-e B` | 32-bit little / big-endian | Rare (UTF-32) |
| `-a` | Scan the whole file | Already the default in modern binutils; see the caution below |
| `-f` | Print the file name before each string | Running over many files and grepping |

**[Supplement]** On Windows, the Sysinternals **Strings** tool (`strings64.exe`) does the same job and by default searches for **both** ASCII and Unicode (UTF-16LE) strings in one pass; `-a` restricts it to ASCII, `-u` to Unicode, `-n` sets the minimum length (default 3), and `-nobanner` suppresses the copyright header. Many analysts also use CyberChef's "Strings" operation or the tools covered in [the 2026 view](#trends).

## A worked example { #example }

Here is `strings` with a minimum length of 10 on the test executable `invoice_tool`:

```
$ strings -n 10 invoice_tool
!This program cannot be run in DOS mode.
MSVBVM60.DLL
ELORCHIDFALLOW
Software\Microsoft\Windows\CurrentVersion\Run
Mozilla/4.0 (compatible; MSIE 8.0)
```

The command:

- `strings` — the tool.
- `-n 10` — only print runs of **10 or more** printable characters. On a real executable the default of 4 would give you thousands of lines of coincidental garbage; 10 keeps mostly real text.
- `invoice_tool` — the file. No extension needed; `strings` doesn't care about names.

Line by line:

- `!This program cannot be run in DOS mode.` — the DOS stub message that sits near the start of **every** Windows PE file (you saw its bytes at offset `0x4e` on the previous page). The leading `!` isn't part of the sentence: it is byte `0x21`, the last byte of the tiny DOS machine-code stub (`cd 21` = "call DOS interrupt 21h"), which happens to be printable and sits right before `T`. If you didn't already know this file was an executable, this line alone would tell you. You will also see it inside PCAPs, memory dumps and documents when an executable is hidden inside them.
- `MSVBVM60.DLL` — a DLL name. A quick search shows it is the **Microsoft Visual Basic 6 virtual machine** runtime. So this program was very likely written in VB6 and will load that DLL when it runs. That matters: VB6 is ancient, rarely used by modern legitimate software, but still shows up in commodity malware and droppers. It also tells a reverse engineer which tools to reach for.
- `ELORCHIDFALLOW` — look closely: the real word is most likely `ORCHIDFALLOW`, and `EL` is two coincidentally printable bytes (`0x45`, `0x4c`) that happened to sit just before it. This is the "`strings` doesn't know where words start" effect from above. Why care about a nonsense word at all? Because a **unique, meaningless string** is gold for hunting: it might be a campaign marker, a mutex name, an XOR key or a developer's in-joke, and it probably appears in other samples of the same family. It is a good candidate for a YARA rule.
- `Software\Microsoft\Windows\CurrentVersion\Run` — a registry path. Programs listed under `HKCU\...\Run` or `HKLM\...\Run` start at every logon. Seeing it hard-coded in an unknown "invoice tool" strongly suggests the program plans to **persist** with a Run key — MITRE ATT&CK **T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**. Now you know what to look for on endpoints (registry event `Sysmon 13`, or `4657` with registry auditing; see [persistence](../../../adversary/persistence.md)).
- `Mozilla/4.0 (compatible; MSIE 8.0)` — a hard-coded HTTP **User-Agent** pretending to be Internet Explorer 8. No real browser in 2026 sends that. It's an excellent network indicator: search the proxy logs and Zeek `http.log` for exactly this value ([User-Agents](../http-analysis/user-agents-cookies.md)).

Notice what's **missing**: no URL, no domain, no dropped file name. A program that persists and speaks HTTP must contact *something*. Either the address is hidden, or it is stored in a way that ASCII mode can't see. The hex dump answers which.

### What the hex dump shows { #example-hex }

The start of the file:

```
$ hexdump -C -n 96 invoice_tool
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 80 00 00 00  |................|
00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|
00000050  69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|
```

- Row `00000000`: `MZ` is printable, but it is only **2** characters long and is followed by `90` (not printable). With `-n 10` it is dropped. Even with the default `-n 4` it would be dropped.
- Rows `0x10`–`0x30`: almost all `00` bytes. Nothing printable at all, so nothing for `strings` to print. That's why the output above jumps straight to the DOS sentence.
- Row `00000040`: `0e 1f ba 0e …` is DOS machine code. A few bytes are printable by accident (`!`, `L`, `!`), but each run is shorter than 10, until `21 54 68 69 73…` starts the long run `!This program cannot be run in DOS mode.` — exactly the first line of output.

Now look further in, at offset `0x300`:

```
$ hexdump -C -s 0x300 -n 64 invoice_tool
00000300  02 00 45 00 02 45 00 4c  45 02 8b 01 01 00 24 00  |..E..E.LE.....$.|
00000310  68 00 74 00 74 00 70 00  3a 00 2f 00 2f 00 6d 00  |h.t.t.p.:././.m.|
00000320  65 00 64 00 69 00 61 00  2d 00 63 00 64 00 6e 00  |e.d.i.a.-.c.d.n.|
00000330  2e 00 65 00 78 00 61 00  6d 00 70 00 6c 00 65 00  |..e.x.a.m.p.l.e.|
```

- `-s 0x300` — skip to offset `0x300`; `-n 64` — show 64 bytes.
- The ASCII column reads `h.t.t.p.:././.m.e.d.i.a.-.c.d.n.` — the text is **there**, but every letter is followed by a `00` byte. `68 00` = `h`, `74 00` = `t`, and so on.
- That is **UTF-16 little-endian**: each English character takes two bytes, the meaningful byte first and the `00` high byte second (see [Unicode and encodings](file-identification.md#unicode) on the previous page).
- In ASCII mode, `strings` sees `h` (printable), then `00` (not printable, run ends), then `t`, then `00`… — a long series of 1-character runs, all shorter than any minimum. The URL is invisible to the first pass **by design of the encoding**, not because anyone hid it.

## Different encodings and byte orders { #encodings }

### Two bytes per character, two possible orders { #byte-order }

When a character takes more than one byte, someone has to decide which byte goes first. This is **byte order**, or **endianness**:

- **Little-endian (LE)**: the **least** significant byte first. `h` = `U+0068` is stored as `68 00`. x86/x64 CPUs and Windows use this.
- **Big-endian (BE)**: the **most** significant byte first. `h` is stored as `00 68`. Used by Java class files, many network protocols ("network byte order") and some older non-x86 systems.

Think of writing a date: `20/11/2026` versus `2026/11/20`. Same date, same pieces, different order, and if you read one with the other's rule you get nonsense. Technically, `strings` needs to know both the **width** (8, 16 or 32 bits per unit) and the **order** before it can tell which byte pairs are characters.

That is what `-e` is for. From the GNU `strings` manual (paraphrased):

| `-e` value | Unit | Order | Typical content |
| --- | --- | --- | --- |
| `s` | 7-bit, 1 byte | — | ASCII (the default) |
| `S` | 8-bit, 1 byte | — | Latin-1, Windows-1252, raw UTF-8 bytes |
| `b` | 16-bit | big-endian | UTF-16BE |
| `l` | 16-bit | little-endian | **UTF-16LE — Windows "wide" strings** |
| `B` | 32-bit | big-endian | UTF-32BE |
| `L` | 32-bit | little-endian | UTF-32LE |

### The second pass { #second-pass }

Same file, 16-bit little-endian, with hex offsets:

```
$ strings -n 10 -e l -t x invoice_tool
    30e $http://media-cdn.example/img/led/tr.php
    370 %APPDATA%\Microsoft\svchostw.exe
```

- `-e l` — decode as 16-bit little-endian: treat `68 00` as one character `h`.
- `-t x` — print each string's starting **offset in hex** in the left column.
- `30e` — this string starts at `0x30e`. In the hex dump, `0x30e` holds `24 00` — that's the `$`. Again one coincidentally printable unit (`$`) is glued to the front; the URL itself begins at `0x310`, where we saw `68 00`.
- `http://media-cdn.example/img/led/tr.php` — the **command-and-control (C2) address**. A `.php` script under an "images" path on a "CDN" name is a classic disguise for a beacon endpoint. This is your top network IOC: block the domain, and search proxy, DNS and Zeek logs for `media-cdn.example` and for the path `/img/led/tr.php` on any host (the path may be reused on other domains). ATT&CK: **T1071.001 Application Layer Protocol: Web Protocols**.
- `370 %APPDATA%\Microsoft\svchostw.exe` — a file path at `0x370`. `%APPDATA%` is the user's roaming profile, writable without admin rights. `svchostw.exe` is a **look-alike** of the real `svchost.exe`, which only ever lives in `C:\Windows\System32`. This is a likely **drop location** and a masquerade (**T1036.005 Masquerading: Match Legitimate Name or Location**). Hunt for file-creation events with that path and for any `svchost*.exe` running outside System32.

Two passes, and the picture is complete: a VB6 program that drops itself as `svchostw.exe` in AppData, sets a Run key, and talks HTTP to `media-cdn.example` with a fake IE8 user agent. You haven't run anything.

**[Supplement]** Quick, reusable habit:

```
$ strings -a -n 8 -t x sample > sample.ascii.txt
$ strings -a -n 8 -t x -e l sample > sample.utf16le.txt
$ cat sample.ascii.txt sample.utf16le.txt | grep -iE 'https?://|\\run|\.exe|\.dll|\.ps1|user-agent|mozilla|[0-9]{1,3}(\.[0-9]{1,3}){3}'
```

- Lines 1–2 save both passes, with offsets, to text files you can attach to the case.
- Line 3 combines them and filters for common IOC shapes: URLs, Run keys, executable and script names, user agents, and dotted-quad IPs. `-i` ignores case; `-E` enables extended regex; `|` separates alternatives.
- This is a first filter only. Always look at the unfiltered output too — unique words like `ORCHIDFALLOW` don't match any pattern.

You can also search for one known UTF-16LE string directly:

```
$ LC_ALL=C grep -obUaP 'h\x00t\x00t\x00p' invoice_tool
784:h t t p
```

- `784` is the decimal offset (= `0x310`, where the URL starts). The "spaces" in the output are your terminal printing the `00` bytes.

### Non-English text, `-e S` and `--unicode` { #non-english }

ASCII mode (`-e s`) only treats `0x20`–`0x7E` as printable, so text in UTF-8 that contains Korean, Cyrillic or accented characters is broken into pieces at every non-ASCII byte. Two ways around it:

- `-e S` treats bytes `0x80`–`0xFF` as printable too. You get the raw UTF-8 bytes, which your terminal will display correctly if it's in UTF-8 — but you also get more noise, because now a random byte is printable about 3 times out of 4.
- **[Supplement]** Recent GNU binutils (2.38 onwards, 2022) added `-U`/`--unicode=` with modes such as `locale` (show valid UTF-8 sequences as characters), `escape` (show them as `\u` escapes) and `highlight` (escapes in colour). `--unicode=escape` is useful for spotting hidden tricks, such as the right-to-left override character `U+202E` in an embedded file name, without your terminal silently rendering it.

## How strings help { #how-strings-help }

### IOCs without running anything { #iocs }

Malware has to modify files and registry keys and contact servers, and the names of all those things have to come from somewhere — very often from text compiled straight into the file. So the strings of a sample are a fast list of what it **may** do. You can block, alert and hunt on those values **before** the malware gets a chance to use them on another machine.

What to look for, roughly in order of usefulness:

| Category | Example from strings | What you do with it |
| --- | --- | --- |
| URLs, domains, IPs | `http://media-cdn.example/img/led/tr.php`, `198.51.100.23` | Block; search proxy/DNS/Zeek/firewall logs fleet-wide |
| File paths and names | `%APPDATA%\Microsoft\svchostw.exe`, `\Temp\upd.ps1` | Hunt for file creation (Sysmon 11) and process creation (4688/Sysmon 1) with that path |
| Registry keys | `...\CurrentVersion\Run`, `...\Image File Execution Options` | Hunt registry events (Sysmon 13), autoruns |
| User agents, HTTP headers | `Mozilla/4.0 (compatible; MSIE 8.0)` | Search proxy and `http.log` |
| Commands | `cmd.exe /c `, `powershell -enc`, `schtasks /create`, `vssadmin delete shadows` | Map to behaviour (T1059, T1053.005, T1490); hunt process command lines |
| Imported DLLs and APIs | `WININET.dll`, `InternetOpenUrlA`, `VirtualAllocEx`, `WriteProcessMemory` | Capability hints (download, injection); hand to a reverse engineer |
| Unique words, mutexes, PDB paths | `ORCHIDFALLOW`, `Global\x7Q2mutex`, `C:\dev\loader\Release\loader.pdb` | Family/campaign clustering; YARA rules |

Treat each one as a **lead**. A legitimate program also contains URLs (its update server), registry paths and API names. Context — what else is in there, where the file came from, what the endpoint actually did — decides.

### Static vs dynamic analysis { #static-dynamic }

- **Static analysis** = examining a file **without executing it**: `file`, hex dumps, `strings`, hashes, header parsing, disassembly. Safe (as long as you don't open it with the program it targets), fast, and leaves no trace on the attacker's infrastructure.
- **Dynamic analysis** = **running** the file in a controlled environment (a sandbox or isolated VM) and watching what it does: processes, files, registry, network traffic. Shows true behaviour, defeats some hiding tricks, but it is slower, can be evaded (the sample detects the sandbox and stays quiet), and can tip off the attacker if the sample reaches out to a live C2 server.

Strings sit at the heart of static triage, and they also help dynamic analysis: knowing the C2 URL in advance tells you what to look for in the sandbox's network capture.

### Why the sandbox shows strings you can't find { #sandbox-strings }

Public and commercial sandboxes (Hybrid Analysis, ANY.RUN, Joe Sandbox, VirusTotal's behaviour reports, your EDR vendor's detonation service) usually show a long **strings** list in the report. Two things to know when reading it:

1. **They merge encodings.** A sandbox typically extracts ASCII, UTF-16LE and sometimes other encodings and concatenates the results, often without saying which encoding each string came from. That's why its list may be longer than your first `strings` pass — and why your second pass with `-e l` usually closes the gap.
2. **They scrape memory.** Many sandboxes also dump the **running process's memory** and extract strings from there. Packed or encrypted malware unpacks itself in memory, so strings appear there that do not exist anywhere on disk. That is dynamic analysis, even though the output looks like `strings`. If you see a URL in the sandbox report that neither of your passes finds, this is almost certainly why.

An illustrative (invented) sandbox strings excerpt:

```
Extracted Strings (static + memory, all encodings)
  MSVBVM60.DLL
  ORCHIDFALLOW
  http://media-cdn.example/img/led/tr.php
  %APPDATA%\Microsoft\svchostw.exe
  POST /img/led/tr.php HTTP/1.1          [memory]
  id=%s&os=%s&av=%s                      [memory]
```

- The first four lines match what our two passes found on disk.
- The two `[memory]` lines exist only at run time: the beacon request line, and a **format string** (`%s` placeholders) that tells you the beacon will send a victim ID, the OS version and the installed antivirus. That's valuable for writing a network detection — but you couldn't have gotten it from the file on disk.

**[Caution]** Uploading a sample to a **public** sandbox makes it visible to others, including possibly the attacker, who may watch for their own hashes. For targeted incidents, prefer hash lookups, private sandboxes or your EDR vendor's private detonation ([sandboxes and OPSEC](../http-analysis/screenshots-sandboxes.md)).

### Packing, encryption and compression { #packing }

`strings` only sees bytes that are text **as stored**. Three things change the stored bytes:

- **Packing** (ATT&CK **T1027.002 Software Packing**). The real program is compressed or encrypted and wrapped in a small unpacking stub that restores it in memory at run time. On disk you mostly see the stub. Typical signs: very few meaningful strings, high entropy (random-looking bytes), only a handful of imports such as `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`/`VirtualProtect`, and sometimes the packer's own section names. The open-source UPX packer is the easiest example:

    ```
    $ strings -n 4 packed_sample | head -6
    !This program cannot be run in DOS mode.
    UPX0
    UPX1
    UPX!
    KERNEL32.DLL
    LoadLibraryA
    ```

    - `UPX0`, `UPX1` are UPX's section names and `UPX!` is its marker. UPX itself is legitimate (and `upx -d` can unpack it), but a packed "invoice tool" is a strong signal.
    - `KERNEL32.DLL` + `LoadLibraryA` and very little else: the stub only needs to load libraries and find functions; the real imports appear after unpacking.

- **Obfuscated or encrypted strings** (**T1027**, decoding at run time is **T1140 Deobfuscate/Decode Files or Information**). Instead of packing the whole file, the author XORs or encrypts just the interesting strings, or builds them character by character on the stack ("stack strings"). `strings` sees nothing useful; tools like FLOSS can emulate the decoding routines and recover them (see [the 2026 view](#trends)).

- **Compression.** ZIP, gzip, 7z, DOCX/XLSX (which are ZIPs), compressed PDF streams, PNG pixel data: compression rewrites the content into new byte patterns, so readable text inside becomes unreadable. For example:

    ```
    $ gzip -c invoice_tool > t.gz
    $ strings -n 10 t.gz
    invoice_tool
    ```

    - All the strings we found earlier are gone. The only survivor is `invoice_tool` — the **original file name**, which gzip stores **uncompressed** in its header. (A small bonus: archive headers can leak original names and paths.)
    - The fix is to **decompress first, then run `strings`**: `zcat t.gz | strings -n 10`, `unzip -p invoice.docx word/document.xml | strings`, or extract to a folder in your analysis VM. For PDFs, tools that decompress streams come up later in this section.

**[Correction]** "No interesting strings, so it's clean" is wrong. Few strings in an executable often means the opposite: someone made an effort to hide them.

### Beyond executables { #beyond-executables }

Strings work on anything that isn't compressed:

- **PCAPs.** Unencrypted protocols carry text. A quick look at a capture:

    ```
    $ strings -n 8 capture.pcap | grep -E '^(Host|User-Agent|Cookie):' | sort | uniq -c | sort -rn | head
         41 Host: media-cdn.example
         41 User-Agent: Mozilla/4.0 (compatible; MSIE 8.0)
         12 Host: intranet.corp.example
          3 Cookie: sid=7f3a9c0e21
    ```

    - `strings -n 8` pulls out text lines from the packets; `grep -E '^(Host|User-Agent|Cookie):'` keeps only those HTTP header lines.
    - `sort | uniq -c | sort -rn` counts identical lines and puts the most frequent first (the frequency-analysis idea from the HTTP section).
    - 41 identical requests to `media-cdn.example` with the fake IE8 user agent: a beacon, found in seconds. Of course this only works for **cleartext** traffic; TLS payloads are encrypted, though the SNI and certificates in the handshake are still readable.

- **Documents and PDFs**: author names, creating software (`Microsoft Word`, `LibreOffice`), embedded URLs, `/JavaScript` or `/OpenAction` keywords in uncompressed PDF objects.
- **Images**: EXIF metadata such as camera model, editing software (`Adobe Photoshop`), timestamps, sometimes GPS — and text that shouldn't be in an image at all, such as `<script>` or `PK` after the image ends (the polyglot clue from the previous page).
- **Memory dumps**: command lines, URLs, decrypted configuration — this is how memory forensics tools find a lot of evidence.

Running `strings` on all sorts of normal files is also a great way to learn what "normal" looks like inside each format, which makes abnormal stand out faster.

## Recap — file contents and identification { #recap }

This page closes the "what is this file?" block of the section. The ideas to carry forward:

- **A file is just a row of bytes.** The name and extension mean nothing to the bytes; they're a label a person or an attacker attached.
- Sometimes all the bytes are readable characters (**plaintext** files: scripts, text, HTML, SVG). Sometimes they are not (**binary** files: executables, archives, images, Office files).
- You will meet files **without extensions** (carved from a PCAP, pulled from memory, dropped by malware with random names). That's normal; you identify them by content.
- **Magic bytes** in a hex dump identify binary formats; the Linux **`file`** command automates this once a file is carved out ([file identification](file-identification.md)).
- **Strings** give you quick clues to what a binary file is and what it does.
- Text comes in **multiple encodings** — ASCII, and Unicode as UTF-8, UTF-16 and UTF-32, in either byte order — so search in more than one.

Understanding files at the byte level does two things for you: you can identify a file whose type is hidden or mislabelled, and you avoid **infecting yourself** by opening a file with the wrong program. The next pages build on this: how to handle suspect files safely, and which file types attackers weaponise and how.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The definition of a string, the plaintext/binary split, the `strings` command and its `-n`, `-t` and `-e` options, and the core lesson — **always search in more than one encoding, especially UTF-16LE on Windows files** — are unchanged. GNU `strings` (binutils 2.4x in current distributions) and Sysinternals Strings are still the standard first tools, and the IOC categories (URLs, domains, IPs, paths, registry keys, user agents, unique markers) are still what analysts pull first. The static vs dynamic distinction, and the fact that sandboxes add memory-scraped strings, still explain most "why don't I see that string?" questions.

!!! info "[Changed] What has changed"
    - **Deobfuscating string tools are now routine.** FLOSS (FLARE Obfuscated String Solver, from Google's Mandiant FLARE team) extracts static strings and also emulates code to recover **stack strings, "tight" strings and decoded strings** that plain `strings` can't see. Since its 3.x releases it also understands **Go and Rust** binaries, whose strings are not null-terminated and otherwise come out as huge concatenated blobs — important because a lot of modern malware is written in Go and Rust.
    - **Ranking the noise.** Tools such as StringSifter (machine-learning ranking of strings by how relevant they are to malware analysis) and the string views in modern sandboxes sort the junk to the bottom.
    - **AI summaries.** Sandboxes and threat-intelligence platforms now add LLM-generated summaries of code and strings (VirusTotal's Code Insight is one example). Useful for speed, but they can be wrong; verify against the actual strings and behaviour.
    - **From strings to detections.** Unique strings are still the classic input to YARA rules; YARA-X (the Rust rewrite of YARA, 1.0 in 2025) is now the recommended engine for new rules, with largely compatible syntax.
    - **GNU `strings` scans the whole file by default** (since binutils 2.26, after a 2014 vulnerability in the object-file parsing path), and recent versions add `--unicode` for UTF-8 display and escaping.
    - **ATT&CK names** used on this page: T1027.002 Software Packing, T1027 Obfuscated Files or Information, T1140 Deobfuscate/Decode Files or Information, T1547.001 Registry Run Keys, T1036.005 Match Legitimate Name or Location, T1071.001 Web Protocols.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't stop after the ASCII pass.** Windows text is usually UTF-16LE and ASCII mode will never find it. Two passes minimum (`-e s` and `-e l`), or a tool that does both.
    - **Don't conclude "clean" from few strings.** That is a typical sign of packing or string obfuscation. Check entropy, imports and packer markers, then use FLOSS, unpacking or memory.
    - **Don't run `strings` on archives and compressed documents and trust the result.** Decompress first.
    - **On very old systems, use `strings -a` explicitly.** Old binutils versions only scanned the data sections of recognised object files by default, and parsing them was itself a source of vulnerabilities. Keep analysis tools patched and run them in an isolated VM.
    - **Don't treat a single string as a verdict.** Legitimate programs contain URLs, Run keys and scary-sounding API names. Correlate with origin, signature, hash reputation and actual endpoint behaviour.
    - **Mind OPSEC with public sandboxes.** Uploading a targeted sample can tell the attacker you found it; prefer hash lookups and private analysis.
    - **Never "look at the strings" by opening the file in its own program** (double-clicking, opening in Word or a browser). Use `strings`, a hex viewer or a plain text viewer on an analysis machine.

## Practice questions { #quiz }

### Question 1

You run `strings -n 10 dropper.bin` on a Windows executable and get only the DOS stub sentence and two DLL names. Your colleague says, "It barely has any strings, so it can't be doing much." Then you run `strings -n 10 -e l dropper.bin` and get `http://upd-check.example/a.php` and `%TEMP%\wuauclt32.exe`. Explain why the first pass missed these, what each string suggests, and what you would do next.

??? success "Answer and explanation"
    **Why the first pass missed them:** The default mode (`-e s`) decodes one byte per character. These strings are stored as **UTF-16 little-endian**, so every letter is followed by a `00` byte (`68 00 74 00 74 00 70 00` for `http`). In ASCII mode each `00` ends the run, leaving only one-character runs that fall below the minimum length. `-e l` reads 16-bit little-endian units and decodes them correctly. The colleague's conclusion is wrong twice: the strings were there all along, and few strings would be suspicious anyway, not reassuring.

    **What they suggest:** `http://upd-check.example/a.php` is a probable C2 or download URL (a PHP script on an "update check" name — T1071.001). `%TEMP%\wuauclt32.exe` is a probable drop path, and `wuauclt32.exe` imitates the real Windows Update client `wuauclt.exe` (which lives in System32) — masquerading, T1036.005.

    **Next:** block and hunt `upd-check.example` and the path `/a.php` in proxy/DNS/Zeek logs; hunt file-creation and process-creation events for `wuauclt32.exe` in any Temp folder; hash the sample and check reputation; optionally detonate in a private sandbox to confirm behaviour.

### Question 2

`strings -n 6 report_q3.exe` shows `!This program cannot be run in DOS mode.`, `UPX0`, `UPX1`, `UPX!`, `KERNEL32.DLL`, `LoadLibraryA`, `GetProcAddress`, `VirtualProtect` — and almost nothing else. A sandbox report for the same hash lists a domain and a `POST` request format string. (a) What does the `strings` output tell you? (b) Why can the sandbox show strings that `strings` can't? (c) What is the ATT&CK technique?

??? success "Answer and explanation"
    **(a)** The file is a Windows executable **packed with UPX**: `UPX0`/`UPX1` are its section names and `UPX!` its marker. The tiny import list (`LoadLibraryA`, `GetProcAddress`, `VirtualProtect`) is what an unpacking stub needs to rebuild the real program in memory. The real strings are compressed and invisible on disk. A packed "quarterly report" executable is suspicious in itself.

    **(b)** The sandbox **ran** the file (dynamic analysis). The stub unpacked the real code into memory, and the sandbox dumped process memory and extracted strings from it — so the domain and request format appear there. Our `strings` only read the packed bytes on disk (static analysis). We could also try `upx -d` on a copy in the analysis VM to unpack it statically and run `strings` again.

    **(c)** **T1027.002 Obfuscated Files or Information: Software Packing.**

### Question 3

(a) In the output line `ELORCHIDFALLOW`, why might the real string be `ORCHIDFALLOW`, and why is a meaningless unique word worth recording? (b) Why does `strings` on a `.docx` file show almost nothing useful, and how do you fix it? (c) Give two uses of `strings` outside executables.

??? success "Answer and explanation"
    **(a)** `strings` only knows where printability starts and stops, not where words start. Any printable bytes that happen to sit directly before the real text (here `0x45` `E` and `0x4c` `L`) are glued onto the front. You confirm by checking the bytes at the string's offset (`-t x`) in a hex dump. A unique nonsense word is valuable because it's unlikely to appear in legitimate software, so it can link samples of the same family or campaign and make a good **YARA** rule or hunt term.

    **(b)** A `.docx` is a **ZIP** archive, and its XML parts are compressed with deflate, which rewrites the text into unreadable bytes. Only uncompressed bits (ZIP headers and part names like `word/document.xml`) remain readable. Decompress first — `unzip -l` to list, `unzip -p file.docx word/document.xml` or extract in the analysis VM — then run `strings` or read the XML.

    **(c)** Any two of: on a **PCAP** to pull out cleartext HTTP `Host`, `User-Agent`, `Cookie` lines and URLs (then count them to spot beacons); on **PDFs** for embedded URLs, the creating software and keywords like `/JavaScript` in uncompressed objects; on **images** for EXIF metadata or text that shouldn't be there (`<script>`, a trailing `PK`); on **memory dumps** for command lines, URLs and decrypted configuration.

## Related { #related }

- [Identifying files — magic bytes, nested files, Unicode and encodings](file-identification.md)
- [Screenshots, sandboxes and when to go manual](../http-analysis/screenshots-sandboxes.md) · [Base64](../http-analysis/base64.md)
- [User agents and cookies](../http-analysis/user-agents-cookies.md) · [Zeek files.log & pe.log](../../../network/zeek/files-log.md)
- [Persistence techniques](../../../adversary/persistence.md) · [Process creation events](../important-events/process-creation.md)
