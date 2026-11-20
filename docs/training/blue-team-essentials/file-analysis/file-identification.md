---
title: "Identifying Files — Bytes, the file Command, Magic Bytes, Nested Files, Polyglots, Unicode and Encodings"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
---

# Identifying Files — Bytes, the file Command, Magic Bytes, Nested Files, Polyglots, Unicode and Encodings { #file-identification }

!!! abstract "What this page covers"
    What a file really is (a row of bytes that a program agrees to interpret), and how to answer the first question about any suspicious download or attachment: **what type of file is this, really?** — without trusting its name, extension or the `Content-Type` a server claimed. We read hex dumps column by column, run the Linux `file` command on six extensionless samples and interpret every output line, learn the **magic bytes** (file signatures) worth memorising and why ZIP and modern Office files share one, find a **file hidden inside another file** in a raw byte stream and carve it out, see why one file can be **two valid types at once** (polyglots) and why attackers now use that, and finish with **Unicode and encodings** (code points, UTF-8, UTF-16, UTF-32, byte order marks) — the background you need before reading `strings` output. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs). The sample files are harmless test files made for this page.

## The 8 key points { #key-points }

1. A file is **just a sequence of bytes**. "PDF", "EXE" or "DOCX" is not a property the file carries around; it's how a program **chooses to interpret** those bytes.
2. The **name, the extension and the HTTP `Content-Type` are claims**, and attackers control all three. The bytes are the evidence.
3. The fastest first check on Linux is **`file`**: it reads the content (not the name) and compares it with a library of known formats. Windows has no built-in equivalent, but the same idea works with a hex view.
4. Most formats start with **magic bytes** (a file signature) — `MZ` for Windows executables, `PK\x03\x04` for ZIP, `%PDF-` for PDF, `\x7fELF` for Linux executables, `\x89PNG` for PNG, `{\rtf1` for RTF, `1F 8B` for gzip.
5. **DOCX, XLSX and PPTX are ZIP files.** Same magic bytes, because they are literally ZIP archives of XML files. Old `.doc`/`.xls` use a different container (OLE, `D0 CF 11 E0`).
6. `file` only looks at the **start** of a file. A file **embedded in another file**, or a file inside a raw network stream, needs a tool that searches for signatures **anywhere** (binwalk, foremost, scalpel, or a simple `grep` for the bytes), and the analyst's eye.
7. A file can be **two valid types at once** (a **polyglot**): a working image that is also a ZIP, a PDF that also runs as HTML Application. What a file "is" depends on **which program opens it**.
8. Text has its own trap: the same characters become **different bytes** in UTF-8, UTF-16 and UTF-32. Decode with the wrong encoding and you get garbage — or miss the string you were searching for.

## Why this matters in a SOC { #why }

Picture a typical alert. A proxy log shows a workstation fetched `http://cdn-update.example/x` and got back a 312 KB response with `Content-Type: image/png`. Shortly afterwards the same workstation started beaconing. You pull the response body out of the packet capture (Wireshark: **File → Export Objects → HTTP**, or Zeek's file extraction). Now you hold a file called `x`. No extension, no hint.

You need to answer, quickly and safely:

1. **What type of file is it really?** An image, as claimed? A Windows program? A script? An archive with more files inside?
2. **Is it dangerous?** That depends heavily on the answer to 1. A real PNG is almost never the threat; a Windows DLL pretending to be a PNG almost always is.

The methods, roughly in order of cost:

- **`file`** — automatic identification from content. Seconds.
- **A hex dump** — look at the first bytes yourself for **magic bytes**. Seconds to minutes.
- **`strings`** and looking for **nested content** — clues, URLs, embedded files. Minutes. (Covered on the next page.)
- **Sandbox / dynamic analysis** — run it in a controlled environment and watch. Minutes to longer, and with OPSEC questions (see [Screenshots, sandboxes, and when to go manual](../http-analysis/screenshots-sandboxes.md)).

An analogy: a parcel arrives labelled "chocolates". The label is the extension. You don't open it in the office to check; you **X-ray it** first. The hex dump and the `file` command are the X-ray: they show what's inside without "running" it. Technically, the X-ray works because almost every file format must follow a **specification** so that its program can read it, and specifications almost always begin with a fixed, recognisable pattern.

<strong>[Caution]</strong> Do all of this on an **analysis machine** (an isolated Linux VM or a dedicated triage box), never on your daily workstation, and never by double-clicking. Identifying a file means **reading** its bytes, not **opening** it in the program it targets. Safe handling has its own page later in this section.

## A file is a sequence of bytes { #bytes }

Every file — a text note, a photo, a program — is stored as a sequence of **bytes**. A byte is 8 bits, a number from 0 to 255, usually written in **hexadecimal** as two characters from `00` to `ff`. What makes one file a PDF and another a program is only **how those numbers are arranged**, and which program is asked to interpret them.

To see the raw bytes you use a **hex dump** tool. On Linux the classics are `hexdump -C`, `xxd` and `od`. Here is the start of a small PDF:

```
$ hexdump -C sample_e | head -3
00000000  25 50 44 46 2d 31 2e 37  0a 25 e2 e3 cf d3 0a 31  |%PDF-1.7.%.....1|
00000010  20 30 20 6f 62 6a 0a 3c  3c 20 2f 54 79 70 65 20  | 0 obj.<< /Type |
00000020  2f 43 61 74 61 6c 6f 67  20 2f 50 61 67 65 73 20  |/Catalog /Pages |
```

The command:

- `hexdump -C` — "canonical" view: offset, 16 bytes in hex, and the same bytes as text.
- `| head -3` — show only the first three lines (48 bytes).

Reading one line, column by column:

- `00000000` — the **offset**: how far from the start of the file this line begins, in hex. Line 2 starts at `0x10` = byte 16, line 3 at `0x20` = byte 32. Offsets are how analysts point at a spot in a file ("the zip starts at 0x15be6").
- `25 50 44 46 2d 31 2e 37  0a 25 …` — the **16 bytes** of that line in hex, split into two groups of 8 for readability.
- `|%PDF-1.7.%.....1|` — the same bytes shown as **ASCII characters**. Bytes that have no printable character (like `0a`, a newline, or `e2`) are shown as `.`.

So `25 50 44 46 2d` is `%`, `P`, `D`, `F`, `-`: the file announces itself as a PDF, version 1.7. The odd bytes `e2 e3 cf d3` on the second line are deliberate: PDF writers put a few bytes above 127 near the top so that transfer tools treat the file as **binary**, not text. That's a small example of a spec dictating bytes.

The same view with `xxd`, which you'll often see in write-ups, groups bytes in pairs:

```
$ xxd -l 16 sample_c
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
```

- `-l 16` — stop after 16 bytes.
- `8950 4e47 0d0a 1a0a` — the eight-byte PNG signature (more on it below), written as four 2-byte groups.
- `0000 000d 4948 4452` — the length (`0x0d` = 13) and name (`IHDR`, the image header) of the first PNG "chunk". Anything after the signature is defined by the PNG spec too.

<strong>[Supplement]</strong> On Windows there is no `hexdump`, but PowerShell has `Format-Hex`:

```powershell
Format-Hex -Path .\x -Count 16
```

```
   Label: C:\triage\case-2611\x

          Offset Bytes                                           Ascii
                 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
          ------ ----------------------------------------------- -----
0000000000000000 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 MZ�� ���  ÿÿ
```

- `-Path .\x` — the file to read. `-Count 16` limits output to 16 bytes (PowerShell 7; Windows PowerShell 5.1 has no `-Count`, so pipe to `Select-Object -First 1`).
- `Offset`, `Bytes`, `Ascii` — the same three columns as `hexdump -C`.
- The first two bytes, `4D 5A` = `MZ`. This "image" is a **Windows executable**.

## The `file` command { #file-command }

Reading hex by hand is slow, so the first thing to try on Linux is `file`. It comes with a database of format signatures (the **magic** database, from the `libmagic` library) and reports the best match for each file **based on the content**. The extension is ignored.

Six samples with no extensions:

```
$ file *
sample_a:     PE32+ executable (GUI) x86-64, for MS Windows
sample_b:     ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3c9e…, for GNU/Linux 3.2.0, stripped
sample_c:     PNG image data, 640 x 480, 8-bit/color RGBA, non-interlaced
sample_d:     SVG Scalable Vector Graphics image
sample_e:     PDF document, version 1.7, 0 page(s)
sample_f:     PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
```

The command: `file *` — run `file` on every file in the current directory (`*` is expanded by the shell).

Line by line:

- `sample_a` — **PE32+** = the Windows "Portable Executable" format, 64-bit flavour (the `+`). `(GUI)` means it's built as a windowed program rather than a console one. `x86-64` = for 64-bit Intel/AMD CPUs. A Windows program.
- `sample_b` — **ELF** = the Linux/Unix executable format. `64-bit LSB` = 64-bit, little-endian (least significant byte first). `pie executable` = position-independent, the modern default. `dynamically linked` + `interpreter /lib64/ld-linux-x86-64.so.2` = it needs system libraries, loaded by that loader. `BuildID` = a compiler-generated ID. `stripped` = debugging symbol names removed (normal for release builds, also common in malware).
- `sample_c` — a real **PNG**, and `file` even read its header: 640×480 pixels, RGBA colour.
- `sample_d` — an **SVG** image. Keep an eye on this one: SVG is **XML text**, and it can contain JavaScript. See [Changed](#trends).
- `sample_e` — a **PDF**, version 1.7. `0 page(s)` tells you it's tiny or odd; real documents have pages.
- `sample_f` — **PE32** (32-bit), `(DLL)` = a library, not a stand-alone program. DLLs are loaded by another process (for example `rundll32.exe` or a legitimate program that's tricked into loading it).

So in seconds: two Windows binaries, one Linux binary, two images and one PDF. If `x` from the alert came back as `sample_f` does, the "PNG" is a **DLL**, and the case just got serious.

### Text files and scripts { #file-text }

For plain text, `file` usually says little:

```
$ file notes update_sh invoice_0412 x.gz
notes:        ASCII text
update_sh:    Bourne-Again shell script, ASCII text executable
invoice_0412: Microsoft Word 2007+
x.gz:         gzip compressed data, last modified: Fri Nov 20 21:49:48 2026, max compression, original size modulo 2^32 5
```

- `notes` — `ASCII text`: only printable characters and newlines. `file` can't tell you what the text *means*.
- `update_sh` — identified as a **bash script** because its first line is `#!/bin/bash` (the "shebang"). `executable` here means "has a shebang", not that the execute permission is set. Scripts without a shebang (most PowerShell, VBScript, JavaScript and batch files) often show up as just `ASCII text` or `UTF-8 text` — so **"text" is not "harmless"**.
- `invoice_0412` — `Microsoft Word 2007+`: `file` saw a ZIP, looked inside at the `[Content_Types].xml` member and recognised a DOCX.
- `x.gz` — gzip, plus details from the gzip header (timestamp, compression level, original size).

### Useful options { #file-options }

| Option | What it does | When you'd use it |
| --- | --- | --- |
| `file -i x` (or `--mime`) | Prints the MIME type, e.g. `application/pdf; charset=binary` | To compare directly with the `Content-Type` the server sent, or with Zeek's `mime_type` |
| `file -k x` | **Keep going**: list every matching signature, not just the first | Suspected polyglots or odd files |
| `file -z x` | Look **inside** compressed files (gzip etc.) | Quick peek at `.gz` content without extracting |
| `file -b x` | Brief: no filename prefix | Scripts and loops |
| `file --extension x` | Suggest the usual extension(s) for the detected type | Renaming carved files for further tools |

```
$ file -i sample_e invoice_0412
sample_e:     application/pdf; charset=binary
invoice_0412: application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=binary
```

If a proxy log says `Content-Type: image/png` and `file -i` says `application/x-dosexec`, you have a **content-type mismatch** — a strong signal on its own (see [Content-Type in HTTP responses](../http/responses.md#content-type)).

### How `file` decides — and how it can be fooled { #file-limits }

`file` runs three kinds of tests, in order: **filesystem tests** (is it empty? a directory? a link?), **magic tests** (compare bytes at fixed offsets with the signature database), and **language tests** (if it looks like text, guess the character set and maybe the language). The first test that succeeds wins.

That design has consequences an analyst should know:

- It mostly trusts the **first bytes**. Prepend `MZ` to a text file and `file` may call it a DOS executable; add a PNG header to a ZIP and it says PNG. Matching signatures proves the bytes **start** like that format, not that the whole file is valid.
- It reports **one** answer by default. A polyglot looks like whatever matches first (use `-k`).
- It doesn't look **deep** inside. An OLE `.doc` with a ZIP buried at byte 89,062 is still just "Composite Document File" to `file`.
- It is software parsing hostile input. `libmagic` has had its own vulnerabilities over the years, which is one more reason to run it on an isolated analysis VM with an up-to-date package.

<strong>[Supplement]</strong> Other identification tools you'll meet: **TrID** (Windows/Linux, ranks probable types with percentages), **Detect It Easy (DIE)** (also identifies the compiler and packer of executables), and **Zeek's file analysis**, which applies its own signatures to every file it sees on the wire and writes `mime_type` into [files.log](../../../network/zeek/files-log.md) — so you can hunt for executables delivered as "images" across the whole network without touching a single file.

## Magic bytes — the file signature { #magic-bytes }

`file` works by recognising **magic bytes**, also called the **file signature**: a fixed byte sequence that a format's specification requires, usually at the very start (offset 0). The reading program checks it to confirm "yes, this is mine" before parsing the rest.

The ones worth knowing by heart:

| File type | Starting bytes (hex) | As ASCII | Notes |
| --- | --- | --- | --- |
| Windows executable (EXE, DLL, SYS, SCR, CPL…) | `4D 5A` | `MZ` | Initials of Mark Zbikowski, a DOS developer. Later there's also a `PE\0\0` header |
| ZIP — and DOCX, XLSX, PPTX, JAR, APK, many more | `50 4B 03 04` | `PK..` | Initials of Phil Katz, author of PKZIP |
| gzip (`.gz`, `.tgz`) | `1F 8B` | (not printable) | |
| PDF | `25 50 44 46 2D` | `%PDF-` | Followed by the version, e.g. `1.7` |
| RTF | `7B 5C 72 74 66 31` | `{\rtf1` | Rich Text Format; covered later in this section |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` | |
| **[Supplement]** ELF (Linux binaries) | `7F 45 4C 46` | `.ELF` | |
| **[Supplement]** OLE / Compound File (old `.doc`, `.xls`, `.ppt`, `.msi`, `.msg`) | `D0 CF 11 E0 A1 B1 1A E1` | (not printable) | Reads like "DOCFILE" in hex-speak |
| **[Supplement]** JPEG | `FF D8 FF` | | |
| **[Supplement]** GIF | `47 49 46 38 37 61` / `…39 61` | `GIF87a` / `GIF89a` | |
| **[Supplement]** 7-Zip | `37 7A BC AF 27 1C` | `7z....` | |
| **[Supplement]** RAR | `52 61 72 21 1A 07` | `Rar!..` | |
| **[Supplement]** Windows shortcut (LNK) | `4C 00 00 00 01 14 02 00` | `L...` | Common phishing payload |
| **[Supplement]** Microsoft Cabinet (CAB) | `4D 53 43 46` | `MSCF` | |
| **[Supplement]** ISO 9660 disc image | `43 44 30 30 31` at offset `0x8001` | `CD001` | Not at offset 0 — a good example of why "first bytes" isn't the whole rule |

You don't need to memorise every row. The top six plus ELF and OLE cover most SOC days, and recognising them **inside a stream** is a skill that pays off constantly.

Let's look at two of them in a dump.

**A Windows executable:**

```
$ hexdump -C sample_a | head -9
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 80 00 00 00  |................|
00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|
00000050  69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|
00000060  74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |
00000070  6d 6f 64 65 2e 0d 0d 0a  24 00 00 00 00 00 00 00  |mode....$.......|
00000080  50 45 00 00 64 86 01 00  b0 a2 31 67 00 00 00 00  |PE..d.....1g....|
```

- Offset `0x00`: `4d 5a` = **`MZ`**, the DOS header signature. Every Windows executable still begins with a tiny DOS program for backwards compatibility.
- Offset `0x3c`: `80 00 00 00` = the number `0x80` (little-endian, so read the bytes backwards: `00 00 00 80`). This field, `e_lfanew`, says **where the real PE header starts**: offset `0x80`.
- Offsets `0x40`–`0x7f`: the **DOS stub** — machine code plus the famous text `This program cannot be run in DOS mode.` If you ever see that sentence in a hex dump, a packet capture or `strings` output, **a Windows executable is right there**, even if its `MZ` was cut off or the file is embedded in something else.
- Offset `0x80`: `50 45 00 00` = **`PE\0\0`**, the PE signature. Then `64 86` = `0x8664` = machine type x86-64 (a 32-bit file has `4c 01` = `0x14c`, Intel 386). Then `01 00` = one section, then `b0 a2 31 67` = the **compile timestamp** (`0x6731a2b0`, seconds since 1970 = November 2024). Timestamps can be faked, but they're a useful clue.

**A DOCX is a ZIP:**

```
$ hexdump -C invoice_0412 | head -3
00000000  50 4b 03 04 14 00 00 00  08 00 38 ae 74 5d c6 12  |PK........8.t]..|
00000010  7a 07 af 00 00 00 f1 00  00 00 13 00 00 00 5b 43  |z.............[C|
00000020  6f 6e 74 65 6e 74 5f 54  79 70 65 73 5d 2e 78 6d  |ontent_Types].xm|
```

- `50 4b 03 04` = **`PK\x03\x04`**, a ZIP **local file header** — the start of one compressed member.
- `14 00` = version needed to extract (`0x14` = 20 → "2.0"), `08 00` = compression method 8 = **deflate**.
- The two bytes `13 00` at offset `0x1a` = `0x13` = 19 = the length of the member's file name, and the name follows: `[Content_Types].xml`. That name is a tell-tale of an **Office Open XML** document.

Why do ZIP and Office share magic bytes? Because since Office 2007, `.docx`, `.xlsx` and `.pptx` **are ZIP archives** containing XML files, images and settings. You can prove it:

```
$ cp invoice_0412 invoice_0412.zip
$ unzip -l invoice_0412.zip
Archive:  invoice_0412.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      241  2026-11-20 21:49   [Content_Types].xml
       16  2026-11-20 21:49   _rels/.rels
       13  2026-11-20 21:49   word/document.xml
---------                     -------
      270                     3 files
```

- `unzip -l` — **list** the members without extracting.
- `[Content_Types].xml` — what each part is. `_rels/.rels` — how parts relate. `word/document.xml` — the actual text (`xl/` for Excel, `ppt/` for PowerPoint).
- In a real malicious document you'd look for parts such as `word/vbaProject.bin` (macros; the file is then usually `.docm`), external relationships in `word/_rels/document.xml.rels` pointing to a URL (remote template injection), or embedded objects under `word/embeddings/`.

<strong>[Supplement]</strong> The old binary formats (`.doc`, `.xls`, `.ppt`, Office 97–2003) are not ZIP; they use the **OLE Compound File** container, magic `D0 CF 11 E0 A1 B1 1A E1`. Outlook `.msg` files and `.msi` installers use it too. Tools like `oledump.py` and `olevba` (from oletools) read it; that's for the Office documents page later in this section.

## Nested files — signatures in the middle { #nested-files }

If `file` does the job, why memorise anything? Because `file` only works when the file has **already been cut out** and its signature is at the start. Two everyday situations break that:

- **A raw byte stream.** A packet capture, a memory dump or an unknown blob from a disk — the interesting file starts somewhere in the middle.
- **A file embedded in another file.** Many formats can carry other files: Word documents with embedded objects, PDFs with attachments, archives within archives, an executable stuffed into an image's trailing bytes. Phishing uses this constantly, because the outer file looks harmless to a quick check. MITRE ATT&CK tracks this as **Embedded Payloads (T1027.009)** and disguised types as **Masquerade File Type (T1036.008)**.

Here is a slice of an old-format Word document (`quote_q4.doc`) from a phishing email. Can you spot the second file?

```
$ hexdump -C -s 0x15bd0 -n 80 quote_q4.doc
00015bd0  ac 1e ac c6 65 10 ce 6f  cb f8 cf 6c 60 99 39 ac  |....e..o...l`.9.|
00015be0  45 99 03 65 2d ca 50 4b  03 04 14 00 00 00 08 00  |E..e-.PK........|
00015bf0  40 ae 74 5d d9 53 f9 65  0c 00 00 00 2f 00 00 00  |@.t].S.e..../...|
00015c00  0e 00 00 00 71 58 76 54  72 62 6d 50 4c 61 2e 78  |....qXvTrbmPLa.x|
00015c10  6d 6c b3 a9 b0 73 24 12  d8 e8 57 d8 01 00 50 4b  |ml...s$...W...PK|
```

The options: `-s 0x15bd0` = skip to that offset, `-n 80` = show 80 bytes.

- Line `00015be0`: the 7th and 8th bytes are `50 4b` = **`PK`**, and they're followed by `03 04` — the ZIP local file header signature. **A ZIP starts at offset `0x15be0 + 6` = `0x15be6`** (decimal 89,062). `PK` is the easy part to spot in the ASCII column; the non-printable `03 04` after it is what confirms it.
- Same line: `14 00` (version 2.0) and `08 00` (deflate) — exactly the header fields we saw in the DOCX, so this isn't a coincidental `PK`.
- Line `00015c00`: `0e 00` was the name length (14), and the name follows: **`qXvTrbmPLa.xml`** — a random-looking member name inside the embedded archive.
- Line `00015c10`: another `50 4b` right after the compressed data — the start of the ZIP's next structure (the central directory, `PK\x01\x02`).

We don't know yet whether this ZIP is the malicious part. But finding it, and its random name, is exactly what you hand to a malware analyst (or analyse further yourself).

**Finding signatures anywhere — a simple way:**

```
$ LC_ALL=C grep -obUaP "PK\x03\x04" quote_q4.doc
89062:PK
```

- `LC_ALL=C` — treat bytes as bytes, not as UTF-8 characters (otherwise `grep` may misread binary data).
- `-o` print only the match, `-b` print its **byte offset**, `-U` binary mode, `-a` treat the binary as text, `-P` Perl-style regex so `\x03\x04` means those exact bytes.
- Output `89062:PK` — the signature is at byte **89,062** = `0x15be6`. Same answer as our eyes.

**Cutting it out (carving):**

```
$ dd if=quote_q4.doc of=carved.zip bs=1 skip=89062 status=none
$ file carved.zip
carved.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
$ unzip -l carved.zip
Archive:  carved.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       47  2026-11-20 21:50   qXvTrbmPLa.xml
```

- `dd if=… of=…` — copy from input file to output file. `bs=1 skip=89062` — 1-byte blocks, skip the first 89,062 bytes. `status=none` — no progress output.
- Everything from the `PK` onwards is copied, including some trailing bytes; ZIP tools tolerate those because they locate the archive's end record.
- `file` now recognises it, because its signature is at offset 0.

**Tools that do this automatically.** **binwalk** (firmware analysis favourite), **foremost** and **scalpel** (forensic carvers) scan the **whole** file for known signatures and can extract what they find. A typical binwalk result looks like this (trimmed):

```
$ binwalk quote_q4.doc
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
89062         0x15BE6         Zip archive data, at least v2.0 to extract, compressed size: 12, uncompressed size: 47, name: qXvTrbmPLa.xml
89178         0x15C5A         End of Zip archive, footer length: 22
```

- `DECIMAL` / `HEXADECIMAL` — the offset of each hit.
- `DESCRIPTION` — what signature matched, plus fields parsed from that header (sizes, member name). The "End of Zip archive" line marks where the archive ends, so the carver knows how much to cut.
- `binwalk -e` (extract) would carve and unpack it into a directory.

<strong>[Caution]</strong> Signature scanners produce **false positives**: a random 2-byte `MZ` or `PK` appears by chance in large binaries all the time. That's why we checked the bytes **after** the signature (version, method, a sensible name length). One matching signature is a lead, not a conclusion. For network captures, the same ideas apply with Wireshark/Zeek extraction; see [Carving exfiltrated data](../../network-forensics/part-1/lab-carving-exfiltrated-data.md).

## Polyglots — one file, two valid types { #polyglots }

What makes a file "a PDF"? Not its name or extension. If its bytes **carry PDF magic**, **follow the PDF specification**, and **open in a PDF reader**, then for every practical purpose it **is** a PDF. But can that same file also be something else? Yes. A file that's valid in two or more formats at once is a **polyglot**.

It's possible because formats differ in **where they look**:

- PDF readers search for `%PDF-` within roughly the **first kilobyte**, not strictly at byte 0, and find objects by reading a table near the **end**.
- ZIP readers start from the **end** of the file (the end-of-central-directory record) and work backwards.
- HTML and HTA engines skip anything that isn't a tag and run whatever `<script>` they find.
- Image viewers read from the **start** and ignore trailing bytes after the image ends.

So a file can begin as a valid JPEG (the viewer is happy), end with a valid ZIP (the archiver is happy), and both programs open "their" file. A well-known demonstration was a picture posted on social media that, saved and renamed, unzipped into a multi-part archive containing the complete works of Shakespeare.

An analogy: a picture that shows a vase or two faces depending on how you look at it. Nothing about the ink changes; only the reader does. Technically, the "type" of a polyglot depends on **which parser opens it**, which is why a gateway that checks the first bytes (sees "image") and a user's system that opens it with another program (sees "archive" or "script") can disagree — and the attacker exploits that gap.

Once a curiosity, polyglots are now seen in real intrusions. Two examples worth knowing:

- In 2023 JPCERT/CC described "**MalDoc in PDF**": a file that looks like a PDF to scanners (`%PDF-` header, PDF objects) but contains an MHT/Word document with a macro, so **Word opens it as a document** and runs the macro if the file is renamed `.doc`.
- In early 2025 Proofpoint reported a targeted campaign against UAE aviation and transport organisations that used **polyglot files** (for example, a file valid as both PDF and HTA, and a PDF with a ZIP appended) to hide the payload stages of a new backdoor.

How to spot them:

- `file -k` (all matches) or `trid` showing **more than one strong type**.
- A signature scan (`binwalk`, `grep -obUaP`) finding a **second format's header or footer** in an unexpected place — a `PK\x05\x06` end record at the end of a "PDF", `<script` or `<HTA:APPLICATION` in an "image".
- **Size that doesn't fit the content** — a 2 MB "favicon".
- Data **after the logical end** of a format: after a PNG's `IEND` chunk, after a JPEG's `FF D9` end marker, after a PDF's final `%%EOF`.

## Unicode and encodings { #unicode }

Before we look for readable text inside files (the next page, `strings`), you need to know how text becomes bytes, because the same word can be **three completely different byte sequences**.

**ASCII** is the old American standard: 128 characters (English letters, digits, punctuation, control codes), one byte each, `A` = `0x41`. Fine for English, useless for Korean, Japanese, Arabic, Cyrillic or emoji. After many competing schemes, **Unicode** won: one big list that gives **every character a unique number**, called a **code point**, written `U+` plus hex. `A` is `U+0041`; the Kanji/Hanja character 学 ("study", 학 in Korean) is `U+5B66`; 😀 is `U+1F600`.

The code space runs from `U+0000` to `U+10FFFF` — **1,114,112** possible code points. Not all are assigned; Unicode 17.0 (September 2025) defines roughly 160,000 characters.

A code point is just a number. How that number is written into a file is the job of an **encoding**. Using 3 bytes for every character would cover the whole range but is an awkward size for computers; 4 bytes each is easy but wastes space, since most text is plain letters with lots of leading zeros. So several encodings exist:

| Encoding | Bytes per character | `A` (U+0041) | 学 (U+5B66) | 😀 (U+1F600) |
| --- | --- | --- | --- | --- |
| ASCII | 1 (only 128 chars) | `41` | cannot encode | cannot encode |
| UTF-8 | 1–4, variable | `41` | `E5 AD A6` | `F0 9F 98 80` |
| UTF-16 (big-endian shown) | 2 or 4, variable | `00 41` | `5B 66` | `D8 3D DE 00` (surrogate pair) |
| UTF-32 (big-endian shown) | always 4 | `00 00 00 41` | `00 00 5B 66` | `00 01 F6 00` |

The string **`学SOC1`** in each:

```
UTF-8   : e5ada6 53 4f 43 31
UTF-16  : 5b66 0053 004f 0043 0031
UTF-32  : 00005b66 00000053 0000004f 00000043 00000031
```

(One space between characters for readability.) Reading it:

- **UTF-8** — English letters are **identical to ASCII** (`53 4f 43 31` = `SOC1`), no padding. 学 takes **three** bytes. This is UTF-8's great trick: ASCII text is already valid UTF-8, and other characters use more bytes only when needed. It's why UTF-8 dominates the web and Linux.
- **UTF-16** — every character here is **two** bytes; English letters get a `00` byte. Characters above `U+FFFF` (like emoji) need **four** bytes, a "surrogate pair", so UTF-16 is variable-length too. Windows uses UTF-16 internally, which matters a lot for `strings` and PowerShell.
- **UTF-32** — every character is exactly **four** bytes. Simplest to process (character *n* is at byte *4n*), most wasteful.

How 学 becomes `E5 AD A6` in UTF-8 — worth seeing once, because it shows why UTF-8 bytes are recognisable:

```
U+5B66 in binary:          0101 1011 0110 0110   (16 bits)
3-byte UTF-8 template:     1110xxxx 10xxxxxx 10xxxxxx
fill the 16 bits in:       1110 0101  10 101101  10 100110
in hex:                    E5         AD         A6
```

- The first byte's `1110` prefix says "this character is **3** bytes long" (`110` = 2 bytes, `11110` = 4 bytes).
- Every following byte starts with `10` ("continuation byte").
- So bytes `0x80`–`0xFF` in valid UTF-8 always come in these patterns — which is how tools (and `file`) can tell UTF-8 from random binary.

**Byte order and the BOM.** For UTF-16 and UTF-32, the bytes of each unit can be written big-end first (`00 41`) or little-end first (`41 00`). Windows uses **little-endian UTF-16** ("UTF-16LE"), so `A` is `41 00`. A file can announce its encoding with a **byte order mark (BOM)** at the start: `FF FE` (UTF-16LE), `FE FF` (UTF-16BE), `EF BB BF` (UTF-8 with BOM, common in files saved by Windows tools). Without a BOM, a program has to guess:

```
$ file bom8 bom16 u16
bom8:  Unicode text, UTF-8 (with BOM) text
bom16: Unicode text, UTF-16, little-endian text, with no line terminators
u16:   data
```

- `bom8`, `bom16` — `file` reads the BOM and is sure.
- `u16` — the same UTF-16LE text **without** a BOM: `file` gives up and says `data`. Text that `file` calls "data" isn't necessarily binary.

Why a SOC analyst cares:

- **Decode with the wrong encoding and you get garbage.** UTF-8 `e5 ad a6` read as Latin-1 shows `å­¦`; read as UTF-16 it's two meaningless characters. When a log or a web page shows "mojibake" like that, the encoding is wrong, not the data.
- **Searches miss.** Searching a binary or memory dump for the ASCII bytes of `powershell` won't find the UTF-16LE version `p\0o\0w\0e\0r\0…` — which is exactly how Windows programs store most strings. PowerShell's `-EncodedCommand` is Base64 of **UTF-16LE** text (see [Base64](../http-analysis/base64.md)).
- **Look-alike characters.** Cyrillic `а` (`U+0430`) looks identical to Latin `a` (`U+0061`) but is a different code point and different bytes. Domain spoofing with this is covered in [Blockchain DNS and IDNs](../dns/blockchain-dns-and-idn.md).
- **Invisible control characters.** The **right-to-left override** `U+202E` reverses how the rest of a name is **displayed**: a file really named `invoice_<U+202E>fdp.exe` shows in Explorer as `invoice_exe.pdf`. It's still an `.exe` — and the magic bytes would say `MZ`. ATT&CK: **Masquerading: Right-to-Left Override (T1036.002)**.

## Putting it together — a triage routine for an unknown file { #routine }

Back to the alert: `x`, delivered as `image/png`.

```
$ file x
x: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
$ file -i x
x: application/x-dosexec; charset=binary
$ hexdump -C x | head -1
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
$ sha256sum x
5e0c7a…(64 hex characters)  x
```

1. `file` → a 32-bit **DLL**. Not a PNG.
2. `file -i` → `application/x-dosexec`, which contradicts the server's `Content-Type: image/png`. That mismatch alone is reportable.
3. Hex → `MZ` at offset 0 confirms it with your own eyes.
4. Hash it (hashing has its own page later in this section) and check the hash in your threat-intelligence tools **without uploading the file** if OPSEC matters.
5. Next steps: `strings` for clues (next page), check whether it ran (on the endpoint: Sysmon 7 image loads, `rundll32.exe`/`regsvr32.exe` process creation — see [Process creation](../important-events/process-creation.md)), and hunt for the same `mime_type` mismatch in Zeek `files.log` across the network.

What the SOC records, in one line: *"Response from `cdn-update.example` declared `image/png`; content is a PE32 DLL (MZ, PE header, i386); SHA-256 5e0c7a…; T1036.008 masquerade file type."*

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Files are still byte sequences, extensions and `Content-Type` are still attacker-controlled claims, and the identification routine — `file`, a hex view, magic bytes, a signature scan for nested content, then deeper analysis — is unchanged. The magic bytes themselves never change (`MZ`, `PK\x03\x04`, `%PDF-`, `\x7fELF`…), and Office Open XML is still ZIP. Unicode, UTF-8/16/32 and Windows' use of UTF-16LE are as described. `file` (libmagic 5.4x in current distributions) remains the standard first step.

!!! info "[Changed] What has changed"
    - **Polyglots moved from curiosity to real tradecraft.** "MalDoc in PDF" (JPCERT/CC, 2023) showed a PDF-looking file that Word opens and runs as a macro document, and in 2025 Proofpoint documented a targeted espionage campaign against UAE aviation and transport firms built on polyglot files (PDF/HTA, PDF with appended ZIP). Treat "this file matches two formats" as a finding, not trivia.
    - **The delivery file mix changed after Microsoft started blocking internet macros** (Office, from 2022): attackers shifted to archives and disk images (ZIP, RAR, 7z, ISO, IMG, VHD), LNK shortcuts, OneNote files, HTML smuggling and, especially in 2024–2025, **SVG attachments** carrying JavaScript or embedded HTML phishing pages, reported as a sharp rise by several email-security vendors. An "image" that `file` calls `SVG Scalable Vector Graphics image` deserves a look inside, because it's text that browsers execute.
    - **Tooling.** binwalk was rewritten in Rust (v3, 2024–2025): faster, with different output and options from the Python v2 you'll see in older guides. Detect It Easy and TrID remain common on Windows; many EDR and email gateways now do "true file type" detection built in.
    - **ATT&CK naming.** Disguised file types are **T1036.008 Masquerade File Type** (added in 2023), embedded payloads are **T1027.009**, right-to-left override is **T1036.002**, double extensions are **T1036.007**.
    - **Unicode keeps growing** (Unicode 17.0 in September 2025, around 160,000 characters), so look-alike and invisible characters in file names, URLs and code remain an evolving problem.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't treat the first `file` answer as the whole truth.** It reads the start of the file and reports one match. Use `file -k`, a signature scan and a look at the end of the file for anything suspicious.
    - **Don't assume `%PDF-` must be at byte 0, or that ISO magic is at the start.** PDF readers accept the header within about the first kilobyte (attackers use that), and ISO's `CD001` sits at `0x8001`.
    - **Don't assume "text" means safe.** Scripts without a shebang, SVG, HTML and HTA all show up as text. Text files that run are among the most common phishing payloads.
    - **Don't search binaries only for ASCII.** Windows strings are usually UTF-16LE; search both, or use tools that do (next page).
    - **Don't identify files on your own workstation or by opening them.** Use an isolated analysis VM, and keep `file`/libmagic updated — the identifier is itself parsing hostile input.
    - **Don't trust a single 2-byte hit** from a signature scan in a large binary. Validate the header fields that follow.

## Practice questions { #quiz }

### Question 1

A proxy log shows `GET http://static-img.example/logo.png` returning `200`, `Content-Type: image/png`, 418,816 bytes. You extract the body and run:

```
$ file logo.png
logo.png: PE32+ executable (DLL) (GUI) x86-64, for MS Windows
$ hexdump -C logo.png | head -1
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
```

What is this file, what three "claims" were false, and what would you do next?

??? success "Answer and explanation"
    **What it is:** a **64-bit Windows DLL**. `file` reports `PE32+ … (DLL) … x86-64`, and the hex dump starts with `4d 5a` = **`MZ`**, the Windows executable signature. A real PNG would start with `89 50 4E 47 0D 0A 1A 0A`.

    **The false claims:** (1) the **file name/extension** `logo.png`, (2) the server's **`Content-Type: image/png`**, and (3) by implication the URL path (`static-img`, `logo`) that suggests a harmless image. All three are controlled by whoever runs the server. Only the bytes are evidence. This is **T1036.008 Masquerade File Type**.

    **Next:** hash it and check reputation (without uploading if OPSEC matters); run `strings` for clues; on the endpoint, check whether it was loaded or executed (process creation of `rundll32.exe`/`regsvr32.exe` with that file, Sysmon 7 image loads, where it was written on disk); hunt across the network for other "images" whose detected MIME type is `application/x-dosexec` (Zeek `files.log`); and block the domain.

### Question 2

A colleague says: "The `file` command said `Composite Document File V2 Document`, so it's just an old Word file. Nothing else inside." You then run `LC_ALL=C grep -obUaP "PK\x03\x04" quote_q4.doc` and get `89062:PK`. Explain why the colleague's conclusion doesn't follow, what the output means, and how you'd confirm it.

??? success "Answer and explanation"
    **Why it doesn't follow:** `file` checks the **start** of the file (here the OLE signature `D0 CF 11 E0…`) and reports **one** match. It does not search the rest of the file, so a file **embedded** further in is invisible to it.

    **What the output means:** the ZIP local file header signature **`PK\x03\x04`** occurs at **byte offset 89,062** (`0x15be6`). Something that looks like the start of a ZIP archive is buried inside the document.

    **How to confirm:** check the bytes after the signature make sense for a ZIP header (version `14 00`, method `08 00` deflate, a sensible file-name length followed by a name — here `qXvTrbmPLa.xml`), because a random `PK` can occur by chance. Then carve from that offset (`dd … skip=89062`, or `binwalk -e`), run `file`/`unzip -l` on the result, and hand it on for analysis. In ATT&CK terms this is **Embedded Payloads (T1027.009)** — whether this particular ZIP is malicious still needs analysis.

### Question 3

(a) Why do DOCX and ZIP files start with the same bytes? (b) The string `cmd` is stored by a Windows program as `63 00 6d 00 64 00`. Which encoding is that, and why would an ASCII-only search for `63 6d 64` miss it? (c) A user opened a file that Explorer displayed as `invoice_exe.pdf`, but your EDR says a PE executable ran. What trick might explain that?

??? success "Answer and explanation"
    **(a)** Because a DOCX **is** a ZIP. Since Office 2007, Office Open XML documents (`.docx`, `.xlsx`, `.pptx`) are ZIP archives of XML parts (`[Content_Types].xml`, `word/document.xml`, …), so they carry the ZIP signature `50 4B 03 04` (`PK\x03\x04`). Rename one to `.zip` and `unzip -l` lists its parts. (Old `.doc` uses the OLE container, `D0 CF 11 E0…`, instead.)

    **(b)** **UTF-16 little-endian** (UTF-16LE): each English character takes two bytes, the character's ASCII value followed by `00`. Windows uses UTF-16LE for most internal strings. An ASCII search looks for the consecutive bytes `63 6d 64`, but in the file they're separated by `00` bytes, so there's no match. Search for both encodings (most string tools have an option for 16-bit little-endian).

    **(c)** Most likely the **right-to-left override** character `U+202E` in the file name — for example the real name `invoice_` + `U+202E` + `fdp.exe`. Everything after `U+202E` is **displayed** reversed, so it shows as `invoice_exe.pdf`, but the name really ends in `.exe` and Windows runs it as a program. The magic bytes (`MZ`) and the EDR agree it's an executable. ATT&CK: **T1036.002 Right-to-Left Override**. Detection: look for `U+202E` (bytes `E2 80 AE` in UTF-8) in file names in process-creation and file-creation logs.

## Related { #related }

- [Malicious files on good sites, file extraction](../http-analysis/files-frequency-naked-ip.md) · [Response headers and Content-Type](../http/responses.md#content-type)
- [Screenshots, sandboxes, and when to go manual](../http-analysis/screenshots-sandboxes.md) · [Base64](../http-analysis/base64.md)
- [Zeek files.log & pe.log](../../../network/zeek/files-log.md) · [Carving exfiltrated data](../../network-forensics/part-1/lab-carving-exfiltrated-data.md)
- [Phishing delivery & initial execution](../../../adversary/phishing-delivery.md) · [Blockchain DNS and IDNs](../dns/blockchain-dns-and-idn.md)
- [Process creation events](../important-events/process-creation.md)
