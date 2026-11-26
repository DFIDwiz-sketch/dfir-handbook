---
title: "RTF, PDF and Other Files as Exploits — and Quickly Sorting Good from Bad"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
  - phishing
---

# RTF, PDF and Other Files as Exploits — and Quickly Sorting Good from Bad { #rtf-pdf-misc-triage }

!!! abstract "What this page covers"
    The previous page covered executables, scripts and Office documents. This one covers the formats people **trust more than they should**. **RTF** (Rich Text Format): it has no macros, but it can carry embedded files and links and has a long record of exploits. Because Word opens it whatever the extension says, attackers often rename it `.doc`. We take a harmless test RTF apart byte by byte: control words, the hex-encoded `\objdata` blob, how to spot an executable inside it with `grep`, and what `rtfobj` reports. **PDF**: links to phishing pages, embedded files, JavaScript, auto-run actions and reader exploits. We read a harmless test PDF's objects through `strings`, then `pdfid`'s keyword counts line by line, and see why a compressed stream hides a URL until you decompress it. **Other files** (pictures, fonts, audio and video, email, `.lnk` shortcuts): rare but real. They work through bugs in the program that parses them, and some of those bugs are in the Windows kernel. Shortcuts also work as a sneaky script launcher. We finish with a six-step routine for **quickly sorting good from bad**, applied to both test files. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs). The RTF and PDF samples on this page are harmless test files built for this page. The "executable" inside the RTF is a few bytes that look like a PE header followed by a text label, and it cannot run. The PDF's JavaScript only shows a message box.

## The 8 key points { #key-points }

1. **RTF has no macros, and that does not make it safe.** It can embed files (OLE objects), link to remote content and trigger parser bugs. Several of the most-used document exploits ever were delivered as RTF.
2. **Word decides by content, not by extension.** An RTF renamed `.doc` opens fine, and so does a `.doc` renamed `.rtf`. Check the first bytes: RTF starts with `{\rtf` (all printable text), OLE `.doc` with `D0 CF 11 E0`, DOCX with `PK`.
3. **Everything in RTF is text, including embedded files.** An embedded object sits in `\objdata` as **hex digits**. So an executable inside shows up as the text `4d5a…` (`MZ`), and the DOS sentence as `546869732070726f6772616d…`. `grep` for those, or let `rtfobj` decode them.
4. **The keywords that matter in RTF** are `\object`, `\objdata`, `\objclass`, `\objupdate` (forces the object to refresh on open, a classic exploit trigger) and `\*\template` (remote template, T1221).
5. **PDFs are weaponised four ways:** links (by far the most common: credential-phishing pages), embedded files, JavaScript and auto-run actions (`/OpenAction`, `/AA`, `/Launch`), and exploits against the reader. Flash content is dead, but the keywords still show up in old samples.
6. **`strings` + `grep http` pulls links out of a PDF without opening it**, but only from **uncompressed** objects. `pdfid` counts the risky keywords. Decompress streams before you conclude there's nothing there.
7. **Pictures, fonts, media, email and shortcuts can be malicious too**, through bugs in whatever parses them (sometimes the kernel, sometimes the email preview pane). `.lnk` shortcuts don't even need a bug: they can launch `cmd` or `powershell` with an encoded command.
8. **Quick triage, in order:** hash lookup → digital signature → look at it safely (screenshot/VM) → `strings` for things that don't belong (`MZ` in a non-executable, script in a picture, odd URLs) → obfuscated scripts → sandbox to see behaviour. Every step is a lead, not a verdict.

## Why this matters in a SOC { #why }

Mail gateways and users have learned that `.exe` attachments are bad and that "Enable Content" is a trap. Attackers responded by using formats that look harmless. An RTF "statement", a PDF "invoice", a picture, a shortcut inside a ZIP. These pass through more filters and get opened more readily. It's like a burglar wearing a delivery uniform: the door opens because of what he looks like, not because anyone checked the parcel.

These formats can't be blocked at the border, because every business sends PDFs and many still exchange RTF. So the SOC's job is to **look inside** them quickly and safely, decide good or bad, and turn what's inside (URLs, embedded file hashes, process behaviour) into blocks and hunts. This page gives you the byte-level picture of each format and a fast routine for that decision.

## Rich Text Format (`.rtf`) { #rtf }

### What RTF is { #rtf-what }

RTF is a document format from the late 1980s, designed so that word processors could exchange formatted text. Unlike `.doc` (a binary OLE container) or `.docx` (a ZIP of XML files), **an RTF file is plain text**: printable characters describing formatting with a markup language. Three building blocks:

- **Control words**: a backslash plus a word, optionally followed by a number: `\rtf1`, `\par`, `\fs22`. They are instructions ("new paragraph", "font size 11 pt").
- **Groups**: curly braces `{ … }` that scope settings, like brackets in maths.
- **Destinations**: groups that start with `\*` mean "if you don't understand this control word, skip the whole group". This is how optional data is added, and attackers love it because a parser that skips unknown groups also lets them hide junk.

Why is a "simple" format dangerous? Because RTF can do most of what Office documents can: **embed OLE objects** (files, other documents, equation objects), **link** to remote content, and load templates. And a parser that has to read decades of loosely specified, tolerant syntax has bugs. The one thing RTF **cannot** do is hold VBA macros. People hear that and conclude it's safe, which is exactly why attackers use it.

### Extension games: `.doc` that is really RTF { #rtf-extension }

Word looks at the **content** to decide how to open a file. An RTF saved as `statement_nov.doc` opens as RTF, and a macro-laden OLE `.doc` renamed `.rtf` still opens as a `.doc`. Attackers use both directions: name an RTF `.doc` so it looks like an ordinary document, or name a `.doc` `.rtf` so you assume "no macros". So, as always, the extension tells you nothing. The bytes do:

```
$ file statement_nov.doc
statement_nov.doc: Rich Text Format data, version 1, ANSI, code page 1252
```

- `file` ignored the `.doc` extension and identified RTF from the opening `{\rtf1`.
- `version 1` comes from `\rtf1`, `ANSI` from `\ansi`, `code page 1252` from `\ansicpg1252` (Western European Windows code page).

The hex view shows why RTF is easy to tell apart from Office formats. Every byte is printable:

```
$ python3 hexview.py statement_nov.doc | head -8
00000000  7b 5c 72 74 66 31 5c 61  6e 73 69 5c 61 6e 73 69  |{\rtf1\ansi\ansi|
00000010  63 70 67 31 32 35 32 5c  64 65 66 66 30 7b 5c 66  |cpg1252\deff0{\f|
00000020  6f 6e 74 74 62 6c 7b 5c  66 30 20 43 61 6c 69 62  |onttbl{\f0 Calib|
00000030  72 69 3b 7d 7d 0a 7b 5c  2a 5c 67 65 6e 65 72 61  |ri;}}.{\*\genera|
00000040  74 6f 72 20 4d 73 66 74  65 64 69 74 20 35 2e 34  |tor Msftedit 5.4|
00000050  31 2e 32 31 2e 32 35 31  30 3b 7d 5c 76 69 65 77  |1.21.2510;}\view|
00000060  6b 69 6e 64 34 5c 75 63  31 5c 70 61 72 64 5c 66  |kind4\uc1\pard\f|
00000070  30 5c 66 73 32 32 20 50  6c 65 61 73 65 20 72 65  |0\fs22 Please re|
```

- The analysis VM had no `hexdump` or `xxd`, so a ten-line Python script printed the same layout as `hexdump -C`: offset, 16 bytes in hex, then the ASCII column.
- `7b 5c 72 74 66 31` = `{\rtf1`, the RTF magic. Compare `D0 CF 11 E0` for an OLE `.doc` and `50 4B 03 04` (`PK..`) for a `.docx` on [the file identification page](file-identification.md#magic-bytes).
- The ASCII column is readable all the way across. The only `.` is at `0x35`, which is `0a`, a newline. A binary format never looks like this.

**[Supplement]** Word is famously lenient about the header. It only needs roughly `{\rt` at the start, so malicious RTFs often begin `{\rtx…` or `{\rt0…` to break naive "starts with `{\rtf1`" filters. Look for `{\rt` and treat any variation as suspicious in itself.

### Reading the test RTF line by line { #rtf-read }

Here is the whole test file (the hex blob is shortened):

```
{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Calibri;}}
{\*\generator Msftedit 5.41.21.2510;}\viewkind4\uc1\pard\f0\fs22 Please review the attached statement.\par
{\object\objemb\objw1440\objh1440{\*\objclass Package}{\*\objdata
0105000002000000080000005061636b61676500010000000001000000001201
000002007570646174652e65786500433a5c55736572735c6465765c4465736b
...
}}\par
}
```

| Piece | What it means |
| --- | --- |
| `{\rtf1` | Start of the document group, RTF version 1 |
| `\ansi\ansicpg1252` | Character set ANSI, code page 1252 |
| `\deff0{\fonttbl{\f0 Calibri;}}` | Default font is font 0. The font table defines font 0 as Calibri |
| `{\*\generator Msftedit 5.41.21.2510;}` | Optional destination naming the program that wrote the file. It's easy to fake, but a mismatch with the claimed story is still a clue |
| `\pard\f0\fs22` | Reset paragraph formatting, use font 0, size 22 half-points (11 pt) |
| `Please review the attached statement.\par` | The visible text, then end of paragraph |
| `{\object\objemb` | **An OLE object starts here**, of the **embedded** kind (the data is inside the file) |
| `\objw1440\objh1440` | Object width and height in twips (1440 twips = 1 inch): a one-inch icon on the page |
| `{\*\objclass Package}` | The object's class is **Package**, the OLE "Packager" that wraps an arbitrary file. It's the classic way to put an `.exe`, `.js` or `.hta` inside a document |
| `{\*\objdata 0105…}` | The object's bytes, written as **hex digits** |

Other object keywords to know:

- `\objlink` / `\objautlink`: the object is a **link** to data somewhere else (a file or URL), not embedded.
- `\objupdate`: "refresh this object as soon as the document opens". Without it, a user would have to double-click the object. With it, Word fetches or activates the object by itself. That's what turned several RTF bugs into **one-double-click** infections.
- `\*\template`: load a template from this path or URL. Pointing it at a remote server is **template injection** (ATT&CK **T1221**). The document is clean, and the template it fetches carries the payload.
- `\*\datastore`, `\*\objdata` with class `Equation.3` or `OLE2Link`: classes tied to famous exploits (below).

### Finding an embedded file in the hex { #rtf-objdata }

Decoding the start of `\objdata`, which is the OLE 1.0 object header:

```
01050000 02000000 08000000 5061636b61676500 ...
```

- `01050000`: OLE version `0x00000501`, little-endian (bytes stored backwards, as on [the strings page](strings.md#byte-order)).
- `02000000`: format ID `2` = **embedded** object (`1` would be linked).
- `08000000`: the class name that follows is 8 bytes long.
- `5061636b61676500`: `P a c k a g e \0`. Same class as `\objclass`.

Further on, `7570646174652e65786500` decodes to `update.exe\0`: the embedded file's name. You don't need to decode by hand to triage. Because the embedded bytes are written as hex text, you can grep for the **hex of signatures you already know**:

```
$ grep -o "4d5a9000" statement_nov.doc
4d5a9000
$ grep -c "546869732070726f6772616d" statement_nov.doc
1
```

- `4d5a9000` = `MZ` followed by `90 00`, the start of a typical Windows executable ([magic bytes](file-identification.md#magic-bytes)).
- `546869732070726f6772616d` = `This program`, the start of the DOS stub sentence. One match.
- An executable inside an emailed statement has no innocent explanation. This is the "magic bytes where they don't belong" check from the triage list below.
- Caution: the hex in `\objdata` can be broken across lines (as here), mixed with whitespace, or padded with junk control words that the parser ignores. A `grep` miss is **not** proof of absence. That's why you also run a parser.

**[Supplement]** `rtfobj` (part of **oletools**) parses RTF the way Word does, extracts every object and identifies it:

```
$ rtfobj statement_nov.doc
===============================================================================
File: 'statement_nov.doc' - size: 862 bytes
---+----------+---------------------------------------------------------------
id |index     |OLE Object
---+----------+---------------------------------------------------------------
0  |000000E2h |format_id: 2 (Embedded)
   |          |class name: b'Package'
   |          |data size: 274
   |          |OLE Package object:
   |          |Filename: 'update.exe'
   |          |Source path: 'C:\\Users\\dev\\Desktop\\update.exe'
   |          |Temp path = 'C:\\Users\\dev\\AppData\\Local\\Temp\\update.exe'
   |          |MD5 = '7a22d6d62fd72ea377a4407885c54e40'
   |          |EXECUTABLE FILE
   |          |File Type: Windows PE Executable or DLL
---+----------+---------------------------------------------------------------
```

- `id 0`, `index 000000E2h`: the first object, starting at offset `0xE2` in the RTF.
- `format_id: 2 (Embedded)`, `class name: b'Package'`: what we decoded by hand.
- `data size: 274`: the native data size in bytes.
- `Filename: 'update.exe'`: the name the user would see under the icon. It's set by the attacker, so it may say `Statement.pdf` while being an `.exe`.
- `Source path: 'C:\\Users\\dev\\Desktop\\update.exe'`: **where the file was on the attacker's machine** when they embedded it. Packager records this automatically. User names and folder layouts in source paths are useful for clustering campaigns.
- `Temp path = …\AppData\Local\Temp\update.exe`: where Packager drops the file when the user double-clicks the icon. **Hunt for this path** in file-creation and process-creation logs.
- `MD5 = '…'`: hash of the embedded file. Look it up and add it to your IOCs (MD5 is fine as a lookup key, see the next page for its limits).
- `EXECUTABLE FILE` / `File Type: Windows PE Executable or DLL`: rtfobj checked the embedded bytes and found `MZ`. Here that's a harmless fake, but in real mail this is a red flag.
- `rtfobj -s 0 -d outdir statement_nov.doc` saves object 0 to a folder, so you can hash it and run `file` and `strings` on it in the analysis VM.

### Famous RTF exploits and what they leave behind { #rtf-exploits }

| CVE | What it abused | How the RTF triggered it | What you see on the endpoint |
| --- | --- | --- | --- |
| CVE-2017-0199 | Office's handling of an `OLE2Link` object pointing to a URL that returns an **HTA** | `\objautlink` + `\objupdate`: Word fetched the remote document on open and ran it. No macro, no warning bar | `WINWORD.EXE` → `mshta.exe` with a URL, then PowerShell/VBScript downloading the next stage |
| CVE-2017-11882, CVE-2018-0802 | Buffer overflows in the old **Equation Editor** (`EQNEDT32.EXE`) | An `Equation.3` object in the RTF. Opening it started the vulnerable process | `EQNEDT32.EXE` running at all (and spawning `cmd`/`powershell`). Microsoft removed Equation Editor in January 2018, but old builds and unpatched installs lingered for years |
| CVE-2017-8570 | Another OLE moniker path similar to 0199, used to drop a scriptlet | Embedded object with a crafted moniker | Script host (`wscript`, `cscript`, `mshta`) as a child of Word |
| CVE-2023-21716 | Heap corruption in Word's **RTF parser** (font table handling) | Just parsing the file. Even the Outlook **preview pane** was enough | Word or Outlook crashing or spawning children. Patched February 2023 |

The common pattern is that the document only has to be **opened or previewed**. That's ATT&CK **T1203 Exploitation for Client Execution**, usually delivered by **T1566.001 Spearphishing Attachment** and relying on **T1204.002 User Execution: Malicious File** for the first click. In investigations, the endpoint side is often clearer than the file. Here's what the CVE-2017-0199 chain looks like in a process-creation event (**4688**, "A new process has been created". It fires every time a process starts, and attackers care because it records what ran, with what command line, and started by whom; see [process creation events](../important-events/process-creation.md)):

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-11-24T02:13:48.0912254Z" />
    <Computer>HR-WS-0042.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">s.park</Data>
    <Data Name="NewProcessName">C:\Windows\System32\mshta.exe</Data>
    <Data Name="CommandLine">C:\Windows\System32\mshta.exe -Embedding</Data>
    <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
    <Data Name="TokenElevationType">%%1938</Data>
  </EventData>
</Event>
```

- `NewProcessName …mshta.exe`: the Windows HTML Application host. It runs HTA files (HTML plus script with full user rights), **T1218.005 Mshta**.
- `CommandLine mshta.exe -Embedding`: `-Embedding` means it was started by COM/OLE on behalf of another program. The HTA it fetched isn't in the command line. Look at the network logs for Word's or mshta's HTTP request right before this.
- `ParentProcessName …WINWORD.EXE`: Word started it. Word has almost no legitimate reason to start `mshta.exe`. This parent-child pair is the detection.
- `TokenElevationType %%1938`: a limited token, normal user rights. The exploit didn't need admin.

### How to triage an RTF { #rtf-triage }

1. `file` it. An RTF named `.doc`, or a header that isn't exactly `{\rtf1`, is a first warning.
2. `grep -c '\\object' file`, `grep -c '\\objupdate'`, `grep -ci 'objclass'`, `grep -c '\\\*\\template'`. A one-paragraph "statement" doesn't need embedded objects.
3. `rtfobj file` lists and identifies every object. `-s all -d out/` extracts them for hashing and deeper analysis.
4. `grep -i "4d5a"` and the DOS-sentence hex. `d0cf11e0` (an OLE file inside) and `504b0304` (a ZIP inside) are also interesting.
5. If the object is `Equation.3` or `OLE2Link`, assume exploit and check the endpoint for `EQNEDT32.EXE` or `WINWORD.EXE` → `mshta.exe`.

## PDF files { #pdf }

### Why PDFs are such a common attack vector { #pdf-why }

PDF is everywhere: invoices, contracts, payslips, shipping notices. You can't block it at the mail gateway, and users open it without thinking. So you need tools that understand its structure and can look inside. A PDF can be weaponised in the same ways as other documents, plus a few of its own:

- **Links** to malicious sites. This is by far the most common case today: the PDF is a fake "invoice" or "shared document" page with a big button leading to a cloned Microsoft 365 or Google sign-in page. There's nothing to "detonate"; the user does the damage by typing a password. Increasingly, the link is a **QR code** image, so the user scans it on a phone outside your controls ("quishing").
- **Embedded files**: PDFs can carry attachments (`/EmbeddedFile`), including executables or scripts.
- **JavaScript** that runs when the document opens, and **actions** that run automatically: `/OpenAction` (on open), `/AA` (additional actions on page view, close, etc.), `/Launch` (start a program or open a file).
- **Flash** content (`/RichMedia`) historically, and **exploits** against the reader itself (Adobe Reader, Foxit, browser PDF engines).
- **Forms** (`/AcroForm`, `/XFA`) that can submit data to a URL or host scripts.

Themes are predictable: invoices, remittances, voicemail notices, "document shared with you" from a cloud service, HR policy updates, e-signature requests.

### How a PDF is put together { #pdf-structure }

A PDF is a mostly-text file with binary streams inside. Four parts:

1. **Header**: `%PDF-1.7` (version), usually followed by a comment line of high bytes (`%âãÏÓ`) so transfer tools treat the file as binary.
2. **Body**: numbered **objects**, each `N 0 obj … endobj`. An object is usually a **dictionary** `<< /Key value … >>`, and may carry a **stream** of data (page content, images, fonts, embedded files), often compressed.
3. **Cross-reference table** (`xref`): the byte offset of every object, so a reader can jump straight to one.
4. **Trailer**: points to the root object (`/Root`) and to the xref (`startxref`), ending with `%%EOF`.

References look like `5 0 R` ("object 5, generation 0"). Think of the PDF as a binder with numbered pages and an index at the back. The reader starts at the index, finds the root, and follows references. An attacker's job is to slip a page into the binder that the reader will act on automatically.

### `strings` on a PDF: the quick look { #pdf-strings }

`strings` on our test PDF (`-n 6` to drop the shortest noise):

```
$ strings -n 6 invoice_8841.pdf
%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R /Names << /EmbeddedFiles 7 0 R >> >>
endobj
...
4 0 obj
<< /Length 122 /Filter /FlateDecode >>
stream
	&&.I;
Qh	-Eoo
m@74{4U
endstream
endobj
5 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert\('Test file - harmless'\);) >>
endobj
6 0 obj
<< /Type /Annot /Subtype /Link /Rect [72 650 400 680] /A << /S /URI /URI (https://docs-view.example/inv/8841) >> >>
endobj
...
9 0 obj
<< /Type /EmbeddedFile /Length 25 >>
stream
harmless test attachment
endstream
...
trailer
<< /Size 10 /Root 1 0 R >>
startxref
```

Reading it object by object:

- `%PDF-1.7`: the magic and version.
- **Object 1**, `/Type /Catalog`: the root of the document. `/OpenAction 5 0 R` means **"when the document opens, run object 5"**. `/Names << /EmbeddedFiles 7 0 R >>` means the PDF carries attachments, listed in object 7. Both are things a plain invoice doesn't need.
- **Object 4**, `/Filter /FlateDecode` + `stream`: the page's content stream, **compressed** with zlib/deflate. `strings` shows a few lines of garbage (`&&.I;`, `Qh -Eoo`): random compressed bytes that happen to be printable, exactly the noise explained on [the strings page](strings.md#printable). Whatever text is inside is invisible here.
- **Object 5**, `/S /JavaScript /JS (…)`: an action of type JavaScript with the code in brackets. Here it's a harmless `app.alert`. In a malicious file this is where you'd see obfuscated code, often `eval` with long strings, or `/JS 12 0 R` pointing to a compressed stream.
- **Object 6**, `/Subtype /Link … /URI (https://docs-view.example/inv/8841)`: a clickable rectangle (`/Rect`, in points from the bottom-left) that opens a URL. This is your **phishing link IOC**.
- **Object 9**, `/Type /EmbeddedFile`: the attachment's content. Here it's an uncompressed text file. Real embedded payloads are usually compressed.
- `trailer … /Root 1 0 R`: the reader starts at object 1.

The fastest IOC extraction, without opening the file:

```
$ strings invoice_8841.pdf | grep -i http
<< /Type /Annot /Subtype /Link /Rect [72 650 400 680] /A << /S /URI /URI (https://docs-view.example/inv/8841) >> >>
```

- One URL, from the link annotation. Search the proxy and DNS logs for `docs-view.example`, and for the path `/inv/8841` on any host.
- **But the page text also contains a URL** (we built it in), and `grep` didn't find it, because object 4 is compressed. Decompress the stream (here with three lines of Python's `zlib`; dedicated tools are covered below) and it appears:

```
BT /F1 18 Tf 72 700 Td (Your invoice is ready - click View Document) Tj ET
BT 72 660 Td (https://docs-view.example/inv/8841) Tj ET
```

- `BT … ET`: begin/end a text block. `/F1 18 Tf`: font 1, size 18. `72 700 Td`: move to x=72, y=700 points. `(…) Tj`: draw this string.
- So the page says "Your invoice is ready - click View Document" and prints the URL. That's the lure a user sees.
- Lesson: `strings | grep http` is a great **first** look, and a miss means "look deeper", not "clean".

### `pdfid`: counting the risky keywords { #pdfid }

`pdfid` (by Didier Stevens; here the Python package version) scans a PDF for the names that matter and counts them, without rendering anything:

```
$ python3 -m pdfid invoice_8841.pdf
PDFiD 0.2.7 invoice_8841.pdf
 PDF Header: %PDF-1.7
 obj                    9
 endobj                 9
 stream                 2
 endstream              2
 xref                   1
 trailer                1
 startxref              1
 /Page                  1
 /Encrypt               0
 /ObjStm                0
 /JS                    1
 /JavaScript            1
 /AA                    0
 /OpenAction            1
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          1
 /XFA                   0
 /Colors > 2^24         0
```

| Line | Meaning | Why you care |
| --- | --- | --- |
| `obj`/`endobj` 9 | Nine objects, all closed | Mismatched counts suggest a malformed or deliberately broken file (parser confusion) |
| `stream` 2 | Two data streams | Each one may hide content; decompress them |
| `xref`/`trailer`/`startxref` 1 | One revision | Several mean the file was **incrementally updated**, so content was appended later, sometimes to hide or change things |
| `/Page` 1 | One page | Malicious PDFs are very often a single page: just a lure and a button |
| `/Encrypt` 0 | Not encrypted | Encryption hides strings from scanners (sometimes with an empty password the reader opens silently) |
| `/ObjStm` 0 | No object streams | Object streams pack objects inside compressed streams, hiding keywords from `strings` and naive scanners |
| `/JS` 1, `/JavaScript` 1 | JavaScript present | Normal business PDFs rarely need it. **High interest** |
| `/AA` 0, `/OpenAction` 1 | One automatic action | Combined with `/JavaScript`, this means **code runs on open**. The most suspicious combination |
| `/AcroForm`, `/XFA` 0 | No forms | Forms can carry scripts or submit data |
| `/JBIG2Decode` 0 | No JBIG2 images | That decoder had serious exploited bugs. Rare in normal documents |
| `/RichMedia` 0 | No Flash/media | Historical Flash exploit route |
| `/Launch` 0 | No launch actions | Would start a program or open a file. Very high interest |
| `/EmbeddedFile` 1 | One attachment | Extract it and analyse it as its own file |
| `/Colors > 2^24` 0 | No absurd colour values | An old exploit indicator |

Our test file scores `/JS`, `/JavaScript`, `/OpenAction` and `/EmbeddedFile`. As a real attachment, that would go straight to deeper analysis.

**[Supplement]** Attackers hide names with **hex escapes**: `/J#61vaScript` is still `/JavaScript` to the reader (`#61` = `a`), but not to a naive `grep`. `pdfid` normalises these and shows the obfuscated count in brackets, for example `/JavaScript 1(1)`. Any obfuscated name is suspicious in itself, because legitimate PDF writers have no reason to do it.

The usual next tool is **`pdf-parser`** (same author). It lists objects, searches for keywords (`--search javascript`), shows one object (`-o 5`), and decompresses streams (`-f`) or dumps them to a file (`-d`). Together, `pdfid` → `pdf-parser` is the standard static path, and both are on the common analysis distributions (see [the 2026 view](#trends)).

### What a PDF attack looks like on the endpoint { #pdf-in-logs }

- **Phishing link**: nothing suspicious on the endpoint except a browser visiting the URL right after the PDF was opened. Join the proxy/DNS log (domain from the PDF) with email logs (who got it) to see who clicked.
- **JavaScript/exploit**: the reader (`AcroRd32.exe`, `Acrobat.exe`, `FoxitPDFReader.exe`) starting `cmd.exe`, `powershell.exe`, `rundll32.exe` or writing an `.exe`/`.dll` to Temp. A PDF reader has almost no reason to start a shell.
- **Embedded file / `/Launch`**: the reader writes the attachment to disk, then a process starts from that path. Hunt for file creation under the reader's temp folders followed by process creation from the same path.

## Miscellaneous files as exploits { #misc }

### Can a picture really be malicious? { #misc-how }

Yes, but it's rare and hard to spot. A picture, song, video or font has no "features" to abuse: there's no macro, link or script slot. So the only route is a **bug in the code that parses the file**. Image decoders, font renderers and media codecs read complicated binary structures and do lots of arithmetic on sizes and offsets that come straight from the file. A crafted file with a "width" that overflows a buffer can make the parser write attacker-controlled bytes where code lives, and then the **viewer** runs the attacker's code.

Think of a parser as a clerk who copies forms into a ledger, trusting the "number of lines" box at the top. Lie in that box and the clerk writes over the next page of the ledger. The technical version is a memory-corruption bug (overflow, use-after-free, integer overflow) in the parsing library.

Where the parser runs decides how bad it is:

- In an **application** (an image viewer, a media player, a browser), the attacker gets that app's rights, often sandboxed.
- In the **Windows kernel**, it's deadly. For years Windows parsed some fonts inside the kernel (`win32k.sys`, and the Adobe Type Manager font driver `ATMFD.DLL`). A font bug there meant code execution with **kernel privileges** just from rendering text, for example on a web page or in a document preview.
- In a **preview** feature (Explorer's preview pane, Outlook's reading pane, thumbnail generation), the user doesn't even have to open the file.

Examples:

| CVE | Format / component | Trigger |
| --- | --- | --- |
| CVE-2010-2568 | Windows Shell `.lnk` icon handling | **Displaying** a folder with a crafted shortcut (e.g. on a USB stick). Used by Stuxnet |
| CVE-2018-1010 | Windows font library | Viewing a page or document that loads a crafted embedded font |
| CVE-2018-8475 | Windows image handling | **Viewing** a crafted picture |
| CVE-2020-1349 | Outlook | **Previewing** a crafted email in the reading pane |
| CVE-2023-4863 [Supplement] | `libwebp` image library (used by Chrome and many other apps) | Rendering a crafted WebP image. Exploited in the wild in 2023, and the fix had to reach every app that bundled the library |
| CVE-2023-23397 [Supplement] | Outlook reminders | A calendar item whose reminder-sound path pointed to an attacker's SMB server. Outlook sent the user's NTLM hash **with no click at all** |

### Shortcuts (`.lnk`): no exploit needed { #lnk }

A `.lnk` file is a Windows shortcut. It stores a **target** program and **arguments**, an icon, a working directory and a "run minimised" flag. That alone makes it a launcher: an attacker sets the target to `cmd.exe` or `powershell.exe` and puts an encoded download-and-run command in the arguments. The icon is set to look like a PDF or a folder. The user double-clicks "Invoice.pdf" and PowerShell runs. This is why `.lnk` attachments, and `.lnk` files inside ZIP/ISO containers, became the go-to replacement for macros after 2022.

Parsed with a shortcut parser (Eric Zimmerman's `LECmd` is a common one), a malicious shortcut looks roughly like this (illustrative, invented values):

```
Source file: C:\Cases\8841\Invoice_8841.pdf.lnk
  Target path:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Arguments:          -w hidden -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
  Icon location:      C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  Show window:        SwShowMinNoActive
  Working directory:  %TEMP%
  Machine ID:         desktop-q7k2m1
  MAC address:        00:0c:29:5a:1e:77
```

- `Source file … Invoice_8841.pdf.lnk`: the real extension is `.lnk`. Explorer hides `.lnk` even when "show extensions" is on, so the user sees `Invoice_8841.pdf`.
- `Target path … powershell.exe`: a "PDF" that launches PowerShell (**T1059.001**).
- `Arguments -w hidden -nop -enc SQBFAFgA…`: hidden window, no profile, Base64-encoded command. `SQBFAFgA` is UTF-16LE Base64 for `IEX` (Invoke-Expression), the same giveaway as on the previous page.
- `Icon location … msedge.exe`: borrows Edge's icon, which users associate with opening PDFs.
- `Show window SwShowMinNoActive`: starts minimised and without focus, so nothing flashes on screen.
- `Machine ID`, `MAC address`: the **attacker's build machine** name and MAC, stored automatically in the shortcut's tracking data. Gold for linking samples to the same builder.

Related ATT&CK: **T1204.002 Malicious File** (the click), **T1547.009 Shortcut Modification** (when shortcuts are used for persistence), **T1027.012 LNK Icon Smuggling** (payload or URL hidden in the icon location field).

**[Changed]** For years, attackers padded the arguments with whitespace so the Properties dialog showed only the harmless-looking start of the target. This was tracked as ZDI-CAN-25373 / CVE-2025-9491 and used by many state-backed groups. Microsoft changed Windows in late 2025 (reported in November–December 2025) so the Properties dialog shows the full command, without issuing a traditional security bulletin. Parse shortcuts with a tool; don't trust the dialog.

## Quickly sorting good from bad { #triage }

You now know the main file types attackers use. When one lands on your desk, here's a fast, surface-level routine. Each step is cheaper than the next, and you stop as soon as the answer is clear.

1. **Online hash lookup.** Compute SHA-256 and look it up (VirusTotal or your threat-intel platform). Known bad means you're done triaging and should start scoping. Known good with years of history is reassuring. **Unknown** tells you nothing, or is mildly suspicious (common software has usually been seen). The details and traps are on the next page.
2. **Digital signature** (for types that can be signed: executables, DLLs, drivers, MSI, scripts, some Office macros). Signed by a well-known publisher and valid is a good sign. Unsigned or signed by a stranger is a reason to look closer, not a verdict. Also on the next page.
3. **Look at it safely.** For documents, a screenshot from a sandbox, or opening it in a disposable VM, often answers the question in one glance: a blurred "invoice" with a giant "Enable content" or "View document" button is a lure. (Visual inspection gets its own page.)
4. **Strings: look for things where they don't belong.**
    - `MZ` / `This program cannot be run in DOS mode` inside something that isn't an executable (a document, a picture, a PDF stream), or its **hex form** inside RTF.
    - Script inside a picture (`<script>`, `powershell`, `eval(`), a `PK` or `%PDF` after an image's end.
    - Odd URLs in a PDF: a look-alike login domain, raw IP addresses, free hosting, URL shorteners.
5. **Scripts: are the names unreadable?** Variable and function names like `_0x3fa1`, `xQzPw`, `lllIIlI` and long concatenated strings are designed to defeat automated scanners. They make a human analyst's job **easier**, because readable code doesn't need to look like that. Some developers obfuscate to protect their code, so let context decide (where did it come from, what does it do).
6. **The ultimate test: sandbox it.** What does it do when it runs? New processes, files dropped, registry changes, network connections, especially anything that happens **immediately on open** (auto-run macros, `/OpenAction` JavaScript, `\objupdate` objects).

Applying it to this page's two test files:

| Step | `statement_nov.doc` (RTF) | `invoice_8841.pdf` |
| --- | --- | --- |
| 1 Hash | Unknown (it's new) → no verdict | Unknown → no verdict |
| 2 Signature | Not applicable (RTF can't be Authenticode-signed) | Not signed. Business PDFs are rarely signed anyway |
| 3 Look | One line of text and a package icon labelled `update.exe` | "Your invoice is ready — click View Document" |
| 4 Strings | `\objclass Package`, hex `4d5a9000` and the DOS sentence in hex, `rtfobj` says PE executable | `/OpenAction` → `/JavaScript`, a link to `docs-view.example`, an embedded file |
| 5 Scripts | — | `app.alert` (harmless here; would be obfuscated in a real case) |
| 6 Sandbox | Would show the icon. If clicked: drop to `%TEMP%\update.exe` and run it | Would show the message box and the link |
| Verdict | **Malicious pattern**: executable embedded in a "statement" | **Suspicious**: auto-run JavaScript plus an attachment and an external link. Check the domain, extract the attachment |

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    RTF still can't hold macros but still carries OLE objects and links, and Word still opens files by content rather than extension. The `\object`/`\objdata`/`\objupdate`/`\*\template` keywords, the hex-in-text trick and `rtfobj` are still how you triage it. PDF structure (objects, streams, xref, trailer), the risky keywords (`/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/ObjStm`), `strings | grep http` as a first look and `pdfid`/`pdf-parser` as the next step are unchanged. Parsing bugs in image, font and media libraries still appear every year. The six-step good-vs-bad routine is still a sound order of work.

!!! info "[Changed] What has changed"
    - **Flash is gone.** Adobe ended Flash Player on 31 December 2020 and readers no longer play it, so `/RichMedia` Flash exploits only matter in old samples. **Acrobat Reader still enables JavaScript by default**, with Protected Mode and Enhanced Security on by default and administrator controls to restrict or disable JavaScript. Browser PDF viewers support only a limited subset of PDF JavaScript.
    - **PDFs today are mostly link and QR-code carriers** for credential phishing, including adversary-in-the-middle pages that steal session cookies and defeat ordinary MFA. Expect few exploits and many URLs, plus QR images that `strings` can't read (decode them with a QR tool in the sandbox).
    - **Equation Editor is gone** (removed January 2018), but CVE-2017-11882 kept appearing in commodity malware campaigns for years because unpatched Office installs lingered. Newer RTF parser bugs (e.g. CVE-2023-21716) show that the preview pane is still an attack surface.
    - **Shortcuts moved centre stage** after the 2022 macro block: `.lnk` in ZIP/ISO/IMG containers, LNK icon smuggling, and the whitespace-padding trick (CVE-2025-9491) that Microsoft mitigated quietly in late 2025.
    - **Image-library bugs became supply-chain problems.** CVE-2023-4863 (libwebp) affected browsers, chat apps and anything else that bundled the library, so patching meant updating many products, not one.
    - **Tools**: oletools (`rtfobj`, `oleid`, `olevba`, `oleobj`) and Didier Stevens' `pdfid`/`pdf-parser` are still the standard. They come preinstalled on REMnux, and many are also on FLARE-VM. Sandboxes add AI summaries; verify them against the actual objects.
    - **ATT&CK names used on this page**: T1566.001 Spearphishing Attachment, T1204.002 Malicious File, T1203 Exploitation for Client Execution, T1221 Template Injection, T1218.005 Mshta, T1059.001 PowerShell, T1547.009 Shortcut Modification, T1027.012 LNK Icon Smuggling.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't treat "RTF = no macros" as "RTF = safe".** Embedded objects, remote templates and parser exploits don't need macros.
    - **Don't trust the extension or the header to be tidy.** Malicious RTF often uses headers like `{\rt0` and hex broken with junk. Use a parser, not only `grep`.
    - **Don't conclude a PDF is clean from `strings | grep http`.** Streams and object streams are compressed, names can be hex-escaped, and the link may be a QR image.
    - **Don't preview suspicious files on your workstation.** Preview panes and thumbnail generators parse the file. Turn them off on analysis machines and only handle samples in the isolated VM.
    - **Don't trust Windows' Properties dialog for `.lnk` targets.** Parse the shortcut with a tool and read the full arguments.
    - **Don't skip the endpoint side.** For document exploits, the parent-child process pair (`WINWORD.EXE` → `mshta.exe`, PDF reader → `powershell.exe`, `EQNEDT32.EXE` running) is often clearer than the file itself.

## Practice questions { #quiz }

### Question 1

A user received `Remittance_0412.doc`. Your gateway says it contains "no macros". `file` says `Rich Text Format data, version 1, unknown character set`, and `grep -c objupdate` returns `1`. (a) Why can a `.doc` be RTF, and why doesn't "no macros" make it safe? (b) What does `\objupdate` do, and why does it matter? (c) What would you look for on the user's endpoint?

??? success "Answer and explanation"
    **(a)** Word opens a file according to its **content**, not its extension, so an RTF renamed `.doc` opens normally. RTF can't hold VBA macros, but it can embed **OLE objects** (including packaged executables or scripts), link to remote content, use remote templates (T1221) and exploit bugs in Word's RTF parser. The macro check was irrelevant.

    **(b)** `\objupdate` tells Word to refresh or activate the embedded or linked object **as soon as the document opens**, so the user doesn't have to double-click it. That's how exploits like CVE-2017-0199 turned "open the document" into "run the attacker's code" with no warning bar. Next step: `rtfobj` to list and identify the objects (look for `OLE2Link`, `Equation.3`, `Package`).

    **(c)** Process creation (4688 or Sysmon 1) with `WINWORD.EXE` as the parent of `mshta.exe`, `powershell.exe`, `cmd.exe`, `wscript.exe` or `rundll32.exe`; any `EQNEDT32.EXE` process; network connections from Word or mshta right after the open; files dropped in `%TEMP%`. Then search other endpoints for the same file hash and URLs.

### Question 2

`pdfid` on `Statement_Q3.pdf` shows `/Page 1`, `/JavaScript 1(1)`, `/OpenAction 1`, `/ObjStm 2` and `/EmbeddedFile 0`. `strings Statement_Q3.pdf | grep -i http` returns nothing. (a) What does each of those lines tell you? (b) Why might `grep` find no URL even if there is one? (c) What would you do next?

??? success "Answer and explanation"
    **(a)** `/Page 1`: a single page, typical of lures. `/JavaScript 1(1)`: JavaScript is present, and the `(1)` means the name was **obfuscated** with hex escapes (like `/J#61vaScript`). Legitimate writers don't do that, so it's suspicious on its own. `/OpenAction 1`: something runs automatically on open, and together with JavaScript that likely means **code on open**. `/ObjStm 2`: objects are packed inside compressed object streams, which hides keywords and URLs from `strings`.

    **(b)** The URL can sit inside a **compressed stream** or object stream (FlateDecode), be built by JavaScript at run time, be hex-escaped, or be a **QR code image**. `strings` only sees uncompressed text.

    **(c)** Use `pdf-parser` to search for and show the JavaScript object and decompress streams (`-f`), and extract any URLs or code. Deobfuscate the JavaScript in a safe environment. Detonate it in a sandbox to see actions and network requests. On endpoints, look for the PDF reader spawning processes or writing executables. Hash the file and check where else it arrived.

### Question 3

Put the six quick-triage steps in order and give one example of what each could reveal. Then explain why a `.lnk` file called `Invoice.pdf` needs no exploit to be dangerous, and name the ATT&CK technique for the user's double-click.

??? success "Answer and explanation"
    **Order:** (1) **hash lookup**: known malware, or no history. (2) **signature check**: signed by a known publisher, unsigned, or signed by a stranger. (3) **safe visual inspection**: a lure page with an "Enable content" or "View document" button. (4) **strings**: `MZ`/DOS sentence (or its hex in RTF) inside a non-executable, script in an image, odd URLs in a PDF. (5) **script obfuscation**: random variable names and concatenated strings. (6) **sandbox**: processes, files, registry and network activity, especially immediately on open.

    **`.lnk`:** a shortcut stores a target program and its arguments. The attacker points it at `powershell.exe` or `cmd.exe` with a hidden-window, encoded download-and-run command, and gives it a PDF-like icon. Explorer hides the `.lnk` extension, so the user sees `Invoice.pdf`. Double-clicking simply runs the configured command. No vulnerability is needed. Technique: **T1204.002 User Execution: Malicious File** (with T1059.001 for the PowerShell it runs).

## Related { #related }

- [Handling suspect files safely and the dangerous file types](safe-handling-file-types.md) · [Strings](strings.md) · [Identifying files](file-identification.md)
- [Screenshots, sandboxes and when to go manual](../http-analysis/screenshots-sandboxes.md) · [Base64](../http-analysis/base64.md)
- [Phishing delivery & initial execution](../../../adversary/phishing-delivery.md) · [LOLBins](../../../adversary/lolbins.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md)
- [Process creation events](../important-events/process-creation.md) · [Email](../email/index.md) · [Zeek files.log & pe.log](../../../network/zeek/files-log.md)
