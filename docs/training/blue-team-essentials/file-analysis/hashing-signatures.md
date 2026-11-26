---
title: "Hashing and Code Signatures — Hash Lookups, Authenticode, sigcheck, and Whether Signed Means Safe"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
  - code-signing
---

# Hashing and Code Signatures — Hash Lookups, Authenticode, sigcheck, and Whether Signed Means Safe { #hashing-signatures }

!!! abstract "What this page covers"
    The first two steps of quick triage, in depth. **Hashing**: what a cryptographic hash is (a fixed-size fingerprint that is one-way and collision-resistant), why changing one byte changes everything, computing MD5/SHA-1/SHA-256 with `md5sum`/`sha256sum`, `Get-FileHash` and `certutil`, and how to read a reputation lookup. That includes the part people get wrong: a hash lookup is a **deny list**, so it finds known bad very reliably and misses everything new. "Unknown" is not a vote for good, and "no detections" on a sample first seen yesterday means very little. We also cover what a hash lookup does and doesn't reveal about you. **Code signing**: how Microsoft **Authenticode** works step by step (certificate from a CA, hash of the program, signature with the private key, signature block appended to the file, verification against the chain of trust), timestamps, catalog signing, and what "valid" actually promises. Then **Sysinternals sigcheck** output and **PowerShell `Get-AuthenticodeSignature`** output, line by line, including a lone machine-learning detection on a genuine Windows file. Finally, **does signed mean safe?** No. Attackers buy their own certificates, steal other people's (as with a 2022 wiper signed with a real company's certificate), abuse signing services, and in the MD5 era even forged signatures with hash collisions. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, publishers and file names are invented for illustration (`.example`, documentation and private IPs). The Linux hash outputs were produced on harmless test files from the previous page. The Windows outputs (`Get-FileHash`, `sigcheck`, `Get-AuthenticodeSignature`) are illustrative: their layout matches the real tools, but the values are invented. No real malware hashes appear on this page.

## The 8 key points { #key-points }

1. A **cryptographic hash** turns any input into a short, fixed-size fingerprint. The same bytes always give the same hash, a one-byte change gives a completely different one, you can't work backwards from the hash to the input, and finding two inputs with the same hash should be practically impossible.
2. **Hash lookups are one of the fastest triage steps.** Compute SHA-256 and look it up. A hit on known malware is a near-certain **true positive**.
3. **They are a deny list, so they miss new things.** Recompiled, repacked or one-byte-changed malware has a new hash. "Not found" or "0 detections" is **not** a clean verdict. Look at the **first-seen date**: years of clean history means much more than a day.
4. **A hash reveals nothing about the file's content**, so looking one up is safe for confidentiality. But a lookup or upload can still tell a watching attacker, or the service, that you have the file. Look up hashes; think twice before uploading files.
5. **MD5 and SHA-1 are broken for collisions.** They're fine as lookup keys for known samples, but use **SHA-256** for evidence, integrity checks and anything that has to resist a deliberate attacker.
6. **Authenticode** signs Windows programs. The publisher's private key signs a hash of the file, and the signature plus the certificate chain are stored inside the file. Verification proves **integrity** (not modified since signing) and **who signed it** (according to a CA that vetted their identity). It says nothing about whether the code is **good**.
7. **`sigcheck -a -h -vt`** (or `Get-AuthenticodeSignature`) shows whether the signature is valid, who signed it, when, its hashes and VirusTotal results. One or two lone detections are often false positives, especially from machine-learning engines.
8. **Signed is not safe.** Attackers get their own certificates, steal real companies' keys, abuse cloud signing services and signed driver programmes, and in the past forged signatures with MD5 collisions. Treat a signature as **evidence about origin**, then judge the publisher, the timing and the behaviour.

## Why this matters in a SOC { #why }

Every day the SOC sees hundreds of files it has never looked at: downloads, email attachments, new binaries the EDR noticed, tools an admin dropped on a server. You can't reverse-engineer them all. Hashes and signatures are the two questions you can answer in seconds for each one:

- **"Has anyone seen these exact bytes before, and what did they think?"** That's the hash lookup.
- **"Who claims to have made this, and has it been changed since?"** That's the signature.

Together they sort a large pile quickly: signed by Microsoft and known for years, move on. Known bad, start the incident. Unsigned, never seen, arrived by email, look closer. The danger is in the middle, where people read "no detections" or "signed" as "safe". This page is mostly about not making that mistake.

## Hashing { #hashing }

### What a hash function is { #hash-what }

A **hash function** takes input of any length (one byte, or a 4 GB disk image) and produces an output of **fixed length**: 128 bits for MD5, 160 for SHA-1, 256 for SHA-256. A **cryptographic** hash function adds promises that make it useful for security:

- **Deterministic**: the same input always produces the same output, on any machine, forever.
- **Avalanche effect**: changing even one bit of the input changes about half the output bits, unpredictably.
- **One-way (preimage resistance)**: given a hash, you can't compute an input that produces it.
- **Collision resistance**: it should be practically impossible to find two different inputs with the same hash.

A meat grinder is the classic picture. Put the same cut of meat in and you get the same mince every time. Look at the mince and you can't rebuild the steak. Technically, though, it's maths, not mush. The function mixes the input through many rounds of bitwise operations and additions so thoroughly that the output behaves like a random number tied to the input.

Collisions **must** exist: there are infinitely many possible inputs and only 2^256 possible SHA-256 outputs (the pigeonhole principle). The promise is only that nobody can **find** one. For SHA-256 nobody has. For MD5 and SHA-1, people have (see [below](#hash-algorithms)).

### Computing hashes { #hash-compute }

On Linux, one command per algorithm. Here are the two test files from the previous page, plus a copy of the RTF with one extra byte (`x`) appended:

```
$ md5sum statement_nov.doc s2.doc
b34c8d8a49f07bc43e11b55457fbf169  statement_nov.doc
8ca96006b712870a1d1e3407c1977238  s2.doc
$ sha1sum statement_nov.doc
b7ac2c82a18e017d1370779ca8f070b03d1f5b07  statement_nov.doc
$ sha256sum statement_nov.doc s2.doc
1b248e9bdf79d40c2fda8b08edfc84976f32273238edb8f2c3cb5cf34a26d2ac  statement_nov.doc
47b9cd4652cdcc42d9fe53113d59f21c252df8948941bc1e136f93ed2ef0af1c  s2.doc
$ echo -n "" | sha256sum
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
```

- Each line is `<hash>  <file name>`. The hash is shown as hex: 32 hex digits for MD5 (128 bits), 40 for SHA-1 (160 bits), 64 for SHA-256 (256 bits). The number of digits tells you the algorithm at a glance.
- `statement_nov.doc` and `s2.doc` differ by **one byte at the end**, yet their hashes have nothing in common. That's the avalanche effect, and it's why an attacker can defeat a hash-based block by changing a single byte.
- `echo -n "" | sha256sum` hashes **empty input**. `e3b0c442…b855` is worth recognising: if it shows up as the hash of a "malicious file" in a ticket, the file was empty or failed to copy. (The MD5 of empty input is `d41d8cd98f00b204e9800998ecf8427e`.) The `-` means "standard input".
- `sha256sum -c hashes.txt` checks files against a saved list, which is handy for proving evidence hasn't changed.

On Windows (illustrative output):

```
PS C:\Cases\8841> Get-FileHash .\statement_nov.doc -Algorithm SHA256 | Format-List

Algorithm : SHA256
Hash      : 1B248E9BDF79D40C2FDA8B08EDFC84976F32273238EDB8F2C3CB5CF34A26D2AC
Path      : C:\Cases\8841\statement_nov.doc

PS C:\Cases\8841> certutil -hashfile .\statement_nov.doc SHA256
SHA256 hash of .\statement_nov.doc:
1b248e9bdf79d40c2fda8b08edfc84976f32273238edb8f2c3cb5cf34a26d2ac
CertUtil: -hashfile command completed successfully.
```

- `Get-FileHash` defaults to SHA-256 (`-Algorithm` also accepts `SHA1`, `MD5`, `SHA384`, `SHA512`). It prints the hash in **upper case**. Hex is case-insensitive, so `1B24…` and `1b24…` are the same hash. Normalise case before comparing strings in scripts or SIEM queries.
- `certutil -hashfile` is built into every Windows version. It's handy on a locked-down server, but attackers also use `certutil` to download and decode files, so expect your EDR to watch it.

**[Supplement]** Where you'll meet hashes in logs: Sysmon event 1 (process creation) and event 7 (image loaded) carry a `Hashes` field such as `SHA256=…,IMPHASH=…`. EDR telemetry, Zeek `files.log` (`md5`/`sha1`/`sha256` of files seen on the wire, see [Zeek files.log](../../../network/zeek/files-log.md)), mail gateways and AV quarantine records all have hashes too. One hash lets you pivot across all of them: "where else did these exact bytes appear?"

### Looking a hash up { #hash-lookup }

The idea is simple: build a huge database of the hashes of files already analysed, and let people query it. **VirusTotal** is the best-known public one. Commercial threat-intelligence platforms, MalwareBazaar, your EDR's cloud and your own SIEM's history of seen hashes work the same way. Antivirus engines use the same trick locally: a list of known-bad hashes is one of the fastest ways to recognise known malware on a disk.

A lookup gives one of three kinds of answer:

| Result | What it means | What you do |
| --- | --- | --- |
| **Known, many engines say malicious** | These exact bytes are known malware. A near-certain true positive | Treat as an incident: contain, scope (search the hash fleet-wide), collect related IOCs from the report |
| **Known, nobody calls it malicious** | Seen before, no detections **yet** | Look at the **first-seen date**. Years of history across many submissions: probably fine. First seen yesterday: weak evidence. Vendors often change their minds a day or two later |
| **Unknown (never seen)** | No information either way | Not good, not bad. For a supposedly common program it's mildly suspicious, since popular software has almost always been seen. For a custom internal tool it's expected. Continue triage (signature, strings, sandbox) |

The second row is where SOCs get burnt. A brand-new sample is submitted, a handful of engines call it clean, an analyst closes the ticket, and 24–48 hours later most engines detect it. The fix is to read the dates as well as the score. A file first seen three years ago, submitted thousands of times under the name of a well-known tool, with zero detections, is a very different thing from a file first seen this morning with zero detections.

An illustrative (invented) lookup summary:

```
SHA-256           1b248e9bdf79d40c2fda8b08edfc84976f32273238edb8f2c3cb5cf34a26d2ac
Detections        41 / 66
Popular label     trojan.rtfobj/packager
First submission  2026-11-24 02:31:10 UTC
Last analysis     2026-11-25 18:02:44 UTC
Names             statement_nov.doc, Remittance_0412.doc, doc_8841.rtf
Contacted URLs    (none in sandbox; requires user to open embedded object)
```

- `Detections 41 / 66`: 41 of 66 engines flag it. Strong consensus.
- `Popular label`: the most common family or type name across engines. Useful, but engines name things differently.
- `First submission`: a day before your ticket, so this is a **current campaign**. Search your mail logs for the same attachment.
- `Names`: other file names this hash arrived under. Search for those too.
- `Contacted URLs (none…)`: a reminder that sandbox results depend on what was clicked (see [the previous page](rtf-pdf-misc-triage.md#triage)).

**[Correction]** "0 detections means clean" is wrong in two ways. Detection engines lag behind new samples, and a hash lookup can only ever recognise **exact** bytes it has seen. It's a deny list: excellent at confirming known bad, blind to anything new.

### What a lookup reveals about you { #hash-privacy }

A hash can't be reversed into the file, so looking up the hash of a confidential document leaks nothing about its **content**, unless the service already has the file because someone else uploaded it. That's the one case where the service (and anyone who can watch its lookups) learns something: that you, from your account or IP, have the same file. For a targeted attack, an attacker who uploaded their own sample to check detection rates might notice that it's suddenly being searched for.

Uploading the **file** is a much bigger step. On public services the file becomes available to other subscribers, including possibly the attacker, and any confidential data inside it (a real invoice, an internal document an attacker modified) is now outside your organisation. Rule of thumb: **look up hashes freely, upload files deliberately**, and prefer private sandboxes for anything that might contain your own data (see [sandboxes and OPSEC](../http-analysis/screenshots-sandboxes.md)).

### Choosing an algorithm: MD5, SHA-1, SHA-256 { #hash-algorithms }

| Algorithm | Output | Status | Use it for |
| --- | --- | --- | --- |
| MD5 | 128 bits, 32 hex | **Broken for collisions** since 2004. Practical chosen-prefix collisions since 2007. Used to forge a code-signing certificate in the wild (the Flame malware, 2012) | Lookup key for known samples, de-duplication. **Not** for integrity against an attacker |
| SHA-1 | 160 bits, 40 hex | First public collision 2017 (SHAttered). Practical chosen-prefix collision 2020. Deprecated by NIST and being phased out by 2030 | Lookup key (many feeds still list it). Not for new signatures or evidence integrity |
| SHA-256 | 256 bits, 64 hex | No known collisions. The current standard | **Default** for IOCs, evidence, integrity checks and signatures |

Why does a collision matter if nobody can reverse a hash? Because of **chosen-prefix collisions**: an attacker builds two files (one innocent, one evil) that share a hash. They get the innocent one approved, signed or allow-listed, and then the evil one inherits the approval. That's exactly the signature-forgery attack discussed [below](#signed-safe).

**[Supplement]** Hashes beyond exact matching:

- **imphash**: a hash of a PE's import table (which DLL functions it uses, in order). Samples rebuilt from the same source often share it even when their file hashes differ. Sysmon and sigcheck can show it.
- **Fuzzy hashes** (ssdeep, TLSH): similarity hashes. Two files that are 90% the same get similar values, so you can find variants of a sample even after small changes.
- **Authenticode hash** (shown by sigcheck as `PESHA1`/`PE256`): the hash Authenticode signs. It skips the signature area, so it stays the same when a file is re-signed.

## Code signing and Authenticode { #signatures }

### Why signatures go a step further { #sig-why }

A hash only tells you "these are the bytes someone else saw". A **digital signature** adds two guarantees:

- **Integrity**: the file hasn't changed since it was signed. Change one byte and verification fails.
- **Authenticity**: the signature was made with a specific private key, and a **certificate authority (CA)** has vouched (through a certificate) that this key belongs to a named organisation.

What it does **not** say: that the organisation is honest, competent or still in control of its key. The CA checks **identity**, not code quality. A wax seal on a letter is a good picture. An unbroken seal proves nobody opened the letter, and the crest tells you whose ring sealed it. It doesn't tell you the letter is truthful, or that the ring wasn't stolen.

So a signature from Microsoft on a system file is strong evidence the file is genuine. A signature from "Brightway Software Solutions Ltd", a name you've never heard of, tells you mostly that someone bought a certificate under that name. That's a lead to investigate, not reassurance.

### How Authenticode works { #authenticode }

**Authenticode** is Microsoft's code-signing format for Windows executables, DLLs, drivers, MSI installers, cabinet files and (in a text form) PowerShell scripts. Step by step:

1. **Get a certificate.** The developer creates a key pair and applies to a CA for a **code-signing certificate**. Like a website certificate, but with the "code signing" purpose (an Extended Key Usage). The CA verifies the organisation's identity (more thoroughly for **EV**, Extended Validation, certificates). Since 2023, industry rules require the private key to be generated and kept on **hardware** (a token, HSM or cloud signing service) so it can't simply be copied off a developer's laptop.
2. **Hash the program.** The signing tool computes the **Authenticode hash** of the file: a hash over almost all of the PE file, deliberately skipping three things that the signing step itself changes: the header's checksum field, the pointer to the certificate table, and the certificate table itself.
3. **Sign the hash.** The hash is signed with the developer's **private key**. Usually this is described as "encrypting the hash with the private key". That's a fair picture for RSA, but strictly it's a signature operation (ECDSA keys can sign but not encrypt).
4. **Attach the signature.** The signature, the developer's certificate and usually the intermediate CA certificates are packed into a PKCS#7 structure and appended to the file in its **certificate table** (the "security directory"). That's why `strings` on a signed file shows CA names and URLs near the end. Most signatures also get a **timestamp** countersignature from a timestamping authority, which proves **when** the file was signed.
5. **Verify.** When Windows (or `sigcheck`) checks the file, it recomputes the Authenticode hash, checks the signature with the **public key** in the certificate, then builds a **chain** from the developer's certificate up to a root CA in the machine's trusted root store, checking validity dates and revocation along the way.

**[Correction]** It's often said the public key must be in the user's **Trusted Publishers** store for verification. Normal verification needs the chain to end at a root in the **Trusted Root Certification Authorities** store (Windows ships with and updates these). The **Trusted Publishers** store is an extra, stricter list that some policies use, for example Office's "only allow macros signed by trusted publishers" or PowerShell's `AllSigned` prompts. Don't confuse "the signature is valid" with "this publisher is in my Trusted Publishers list".

Facts that matter in investigations:

- **Any change breaks it.** Modify the program or the signature and verification reports a hash mismatch. (One historical weakness: Windows didn't check extra bytes padded into the certificate table, CVE-2013-3900. Microsoft made the stricter check **opt-in**, via the `EnableCertPaddingCheck` setting, rather than default, so installers with data hidden in the signature area can still verify on many systems.)
- **Timestamps keep old signatures valid.** A certificate expires, but a file signed and timestamped **while** the certificate was valid stays valid. If a certificate is **revoked** (for example after a theft), CAs can set the revocation date so that files signed before the theft stay valid and later ones fail.
- **Catalog signing.** Many Windows files carry no embedded signature at all. Their hashes are listed in a signed **catalog** file (`.cat`) under `C:\Windows\System32\CatRoot`. Tools report them as signed, with the catalog's path. Copy such a file to another machine without that catalog and it looks unsigned.
- **Scripts.** A signed PowerShell script carries its signature as a comment block at the end, starting `# SIG # Begin signature block`.

### Verifying signatures with sigcheck { #sigcheck }

**Sigcheck** (Sysinternals) is a fast way to check a file's signature. It verifies the Authenticode signature, prints the publisher and version details, several hashes and the entropy, and can check the hash against VirusTotal. An illustrative run on the genuine Windows Calculator:

```
C:\Tools> sigcheck64.exe -a -h -vt C:\Windows\System32\calc.exe

Sigcheck v2.90 - File version and signature viewer
Copyright (C) 2004-2026 Mark Russinovich
Sysinternals - www.sysinternals.com

c:\windows\system32\calc.exe:
        Verified:       Signed
        Signing date:   06:12 14/10/2026
        Publisher:      Microsoft Windows
        Company:        Microsoft Corporation
        Description:    Windows Calculator
        Product:        Microsoft® Windows® Operating System
        Prod version:   10.0.26100.1
        File version:   10.0.26100.1 (WinBuild.160101.0800)
        MachineType:    64-bit
        Binary Version: 10.0.26100.1
        Original Name:  CALC.EXE
        Internal Name:  CALC
        Copyright:      © Microsoft Corporation. All rights reserved.
        Comments:       n/a
        Entropy:        4.12
        MD5:    0F2A...(32 hex)
        SHA1:   5C1B...(40 hex)
        PESHA1: A93E...(40 hex)
        PE256:  77D0...(64 hex)
        SHA256: 4B6F...(64 hex)
        IMP:    n/a
        VT detection:   1/72
        VT link:        https://www.virustotal.com/gui/file/4b6f...
```

The command:

- `sigcheck64.exe`: the 64-bit build.
- `-a`: show **extended version information** (description, product, original name, entropy and more).
- `-h`: show **file hashes** (MD5, SHA-1, the Authenticode `PESHA1`/`PE256`, SHA-256, and import hash).
- `-vt`: **check VirusTotal** by hash, accepting the VirusTotal terms of service. (`-v` alone does the same but prompts for the terms. Add `r` to `-v` to open reports in a browser or `s` to **upload** unknown files. Don't use the upload option casually.)

Line by line:

- `Verified: Signed`: the signature checks out and chains to a trusted root. Other values you'll see: `Unsigned`, `The digital signature of the object did not verify` (tampered or corrupt), or a message about an untrusted root or a revoked certificate.
- `Signing date`: when it was signed (from the timestamp). A program "from 2019" signed last week is worth a question.
- `Publisher: Microsoft Windows`: the **signer's certificate subject**. This is the line that matters most. `Company`, `Description`, `Product` and the version lines come from the file's **version resource**, which the developer writes and anyone can fake. Only `Publisher` is backed by the certificate.
- `Original Name: CALC.EXE`: the file name the developer compiled. If a file on disk is called `svchost.exe` but `Original Name` says `nc.exe` or `rclone.exe`, it was renamed, which is a classic masquerade (**T1036.003 Rename Legitimate Utilities**).
- `Entropy: 4.12`: randomness on a 0–8 scale. Ordinary code sits roughly between 5 and 6.5. Values near 7.5–8 suggest **packed or encrypted** content (see [packing](strings.md#packing)).
- `MD5`/`SHA1`/`SHA256`: whole-file hashes for lookups. `PESHA1`/`PE256`: the Authenticode hashes. `IMP`: imphash (`n/a` when the tool can't compute one).
- `VT detection: 1/72`: **one** engine out of 72 calls the real Windows Calculator malicious. Engines that use machine learning sometimes give generic labels such as "Unsafe" or "Malicious (score: 6x)" to perfectly legitimate files. A lone hit on a Microsoft-signed, years-old system binary is almost certainly a **false positive**. In general, when only one or two engines flag a file, you can't tell whether they're the best detectors or the jumpiest. That's when you move on to dynamic analysis (a sandbox) or a closer manual look, rather than trusting the number.

Other options worth knowing: `-e` (check only executable images), `-s` (recurse into subfolders), `-u` (show only files that are unsigned or, with `-vt`, not clean on VirusTotal), `-c`/`-ct` (CSV/tab output for spreadsheets), `-i` (show the full certificate chain), and `-m` (dump the application manifest). For example, `sigcheck64.exe -e -u -s -vt C:\Users\*\AppData` quickly lists unsigned or flagged executables in user profiles, a useful hunt on a suspicious host.

The same file, unsigned and renamed, in an illustrative sigcheck result from a user's profile:

```
c:\users\j.kim\appdata\roaming\microsoft\svchostw.exe:
        Verified:       Unsigned
        Link date:      03:44 22/11/2026
        Publisher:      n/a
        Company:        Microsoft Corporation
        Description:    Host Process for Windows Services
        Original Name:  ldr.exe
        Entropy:        7.86
        VT detection:   0/72
```

- `Unsigned`, but the version resource claims `Microsoft Corporation`. Real Microsoft binaries are signed (embedded or by catalog), so a "Microsoft" file with no signature is a red flag.
- `Link date 22/11/2026`: compiled four days ago.
- `Original Name: ldr.exe` vs file name `svchostw.exe`: renamed. And `svchost` only ever lives in System32.
- `Entropy 7.86`: probably packed.
- `VT detection 0/72`: likely **new**, not clean. Everything else here says malicious.

### `Get-AuthenticodeSignature` { #get-authenticodesignature }

PowerShell can check signatures without extra tools (illustrative output):

```
PS C:\> Get-AuthenticodeSignature C:\Users\j.kim\Downloads\RemoteHelper.exe | Format-List

SignerCertificate      : [Subject]
                           CN="Brightway Software Solutions Ltd", O="Brightway Software Solutions Ltd", L=Example City, C=GB
                         [Issuer]
                           CN=Example Code Signing CA R3, O=Example Trust Services, C=US
                         [Serial Number]
                           4F0E2A9C77D1B3305E6A
                         [Not Before]
                           2/11/2026 12:00:00 AM
                         [Not After]
                           6/02/2028 11:59:59 PM
                         [Thumbprint]
                           9A1C...(40 hex)
TimeStamperCertificate : [Subject]
                           CN=Example Timestamping Authority 2026, O=Example Trust Services, C=US
                         ...
Status                 : Valid
StatusMessage          : Signature verified.
Path                   : C:\Users\j.kim\Downloads\RemoteHelper.exe
SignatureType          : Authenticode
IsOSBinary             : False
```

- `SignerCertificate [Subject]`: who the certificate was issued to. `CN` is the common name, `O` the organisation, `L` the locality, `C` the country.
- `[Issuer]`: the CA that issued it.
- `[Not Before] 2/11/2026`: issued **three weeks ago**. A brand-new certificate on a "remote helper" tool that arrived by email deserves a hard look.
- `[Thumbprint]`: the SHA-1 hash of the certificate itself. Pivot on it: search your EDR for other files signed with the same certificate.
- `TimeStamperCertificate`: a timestamp is present, so the signing time is attested.
- `Status : Valid`, `Signature verified.`: the signature is mathematically fine and chains to a trusted root. That's **all** "Valid" means. Other statuses: `NotSigned`, `HashMismatch` (the file was modified after signing), `NotTrusted` (chains to an untrusted root, for example a self-signed certificate), `UnknownError`.
- `SignatureType : Authenticode`: embedded signature (`Catalog` for catalog-signed files).
- `IsOSBinary : False`: not part of Windows.

**[Supplement]** Windows logs signature checks in several places. Sysmon event 7 (image loaded) includes `Signed`, `Signature` and `SignatureStatus`. Microsoft Defender for Endpoint and other EDRs record signer and validity for every process. Code integrity events (`Microsoft-Windows-CodeIntegrity/Operational`, e.g. 3033 and 3077 when App Control blocks an unsigned or non-compliant image) show signature-based blocks. Hunting for "processes signed by certificates first seen in our environment this week" is a high-value query.

## Does digitally signed mean safe? { #signed-safe }

**No.** A valid signature tells you who signed the file and that it hasn't changed since. There are four broad ways attackers end up with validly signed malware:

| Route | How it works | What you'd see | ATT&CK |
| --- | --- | --- | --- |
| **Their own certificate** | Register a company (real or a shell) and buy a certificate, or buy one through a broker or "signing-as-a-service" crime operation | A publisher nobody has heard of, a newly issued certificate, often unrelated to the file's claimed product | **T1587.002** / **T1588.003** (obtain/develop code-signing certificates), **T1553.002 Code Signing** |
| **Stolen certificate or key** | Steal a legitimate developer's private key (or signing access) and sign malware with it | A real, reputable publisher, but on a file that doesn't match their products, or signed at odd times. Revocation usually follows, sometimes slowly | **T1588.003**, **T1553.002** |
| **Abused signing services and programmes** | Get malicious code through a legitimate vendor's signing pipeline: driver-signing portals, cloud signing services with short-lived certificates, or a compromised build system (supply chain) | Signatures from big, trusted names (sometimes even Microsoft's own driver signing) on malware | **T1553.002**, **T1195.002** (supply chain compromise) |
| **Hash collision** | Build a good and an evil file with the same (weak) hash, get the good one signed, and transplant the signature | A signature that verifies on a file the publisher never signed. Only possible with broken hashes such as MD5 | **T1553.002** |

Real examples (all public):

- **A stolen certificate on a wiper (2022).** Destructive malware used against Ukrainian organisations in February 2022 was signed with a valid certificate issued to a small, real company that had nothing to do with it. The signature helped it look like legitimate software.
- **Signed malware is not new or rare.** Academic research in 2017 found many signed malware samples in the wild, most of them signed with compromised certificates, and showed that some antivirus engines were more lenient with signed files, even when the signature was **invalid**. Signed malware long predates Stuxnet, which made it famous.
- **Collisions (2009 and 2012).** A researcher showed in 2009 that with MD5-based Authenticode you could create a good and an evil program with the same MD5 hash, sign the good one and move the signature to the evil one, and it would verify. In 2012 the Flame espionage malware used an MD5 collision to forge a certificate that chained to Microsoft and abused it to spread through Windows Update. Both are why modern signing uses SHA-256 and why SHA-1/MD5 signatures are no longer accepted for new Windows code.
- **[Supplement]** Since then: drivers signed through Microsoft's own hardware developer programme by malicious developer accounts (Microsoft revoked them in late 2022). Leaked signing keys from large hardware vendors after breaches (2022–2023). Trojanised but validly signed business software through supply-chain compromises (e.g. a VoIP desktop client in 2023). And criminal services that obtained short-lived certificates from Microsoft's cloud signing service to sign ransomware tooling, which Microsoft disrupted in May 2026.

So how do you use signatures without being fooled?

1. **Validity first**: `Unsigned`, `HashMismatch`, `NotTrusted` or revoked on something claiming to be a commercial product is a strong signal.
2. **Then the publisher**: is it who the file claims to be? Calculator should be signed by Microsoft, a remote-support tool by its vendor, not by "Brightway Software Solutions Ltd".
3. **Then the certificate's age and spread**: brand new, rarely seen in your environment, first seen this week? Pivot on the thumbprint and the serial number.
4. **Then the behaviour**: a signed binary that spawns `powershell -enc`, injects into `lsass.exe` or talks to a fresh domain is malicious however it's signed.
5. **Watch for signed tools used for evil**: legitimate, validly signed remote-access and admin tools (and vulnerable signed drivers, "bring your own vulnerable driver") are a big part of modern intrusions. The signature is genuine. The problem is who ran it and why.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Hash lookups are still one of the fastest triage steps, and the core lessons are unchanged: same bytes give the same hash, one byte changed gives a new hash, a lookup is a deny list, "unknown" and "0 detections on day one" are not clean verdicts, and the first-seen date matters. Hashes still don't reveal content, while uploads do. Authenticode still works the way described (hash, sign, embed, chain to a trusted root, timestamp), sigcheck and `Get-AuthenticodeSignature` are still the standard tools, and machine-learning false positives on lone engines are still common. "Signed does not mean safe" is truer than ever.

!!! info "[Changed] What has changed"
    - **Private keys must live in hardware.** Since 1 June 2023, CA/Browser Forum rules require code-signing keys (OV as well as EV) to be generated and stored in certified hardware (tokens, HSMs or cloud HSM services). This makes simple key theft from a developer's disk harder, but attackers moved to stealing **signing access** (build servers, cloud signing accounts) instead.
    - **Shorter certificates.** Under a 2025 CA/Browser Forum ballot, publicly trusted code-signing certificates issued from **1 March 2026** can be valid for at most about 460 days (roughly 15 months, down from up to 39 months). Expect more frequent certificate changes for legitimate software, so "new certificate" alone is a weaker signal than it used to be. Combine it with publisher and behaviour.
    - **EV no longer buys instant trust.** Microsoft changed SmartScreen in 2024 so EV-signed files no longer get immediate reputation. Reputation now builds from how files are actually seen.
    - **Cloud signing services and their abuse.** Microsoft's managed signing service (formerly Trusted Signing, now Artifact Signing) issues short-lived certificates. Criminal operations abused it to sign malware, and Microsoft disrupted one such service (tracked as Fox Tempest) in May 2026. A valid signature from a cloud-issued certificate is evidence of an identity check, not of good intent.
    - **SHA-1 is on its way out.** Windows code signing moved to SHA-256 (SHA-1-only signatures were retired for Windows updates around 2019–2020), and NIST plans to retire SHA-1 by the end of 2030. Use SHA-256 for IOCs and evidence. MD5 and SHA-1 remain useful only as lookup keys.
    - **Reputation and signature-based execution control.** Smart App Control on Windows 11 and App Control for Business (formerly WDAC) allow or block programs using signatures and cloud reputation, which makes signer information part of prevention as well as triage.
    - **ATT&CK names used on this page**: T1553.002 Subvert Trust Controls: Code Signing, T1588.003 Obtain Capabilities: Code Signing Certificates, T1587.002 Develop Capabilities: Code Signing Certificates, T1036.001 Invalid Code Signature, T1036.003 Rename Legitimate Utilities, T1195.002 Compromise Software Supply Chain.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't close a ticket on "0 detections".** Check the first-seen date and the file's other properties. New malware is routinely clean on day one.
    - **Don't rely on hash block lists alone.** A one-byte change defeats them. Add behaviour detections, signer-based rules and fuzzy hashes or imphash for families.
    - **Don't use MD5 or SHA-1 for evidence integrity or allow-listing.** Collisions are practical. Record SHA-256 (and keep MD5/SHA-1 only for feeds that require them).
    - **Don't upload sensitive or targeted samples to public services by reflex.** Hash lookups first. Uploads can leak data and tip off the attacker.
    - **Don't read "Valid" as "safe", and don't trust the version resource.** Only the signer certificate is verified. `Company` and `Description` are just text the developer wrote.
    - **Don't trust a signature just because the publisher is big.** Stolen keys, abused signing programmes and supply-chain compromises have all produced malware with famous names on it. Pivot on the certificate thumbprint and judge behaviour.
    - **Don't forget catalog signing.** A Windows system file copied off its host may look unsigned. Verify it on the original machine or against the original catalog before calling it tampered.

## Practice questions { #quiz }

### Question 1

An analyst looks up the SHA-256 of an email attachment: 0 detections out of 70, first submission 3 hours ago. They close the ticket as "clean". (a) What's wrong with that conclusion? (b) How would your view change if the first submission were four years ago, with thousands of submissions under the name of a popular open-source tool? (c) Why does it not leak the document's contents to look up its hash, and when could the lookup still reveal something?

??? success "Answer and explanation"
    **(a)** A hash lookup is a **deny list**. It can only confirm bytes already known to be bad. A file first seen three hours ago hasn't had time for engines and analysts to catch up, and vendors often flag new samples 24–48 hours later. "0 detections" here means "no opinion yet", not "clean". Continue triage: signature, strings and structure, sandbox, and check where else the attachment arrived.

    **(b)** Years of history and many submissions under a well-known name, with no detections, is much stronger evidence that the file is what it claims to be. It still isn't proof, so you'd also check that it's validly signed by that project's usual publisher and that the context (who downloaded it, why) makes sense.

    **(c)** A cryptographic hash is **one-way**: you can't rebuild the input from it, so the service learns nothing about the content. It could still reveal something if the service already has the file (someone uploaded it). Then the lookup shows that **you** also have it, which matters if the attacker is watching searches for their own samples. Uploading the file, by contrast, hands over the content itself.

### Question 2

`sigcheck -a -h -vt` on `C:\ProgramData\Updater\svchost.exe` shows: `Verified: Unsigned`, `Company: Microsoft Corporation`, `Description: Host Process for Windows Services`, `Original Name: rsync_x.exe`, `Entropy: 7.9`, `VT detection: 0/71`. (a) Interpret each line. (b) Which ATT&CK techniques apply? (c) What would you do next?

??? success "Answer and explanation"
    **(a)** `Unsigned`: genuine Microsoft binaries are always signed (embedded or by catalog), so an unsigned "Microsoft" file is a red flag. `Company`/`Description`: from the version resource, which anyone can write, and here it's copied from the real svchost to look legitimate. `Original Name: rsync_x.exe`: the developer's file name doesn't match `svchost.exe`, so the file was **renamed**. Also, `svchost.exe` only belongs in `C:\Windows\System32`, not `ProgramData`. `Entropy 7.9`: close to the maximum of 8, so likely **packed or encrypted**. `VT 0/71`: probably new, not clean. Everything else points to malicious.

    **(b)** **T1036.005 Masquerading: Match Legitimate Name or Location** (a svchost look-alike), **T1036.003 Rename Legitimate Utilities** if it turns out to be a renamed tool (here, possibly a data-transfer tool used for exfiltration), and **T1027.002 Software Packing** given the entropy.

    **(c)** Collect the SHA-256 and search the fleet for it and for the path. Look at process creation for this file (parent, command line, user) and its network connections. Check how it got there (file creation, service or scheduled task creation). Analyse a copy in a sandbox or isolated VM, and contain the host if the behaviour confirms it.

### Question 3

A file is signed: `Get-AuthenticodeSignature` says `Status : Valid`, the signer is a well-known hardware vendor, and the timestamp is two weeks ago. EDR shows the file loading a driver and then terminating your EDR's processes. (a) What exactly does `Valid` guarantee, and what doesn't it? (b) Give three ways malware can end up with a valid signature. (c) Why was MD5 a problem for code signing, and what changed?

??? success "Answer and explanation"
    **(a)** `Valid` means the file hasn't been modified since it was signed (the Authenticode hash matches), the signature was made with the private key matching the certificate, and the certificate chains to a trusted root and wasn't expired or revoked at signing time. It does **not** guarantee that the code is benign, that the signer is the real author of this file, or that the signer still controls its key. The behaviour (killing security tools via a driver) decides here: it's malicious.

    **(b)** Any three of: the attacker **buys their own certificate**, often under a shell company or through a signing-as-a-service broker. A legitimate company's **key or signing access is stolen** (as with the 2022 wiper, or leaked vendor keys). A **legitimate signing pipeline is abused**: driver-signing programmes, cloud signing services, or a compromised build system (supply chain). Or, historically, a **hash collision** lets a signature be moved from a good file to an evil one. A related case: a genuine, validly signed but **vulnerable driver** is brought along and exploited ("bring your own vulnerable driver"), which fits the scenario in the question.

    **(c)** Authenticode signs a **hash** of the file. If two files can be made with the same hash, a signature on one is a valid signature on the other. MD5 collisions became practical, as demonstrated with Authenticode in 2009 and used in the wild by Flame in 2012 to forge a Microsoft-chained certificate. Modern code signing uses **SHA-256**, older MD5 and SHA-1 signatures are no longer accepted for new Windows code, and SHA-1 is being retired altogether.

## Related { #related }

- [RTF, PDF and other files as exploits, and quick triage](rtf-pdf-misc-triage.md) · [Strings](strings.md) · [Identifying files](file-identification.md)
- [Screenshots, sandboxes and when to go manual](../http-analysis/screenshots-sandboxes.md) · [HTTPS and certificates](../http-analysis/https-certificates.md)
- [Zeek files.log & pe.log](../../../network/zeek/files-log.md) · [Process creation events](../important-events/process-creation.md)
- [Application control, FIM and catching persistence](../endpoint-defense/appcontrol-fim-persistence.md) · [Impair defenses and log clearing](../../../adversary/impair-defenses-log-clearing.md)
