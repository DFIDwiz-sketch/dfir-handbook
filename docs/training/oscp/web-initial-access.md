---
title: Web & Initial Access
tags:
  - oscp
---

# Web & Initial Access

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per standalone (`local.txt`) · **Last updated:** 2026-10-23
</div>

!!! abstract "In one sentence"
    Getting the first shell on a standalone: usually a web application or an exposed service, often a public exploit that needs fixing before it runs.

!!! note "How this page is organised"
    A study map of the initial-access surface. The exam rewards thorough enumeration and simple ideas over clever ones — most footholds are a known software version, a default credential, or an upload the app shouldn't allow.

## 1. Enumerate every service { #enumeration }

Start from the [Nmap](../../pentesting/recon/nmap/index.md) output and treat each open port as its own small investigation. Don't wait for the full scan — start on the first ports while the rest runs.

- **Identify versions.** A service banner or a web app's version is the fastest route to a public exploit — search `searchsploit <product> <version>`.
- **Read everything.** Page source, comments, robots.txt, error messages, HTTP headers. OSCP boxes hide a lot in plain sight.
- **Fuzz web content.** Directories, files, and vhosts / subdomains (`feroxbuster`, `ffuf`, `gobuster`). A hidden `/admin` or a dev vhost is a common way in.
- **Don't stop at the first finding.** An LFI is not the whole box — there may also be an upload, an SSRF, or a second app on another port.

## 2. Web application vectors { #web-vectors }

| Vector | What to look for | Lead |
|---|---|---|
| **Known-vulnerable software** | A CMS / app with a version number | `searchsploit`; read and fix the exploit before running it |
| **Default / weak credentials** | Admin panels, Tomcat, Jenkins, databases | Try `admin:admin`, product defaults, then a short spray |
| **SQL injection (manual)** | Input that changes the response; errors | Auth bypass, data extraction, sometimes RCE — by hand, see [below](#sqli) |
| **File upload** | Any upload form | Bypass the filter to upload a web shell → but read a flag from an **interactive** shell, not the web shell ([exam rule](exam-format.md#flag-rules)) |
| **LFI / path traversal** | A parameter that loads a file | Read SSH keys / config; chain with log poisoning or an upload for RCE |
| **SSRF** | The app fetches a URL you control | Reach internal services, cloud metadata |
| **Authenticated features** | Once logged in, template / plugin / import features | Many CMS RCEs need a login first |

### SQL injection — manual only { #sqli }

sqlmap is **banned** in the exam. Learn to do it by hand: detect with a quote and boolean/time payloads, enumerate with `UNION SELECT` or error-based extraction, then escalate (read files, write a web shell, or `xp_cmdshell` on MSSQL). Keep a notes file of the payloads that worked per database type.

### File upload → shell { #file-upload }

The goal is code execution, but remember the flag must come from an **interactive** shell:

1. Upload a web shell (bypass the filter — extension tricks, content-type, magic bytes, double extensions, `.htaccess`).
2. Use the web shell only to launch a **reverse shell** back to your handler.
3. Read `local.txt` from that interactive shell.

## 3. Public exploits { #public-exploits }

Most exam footholds use a public exploit, and most need work:

- Find it: `searchsploit <product> <version>`, Exploit-DB, GitHub.
- **Read it before running it** — understand what it does; never run an unknown binary against a box blindly.
- Fix it: update the target IP/port, the payload, Python 2 → 3, broken URLs, outdated offsets.
- **Document changes for the report:** modified code, original URL, and an explanation of every change ([exam rule](exam-format.md#exploit-code)).

## 4. Client-side attacks { #client-side }

If a box simulates a user who opens files (common in AD-flavoured standalones), a file you plant or send can call back to you — a macro document, a malicious shortcut, or a captured NetNTLMv2 hash via a UNC path. Capture the hash by making the target connect to **your** SMB server — **not** by poisoning name resolution with Responder, which is a banned spoofing technique ([exam rule](exam-format.md#restricted)).

## 5. Non-web services { #other-services }

Don't tunnel-vision on port 80/443:

- **FTP (21)** — anonymous login, writable directories, known-vuln versions.
- **SMB (445)** — null sessions, readable shares, `nxc smb -u '' -p ''`.
- **SNMP (161/UDP)** — `snmpwalk` for users, processes, software. Remember UDP: run a UDP scan.
- **NFS (2049)** — `showmount -e`; misconfigured exports and no_root_squash.
- **SSH (22)** — weak credentials, found private keys, version-specific issues.

## Checklist { #checklist }

- [ ] All ports enumerated; versions identified and searched
- [ ] Web content fuzzed (dirs, files, vhosts); source and headers read
- [ ] Default / weak credentials tried on every login
- [ ] Each vector pushed past the first finding (upload + LFI + SSRF…)
- [ ] Public exploit understood, fixed, and changes noted for the report
- [ ] UDP services (SNMP) and non-web services checked

## Related pages

- [Nmap](../../pentesting/recon/nmap/index.md) · [Well-known ports](../../basics/well-known-ports.md) · [HTTP status codes](../../basics/http-status-codes.md)
- [Red Team: Initial Access](../../redteam/initial-access.md) · [Phishing delivery](../../adversary/phishing-delivery.md) · [Methodology & habits](methodology.md)

## References

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
