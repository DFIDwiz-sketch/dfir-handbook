---
title: "Linux Log Files and the systemd Journal — the Traditional Log Path, Files Worth Collecting, journalctl, Command-Line Logging and a Section Summary"
tags:
  - training
  - blue-team
  - linux
  - logging
  - journald
  - auditd
---

# Linux Log Files and the systemd Journal — the Traditional Log Path, Files Worth Collecting, journalctl, Command-Line Logging and a Section Summary { #log-files-journal }

!!! abstract "What this page covers"
    The road a Linux log message travels: from the program, through the `/dev/log` socket and the syslog daemon, into plain-text files under `/var/log` and across the network — and how journald now sits in the middle of that road. The log files most worth collecting (`auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron`, `audit.log`, `ufw.log`, web server and database logs, plus the binary `wtmp`/`btmp`/`lastlog` login records), how they differ between Debian- and Red Hat-style systems, and how log rotation affects collection and tampering. The systemd journal: where it lives, why it is a structured binary database, how to query it with `journalctl`, and how its **trusted fields** expose a forged message that a text file would accept. Extra command-line logging with auditd, Sysmon for Linux, Snoopy and `logger`. A summary of the whole Linux logging section, then practice questions with explanations.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. The classic path is **program → `/dev/log` socket → syslog daemon → text files in `/var/log`** (and optionally → a remote collector). The daemon writes the standard header in front of each message and uses **facility and severity** to choose the file.
2. On systemd systems, **journald owns `/dev/log`**. Messages go into the journal first, and rsyslog (if installed) reads them from journald to write the familiar text files. No rsyslog means **no `/var/log/auth.log`** — only the journal.
3. File names differ by family: authentication goes to **`/var/log/auth.log`** (Debian/Ubuntu) or **`/var/log/secure`** (Red Hat family); the general log is **`/var/log/syslog`** or **`/var/log/messages`**. Check each distribution rather than assuming.
4. The most valuable files for security are the authentication log, the general system log, `audit.log`, cron logs, firewall logs and your web/database server logs. **`kern.log`** is mostly noise but holds USB and firewall messages.
5. Login history is also kept in **binary** files — `wtmp` (logins), `btmp` (failed logins), `lastlog` — read with `last`, `lastb` and `lastlog`, not `cat`. Newer distributions are replacing them with Y2038-safe databases (`wtmpdb`, `lastlog2`).
6. The **systemd journal** (`/var/log/journal/<machine-id>/`, or `/run/log/journal` if not persistent) is a **structured binary log** with named fields, much closer to Windows EVTX. Read it with **`journalctl`**: `-u` for a service, `--since`, `-p`, `-o json`.
7. Journal fields that start with an underscore (`_PID`, `_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`) are **added by journald from the kernel**, not supplied by the program. They reveal who really wrote a message — the answer to `logger` forgery.
8. Built-in logging does not record every command. Add **auditd** (built in), **Sysmon for Linux** (third-party, free) or **Snoopy**, and use **`logger`** for your own scripts. Then make sure whatever you add is actually parsed and forwarded — a log you can't parse is a log you can't alert on.

## The traditional Linux log path { #log-path }

### From program to file { #program-to-file }

Picture an office mailroom. Every department (program) drops envelopes into one slot in the wall (`/dev/log`). Behind the wall, one clerk (the syslog daemon) stamps each envelope with the date and the sender's name, reads the department and urgency labels (facility and severity), and files it in the right pigeonhole (a text file in `/var/log`) — maybe also photocopying it to head office (a remote collector).

Back to the technical reality:

1. A program calls the C library function `syslog()` (or a logging library that does the same). The message, its facility, its severity and the program's tag are written to the Unix domain socket **`/dev/log`**.
2. The kernel writes its own messages to a ring buffer (what `dmesg` shows), which the daemon reads separately.
3. The **syslog daemon** (rsyslog, syslog-ng) receives the message, adds the header (time, host, tag, PID) and compares facility and severity with its rules.
4. It appends the line to one or more **plain-text files**, typically under **`/var/log`**, and can send a copy to a **remote collector**.

Here is what lands in the files of an invented Ubuntu host `web-01`:

```
/var/log/auth.log:
Nov 20 14:25:01 web-01 CRON[4295]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Nov 20 14:25:01 web-01 CRON[4295]: pam_unix(cron:session): session closed for user root

/var/log/syslog:
Nov 20 14:13:51 web-01 NetworkManager[574]: <info>  [1795144431.5264] dhcp4 (eth0): activation: beginning transaction (timeout in 45 seconds)
Nov 20 14:13:51 web-01 dhclient[4231]: DHCPDISCOVER on eth0 to 255.255.255.255 port 67 interval 3 (xid=0x5a1c2e7d)
```

Line by line:

- `CRON[4295]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)` — the cron daemon (process 4295) is about to run a scheduled job as `root`. Cron goes through PAM (the pluggable authentication modules), and the PAM module `pam_unix` reports the session opening. That's why a job scheduler shows up in the **authentication** log.
- `session closed for user root` — the job finished. A pair like this every few minutes is normal background noise. What matters is a **new** pattern: a cron session for an unusual user, or at an unusual interval, can be a persistence job (MITRE ATT&CK **T1053.003**, Scheduled Task/Job: Cron).
- `NetworkManager[574]: <info>  [1795144431.5264] dhcp4 (eth0): ...` — NetworkManager writes its own level (`<info>`) and a Unix timestamp inside the message. That's not the syslog PRI; it's just text the program chose to include. Free-form messages contain whatever the developer decided.
- `dhclient[4231]: DHCPDISCOVER on eth0 to 255.255.255.255 port 67 ...` — the DHCP client is broadcasting for an address. Together with later `DHCPACK` lines this tells you which IP the host had and when.

Notice that each file is just text. Any program — your SIEM agent, `grep`, `less` — can read it, which is the strength of the design. And each file mixes many programs, sorted only by facility and severity rules, which is its weakness.

### Where journald fits in today { #journald-in-path }

On almost every current distribution, systemd's logging service **journald** owns `/dev/log`. The road now looks like this:

```
program (syslog())       ──> /dev/log ──┐
program (native API)     ───────────────┤
kernel (/dev/kmsg)       ───────────────┼──> journald ──> journal files
service stdout/stderr    ───────────────┘        │       (/var/log/journal or /run/log/journal)
                                                 │
                                                 └──> rsyslog (imjournal or imuxsock)
                                                        ├──> /var/log/auth.log, /var/log/syslog, ...
                                                        └──> remote collector
```

- journald collects from four places: the syslog socket, its own native API, the kernel, and the **standard output and error of every service** systemd starts. That last one matters: a service that just prints to stdout ends up in the journal even though it never "logged" in the syslog sense.
- rsyslog then gets its copy from journald — on Red Hat systems through the `imjournal` input module, on Debian/Ubuntu through a socket journald forwards to (`imuxsock`). It writes the text files and forwards as before.
- If rsyslog isn't installed (the default on Debian 12 and later), the text files are simply **never created**. The journal is the only local log store.

**[Supplement] Why this matters for collection.** If your SIEM agent tails `/var/log/auth.log` and that file doesn't exist, the agent sends nothing — and doesn't complain. For every Linux build in your estate, find out whether the source of truth is the journal, the text files, or both, and configure the agent to read the right one.

## Common Linux log files to collect { #log-files }

### The file map { #file-map }

Each distribution logs a little differently, so treat this as a starting map and check your own builds.

| What | Debian / Ubuntu | Red Hat / Fedora / Rocky / Alma | Security value |
| --- | --- | --- | --- |
| Authentication (sshd, sudo, su, PAM, cron sessions) | `/var/log/auth.log` | `/var/log/secure` | Very high |
| General system messages | `/var/log/syslog` | `/var/log/messages` | High — the first place to look for most things, similar to the Windows System log |
| Kernel | `/var/log/kern.log` | (inside `messages`) | Low/medium — noisy, but USB devices, firewall drops, module loads |
| Cron | (inside `syslog`) | `/var/log/cron` | Medium — persistence via scheduled jobs |
| Audit framework | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` | Very high when rules are set |
| UFW firewall | `/var/log/ufw.log` | (firewalld logs to `messages`/journal) | Medium/high |
| Apache web server | `/var/log/apache2/access.log`, `error.log` | `/var/log/httpd/access_log`, `error_log` | High on web servers |
| Nginx | `/var/log/nginx/access.log`, `error.log` | same | High on web servers |
| MySQL / MariaDB | `/var/log/mysql/error.log` | `/var/log/mysqld.log` or `/var/log/mariadb/mariadb.log` | Medium — logins and errors; query logging is usually off |
| Package installs | `/var/log/dpkg.log`, `/var/log/apt/history.log` | `/var/log/dnf.log` (and `dnf history`) | Medium — tools installed by an intruder |
| Logins (binary) | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | same | High |

**[Correction]** You will sometimes see lists that put `kern.log` and `ufw.log` under `/var/log/audit/`. They aren't there: `/var/log/audit/` belongs to auditd alone, and `kern.log` and `ufw.log` sit directly in `/var/log/`. Likewise the MySQL log path depends on the package and distribution — find the real path in the database's configuration (`log_error`) instead of trusting a list.

### Reading the authentication log { #auth-log }

The authentication log is where an SSH intrusion first becomes visible. A realistic slice from `/var/log/auth.log` on `web-01`:

```
Nov 20 14:31:07 web-01 sshd[5011]: Invalid user admin from 203.0.113.45 port 40122
Nov 20 14:31:09 web-01 sshd[5011]: Failed password for invalid user admin from 203.0.113.45 port 40122 ssh2
Nov 20 14:33:40 web-01 sshd[5032]: Accepted publickey for deploy from 198.51.100.61 port 50544 ssh2: ED25519 SHA256:kq3V0bXa1nYv7k0Lr2Wc9mT4Jt8sQ1eZpHfUo6dNgAs
Nov 20 14:33:40 web-01 sshd[5032]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by deploy(uid=0)
Nov 20 14:35:02 web-01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt install -y socat
Nov 20 14:35:02 web-01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1003)
Nov 20 14:36:18 web-01 su[5101]: (to backup) deploy on pts/1
Nov 20 14:36:18 web-01 su[5101]: pam_unix(su-l:session): session opened for user backup(uid=1010) by deploy(uid=1003)
```

Line by line:

- `Invalid user admin from 203.0.113.45 port 40122` — someone tried to log in as `admin`, an account that doesn't exist here. Usually the first line of a guessing run.
- `Failed password for invalid user admin ...` — the password attempt itself failed. Many such lines from one source with different user names is password guessing (**T1110.001**); one password across many accounts is spraying (**T1110.003**).
- `Accepted publickey for deploy from 198.51.100.61 ... ED25519 SHA256:kq3V...` — a **successful** login with an SSH key. The key's **fingerprint** is gold: it tells you which key was used, so you can find it in `~deploy/.ssh/authorized_keys` and check whether it's one you issued. An unknown key added there is persistence (**T1098.004**, SSH Authorized Keys).
- `pam_unix(sshd:session): session opened for user deploy(uid=1003)` — the session really started.
- `sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt install -y socat` — `deploy` used sudo to run a command **as root**: installing `socat`, a network relay tool. sudo's semicolon-separated fields (`TTY`, `PWD`, `USER`, `COMMAND`) are easy to parse and are one of the best sources on a Linux host. Installing a tunnelling tool right after a remote login is worth a hard look (tool transfer and protocol tunnelling, **T1105**, **T1572**).
- `su[5101]: (to backup) deploy on pts/1` — `deploy` switched to the `backup` account with `su`. The next line confirms the session. Account hopping like this is how intruders move between privilege levels.

**[Changed] `sshd` may now be `sshd-session`.** From OpenSSH 9.8 (2024), the per-connection work moved into a separate program, `sshd-session`. On distributions that ship it, many of these lines carry the tag `sshd-session[5032]:` instead of `sshd[5032]:`. Several well-known log tools had to update their patterns, and a SIEM rule that matches the literal `sshd[` will silently miss them. Check what your newest builds write and match both.

### Other files, one sample each { #other-files }

A UFW firewall drop in `/var/log/ufw.log` (written from kernel messages):

```
Nov 20 14:40:12 web-01 kernel: [183311.442190] [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:ab:cd:ef:08:00 SRC=198.51.100.23 DST=10.20.30.41 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=40122 DF PROTO=TCP SPT=44871 DPT=3306 WINDOW=64240 RES=0x00 SYN URGP=0
```

- `kernel:` and `[183311.442190]` — the firewall lives in the kernel, so the "program" is the kernel and the bracket is seconds since boot.
- `[UFW BLOCK]` — the prefix UFW adds so the line can be routed into `ufw.log`.
- `IN=eth0 OUT=` — arrived on `eth0`, wasn't routed anywhere (it was for this host).
- `SRC=198.51.100.23 DST=10.20.30.41` — from an outside address to this server.
- `PROTO=TCP SPT=44871 DPT=3306` — TCP from source port 44871 to **3306, MySQL**. Someone is probing the database port from the internet.
- `SYN` — a connection attempt, not mid-session traffic.

The firewall log fields are explained in detail in a later section; for now, know that this file exists and is worth collecting.

An Apache access log line (combined log format) from `/var/log/apache2/access.log`:

```
198.51.100.77 - - [20/Nov/2026:14:42:31 +1100] "GET /wp-login.php HTTP/1.1" 404 492 "-" "python-requests/2.32.3"
```

- `198.51.100.77` — the client IP.
- `- -` — the `identd` name and the authenticated user; dashes mean none.
- `[20/Nov/2026:14:42:31 +1100]` — note that **this** format includes the year and time zone, unlike the syslog header.
- `"GET /wp-login.php HTTP/1.1"` — the request line. This server has no WordPress, so this is a scanner looking for one.
- `404 492` — status code (not found) and response size in bytes.
- `"-" "python-requests/2.32.3"` — referrer (none) and user agent: a script, not a browser.

### The binary login records { #wtmp }

**[Supplement]** Three login records are **binary**, so `cat` shows garbage and `grep` misses things:

- `/var/log/wtmp` — every login and logout, plus reboots. Read with `last`.
- `/var/log/btmp` — failed logins. Read with `sudo lastb`.
- `/var/log/lastlog` — the last login of each account. Read with `lastlog`.

```
$ last -F -n 3
deploy   pts/1        198.51.100.61    Fri Nov 20 14:33:40 2026   still logged in
j.kim    pts/0        10.20.30.15      Fri Nov 20 09:02:11 2026 - Fri Nov 20 11:47:30 2026  (02:45)
reboot   system boot  6.8.0-49-generic Thu Nov 19 22:10:05 2026   still running
```

- `last` — reads `wtmp`; `-F` prints full dates with the year; `-n 3` shows the three newest entries.
- Each row: user, terminal (`pts/1` = a remote pseudo-terminal), source host, login time, logout time or `still logged in`, and the session length.
- `reboot system boot` rows give you boot times — useful when the journal or other logs start fresh.

**[Changed]** The old formats store times in 32 bits and break in 2038. Debian 13 and some other recent distributions have started replacing them with SQLite-based tools — `wtmpdb` for login history and `lastlog2` for last logins — so on those systems `last` may read a database instead of `/var/log/wtmp`, and `lastlog` may be missing. Your collection and your forensic tooling need to know which one a host uses.

### Log rotation { #rotation }

Text logs would grow forever, so a scheduled job, **logrotate**, renames them on a schedule (weekly by default on many systems) and compresses older copies:

```
$ ls -l /var/log/auth.log*
-rw-r----- 1 syslog adm  48211 Nov 20 14:36 /var/log/auth.log
-rw-r----- 1 syslog adm 612884 Nov 15 00:00 /var/log/auth.log.1
-rw-r----- 1 syslog adm  71240 Nov  8 00:00 /var/log/auth.log.2.gz
-rw-r----- 1 syslog adm  69915 Nov  1 00:00 /var/log/auth.log.3.gz
```

- `auth.log` — the live file being written now.
- `auth.log.1` — last week's, not yet compressed.
- `auth.log.2.gz`, `.3.gz` — older weeks, gzip-compressed. Search them with `zgrep "Accepted" /var/log/auth.log.*.gz`, which unpacks on the fly.
- `syslog adm` and `-rw-r-----` — owned by the `syslog` user and the `adm` group; only they and root can read it. Members of `adm` can read authentication logs, so watch who is in that group.

Two consequences: your agent must follow the file across a rename (any decent agent does), and **local history is short** — four weeks here. An intruder with root can also delete or edit these files (**T1070.002**, Clear Linux or Mac System Logs). Only what has already left the host is safe.

## The systemd journal { #journal }

### What it is and why it exists { #journal-what }

The journal was designed to fix syslog's weak points: no structure, no custom fields, no reliable information about who sent a message. **systemd-journald** is a background service that accepts log data and writes it into a **binary, indexed database**, much like an `.evtx` file on Windows.

If syslog files are a pile of postcards, the journal is a filing cabinet with an index card for each letter: sender, time, department and many more fields, all searchable — and the post office itself writes some of the fields, so the sender can't fake them.

The technical facts:

- **Location.** Persistent storage is `/var/log/journal/<machine-id>/`, where `<machine-id>` is the value in `/etc/machine-id`. If that directory doesn't exist and storage is left at `auto`, journald keeps logs only in **`/run/log/journal`**, which is in memory and **lost at reboot**. Check which you have — "the logs from before the reboot are gone" is a common, avoidable surprise in an investigation.
- **Format.** Every entry is a set of `FIELD=value` pairs. Most values are text, but binary values are allowed, and entries can carry fields the program invents.
- **Compatibility.** Entries still carry syslog-style data (`MESSAGE`, `PRIORITY`, `SYSLOG_FACILITY`, `SYSLOG_IDENTIFIER`), and everything can be forwarded as normal syslog.
- **Size and retention.** Controlled in `/etc/systemd/journald.conf` (`SystemMaxUse=`, `MaxRetentionSec=`, `Storage=`). The journal deletes its oldest files when it hits the limit.

### Querying with journalctl { #journalctl }

Typing `journalctl` alone shows the whole journal, oldest first, in a pager. In practice you filter. An example for a network IDS service:

```
$ journalctl -u suricata --since "2026-11-20 00:00" --no-pager
Nov 20 02:15:09 sensor-01 systemd[1]: Starting suricata.service - Suricata IDS/IDP daemon...
Nov 20 02:15:10 sensor-01 suricata[34399]: Notice: suricata: This is Suricata version 7.0.7 RELEASE running in SYSTEM mode
Nov 20 02:15:11 sensor-01 systemd[1]: Started suricata.service - Suricata IDS/IDP daemon.
Nov 20 13:52:44 sensor-01 systemd[1]: Stopping suricata.service - Suricata IDS/IDP daemon...
Nov 20 13:52:45 sensor-01 systemd[1]: suricata.service: Deactivated successfully.
```

- `journalctl` — the journal query tool.
- `-u suricata` — only entries for the systemd **unit** (registered service) `suricata.service`. That includes systemd's own start/stop messages about the unit and anything the service wrote.
- `--since "2026-11-20 00:00"` — only from midnight onwards (`--until` sets an end).
- `--no-pager` — print straight to the screen instead of opening `less`.
- The output looks like syslog: time, host, tag[PID], message. The journal can always show itself in this familiar form.
- The interesting part is the last two lines: the IDS sensor was **stopped** at 13:52. If nobody planned that, a stopped sensor is defence evasion (**T1562.001**, Disable or Modify Tools).

Other options you'll use constantly:

| Command | What it does |
| --- | --- |
| `journalctl -p warning` | Only severity `warning` and more severe (same 0–7 scale as syslog) |
| `journalctl -k` | Kernel messages only (like `dmesg`, but kept across time) |
| `journalctl -b` / `-b -1` | This boot / the previous boot |
| `journalctl --list-boots` | Every boot the journal remembers, with time ranges |
| `journalctl _COMM=sudo` | Filter on any field, here the process name |
| `journalctl -f` | Follow live, like `tail -f` |
| `journalctl -o json-pretty -n 1` | Show the newest entry with **all** its fields |
| `journalctl --disk-usage` | How much space the journal uses |
| `journalctl --verify` | Check the journal files for corruption (and for sealing, below) |

### Trusted fields: catching a forged message { #trusted-fields }

On the syslog page we forged an sshd line with `logger`. In a text file it looks real. In the journal, look at all the fields of that entry:

```
$ journalctl -o json-pretty -n 1 SYSLOG_IDENTIFIER=sshd
{
        "__REALTIME_TIMESTAMP" : "1795143831204871",
        "_HOSTNAME" : "web-01",
        "PRIORITY" : "6",
        "SYSLOG_FACILITY" : "10",
        "SYSLOG_IDENTIFIER" : "sshd",
        "MESSAGE" : "Accepted password for admin from 10.20.30.99 port 40022 ssh2",
        "_TRANSPORT" : "syslog",
        "_PID" : "5120",
        "_UID" : "1004",
        "_GID" : "1004",
        "_COMM" : "logger",
        "_EXE" : "/usr/bin/logger",
        "_CMDLINE" : "logger -t sshd -p authpriv.info Accepted password for admin from 10.20.30.99 port 40022 ssh2",
        "_SYSTEMD_UNIT" : "session-12.scope",
        "_BOOT_ID" : "3f1c0d2e9a8b4c7d8e6f5a4b3c2d1e0f"
}
```

Field by field:

- `__REALTIME_TIMESTAMP` — microseconds since 1970 in UTC (here 2026-11-20 03:03:51.204871 UTC). Unlike the syslog header, the year, time zone and sub-second precision are all there.
- `PRIORITY` `6` and `SYSLOG_FACILITY` `10` — severity `info`, facility `authpriv`. **Supplied by the sender.**
- `SYSLOG_IDENTIFIER` `sshd` and `MESSAGE` — also supplied by the sender, so also forgeable.
- `_TRANSPORT` `syslog` — came in through the `/dev/log` socket (other values: `journal`, `stdout`, `kernel`).
- `_PID`, `_UID`, `_GID` — **added by journald** from the kernel's record of the sending process. The underscore means the sender cannot set it.
- `_COMM` `logger`, `_EXE` `/usr/bin/logger`, `_CMDLINE` — the real program and its full command line.
- `_SYSTEMD_UNIT` `session-12.scope` — written from a user's login session, not from the SSH service.

A real sshd entry would show `_COMM=sshd` (or `sshd-session`), `_UID=0`, and `_SYSTEMD_UNIT=ssh.service` (Debian/Ubuntu) or `sshd.service` (Red Hat). Here an unprivileged user (UID 1004) ran `logger` from an interactive session. This is a planted line.

A detection idea that follows: alert when `SYSLOG_IDENTIFIER` is a sensitive daemon (`sshd`, `sudo`, `su`) but `_COMM` or `_EXE` doesn't match it. One honest limit: for a process that exits extremely fast, journald sometimes can't read all its details in time and some underscore fields are missing. Missing trusted fields are a reason to look closer, not proof either way.

Remember too that the trusted fields only exist **in the journal**. If rsyslog writes the message to `auth.log` and forwards it as plain syslog, they are dropped. That's a strong reason to have your agent read the journal itself, or to forward a structured format that keeps these fields.

### Getting the journal off the host and protecting it { #journal-forwarding }

Ways to get journal data to a SIEM:

- **An agent that reads the journal directly** (most SIEM and EDR agents, and OpenTelemetry collectors, have a journald input). This keeps all fields.
- **rsyslog reading the journal** (`imjournal`) and forwarding as syslog — familiar, but by default only the classic syslog fields survive.
- **journald's own `ForwardToSyslog=yes`** to a local syslog daemon.
- **`systemd-journal-upload` and `systemd-journal-remote`** — the journal's own HTTP(S) transport to a central journal server. Less common in SOCs, but it exists.

An intruder with root can shrink or wipe the journal (for example by forcing a rotation and then a vacuum of old files), which is the same **T1070.002** as deleting text logs. Journald offers **Forward Secure Sealing** (`journalctl --setup-keys`), which periodically signs the journal so `journalctl --verify` can show that entries were altered or removed after sealing. Sealing tells you tampering happened; it doesn't stop it. The real protection is still fast off-host forwarding.

## Additional command-line logging { #extra-logging }

By default Linux does not record "user X ran command Y with these arguments." Shell history (`~/.bash_history`) is not a log: the user controls it and can disable or wipe it (**T1070.003**, Clear Command History). There are three ways to fill the gap.

### 1. Built in: the Linux audit subsystem (auditd) { #auditd }

The kernel has an audit framework, and **auditd** is the service that writes its records to `/var/log/audit/audit.log`. It's available on nearly every distribution (installed by default on Red Hat; one package install on Debian/Ubuntu). Its upside is that it's built in and very detailed; its downside is that the records are hard to read and the rules are less intuitive than other tools.

A rule that records every program execution, saved in a file under `/etc/audit/rules.d/`:

```
-a always,exit -F arch=b64 -S execve -k exec_log
```

- `-a always,exit` — always create a record when the system call finishes.
- `-F arch=b64` — for 64-bit calls (add a second line with `arch=b32` to catch 32-bit ones too).
- `-S execve` — the system call that starts a new program.
- `-k exec_log` — tag matching records with the key `exec_log` so you can find them.

What one execution produces (simplified):

```
type=SYSCALL msg=audit(1795143831.204:4412): arch=c000003e syscall=59 success=yes exit=0 ppid=5032 pid=5201 auid=1003 uid=1003 euid=1003 tty=pts1 ses=7 comm="curl" exe="/usr/bin/curl" key="exec_log"
type=EXECVE msg=audit(1795143831.204:4412): argc=4 a0="curl" a1="-s" a2="-o" a3="/tmp/.cache-upd"
```

- `msg=audit(1795143831.204:4412)` — epoch time and an event serial number. Records with the same number belong to one event.
- `syscall=59` — `execve` on 64-bit x86. `success=yes` — it worked.
- `ppid=5032 pid=5201` — parent and child process IDs; 5032 was the SSH session from the auth log above.
- `auid=1003` — the **audit user ID**, the account that originally logged in. It stays the same through `sudo` and `su`, so it tells you who is really behind a root command.
- `comm="curl" exe="/usr/bin/curl"` — the program.
- `EXECVE ... a0= a1= a2= a3=` — the full argument list: `curl -s -o /tmp/.cache-upd` (the URL would follow as `a4`; it's shortened here). A download into a hidden file in `/tmp` is classic tool transfer (**T1105**).

`ausearch -k exec_log -i` finds these records and translates numbers into names. auditd is covered in detail, with process creation, in a later section.

### 2. Third-party: Sysmon for Linux { #sysmon-linux }

Microsoft's Sysmon, the popular free Windows monitoring tool, also has a Linux version. It uses eBPF to watch the kernel and records process creation, network connections, file creation and more, using the **same event IDs and XML layout as Windows Sysmon**. It writes to syslog/the journal, so a line in `/var/log/syslog` looks like this (shortened):

```
Nov 20 14:35:40 web-01 sysmon: <Event><System><Provider Name="Linux-Sysmon"/><EventID>1</EventID>...<Computer>web-01</Computer></System><EventData><Data Name="Image">/usr/bin/curl</Data><Data Name="CommandLine">curl -s -o /tmp/.cache-upd ...</Data><Data Name="User">deploy</Data><Data Name="ParentImage">/usr/bin/bash</Data>...</EventData></Event>
```

- `sysmon:` — the tag, so it can be routed and found.
- `<EventID>1</EventID>` — process creation, as on Windows.
- `Image`, `CommandLine`, `User`, `ParentImage` — the same named fields you know from Windows, so the same analytics and parsers can be reused across both platforms.

Its weak point is the transport: XML inside a syslog line needs a parser that knows to extract it.

### 3. Your own scripts: `logger` { #logger }

Any script can write to the system log with `logger`, which is useful for recording your own checks:

```
$ logger -t soc-integrity -p local5.notice "sha256 mismatch on /usr/sbin/sshd"
```

- `-t soc-integrity` — the tag, so the SIEM can find these messages.
- `-p local5.notice` — a local-use facility your team reserves for its own scripts, and severity `notice`.
- The message — what the script found.

The same tool that lets intruders forge lines lets you add useful ones. Record which `local` facilities your team uses so the SIEM engineer can map them.

**[Supplement] Snoopy.** Snoopy is a small open-source library that logs every program execution (user, command line, working directory) as a normal syslog line. It's easier to read than auditd but easier for a root intruder to switch off. It's covered with process creation later.

## Linux logging: section summary { #summary }

Compared to Windows, Linux logging takes an entirely different approach, simpler to understand and more painful to analyse at scale:

- **Plain text in files.** Easy to read with any tool, but every program writes its own sentence, so fields often have to be **parsed by hand** (regex) and parsers break when wording changes — as the move to `sshd-session` showed.
- **Facility and severity drive everything.** They decide which file each message is written to and which host it is forwarded to. They're the sender's claims, not facts.
- **The daemons are powerful.** rsyslog and syslog-ng can filter, buffer to disk, convert formats (for example to JSON) and send to other syslog relays, message brokers like Kafka, or databases.
- **The journal brings structure.** It has named fields and trusted fields, but it's binary, may be volatile, and its extra fields are lost if you forward only plain syslog.
- **Appliances are often Linux underneath.** Firewalls, proxies and storage boxes may run Linux but write their own custom log formats, which need their own parsers.

For a SOC, the practical point is: review which files and journals are collected, the format they arrive in, and the transport they use, and choose settings that favour detecting malicious activity. **Above all, check parsing — it's hard to write an analytic for a log that isn't reliably parsed.**

## Putting it to work in a SOC { #soc-use }

When you onboard a Linux build or pick up a Linux alert:

1. **Where is the source of truth?** Journal only, text files only, or both? Is the journal persistent (`/var/log/journal` exists) or will it vanish at reboot?
2. **Which files are collected?** At minimum the authentication log (`auth.log`/`secure`), the general log, `audit.log`, cron, firewall and the server application logs for that host's role. Is rotation handled?
3. **Are the important programs parsed?** sshd (and `sshd-session`), sudo, su, cron, auditd, the web server. Test with fresh sample lines from the current version.
4. **Can you see commands?** Is auditd (or Sysmon for Linux, or Snoopy) recording executions, and are those records reaching the SIEM?
5. **Can you trust it?** Are trusted journal fields kept? Are logs forwarded quickly, over TLS? Is there an alert when a host goes silent?
6. **During an incident**, collect from the host before it changes: `/var/log` (including rotated `.gz` files), the journal directory, `wtmp`/`btmp`/`lastlog` (or `wtmpdb`/`lastlog2`), and `/var/log/audit/`.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The traditional path (program → syslog daemon → `/var/log` files and a remote collector), the file names `auth.log`/`secure` and `syslog`/`messages`, logrotate, `journalctl` with `-u`, auditd's record format and `logger` all work as described. The journal is now the default local store on essentially every mainstream distribution, and Sysmon for Linux is still maintained by Microsoft. The core lesson — check what's collected, how it's parsed and whether it's complete — hasn't changed.

!!! info "[Changed] What has changed"
    - **Journal first, text files optional.** Debian 12 and later don't install rsyslog by default, so `/var/log/auth.log` and `/var/log/syslog` don't exist unless you add it. Other distributions still ship rsyslog alongside journald; check each build.
    - **OpenSSH 9.8+ splits sshd.** Session messages can now come from `sshd-session`, and log tools and SIEM rules keyed on `sshd[` have had to be updated.
    - **Y2038-safe login records.** `wtmp`/`btmp`/`lastlog` are being replaced by `wtmpdb` and `lastlog2` on some recent distributions, starting with Debian 13. Forensic tools and collection scripts need to handle both.
    - **Agents over files.** SIEM, EDR and OpenTelemetry agents increasingly read the journal natively and keep its structured fields. Commercial Linux EDR sensors (usually eBPF-based) now record process and network activity that once required auditd or Snoopy; many SOCs use EDR telemetry as the main command-line source and auditd as an independent second source.
    - **Common schemas.** Pipelines often map Linux logs to schemas like Elastic Common Schema or OCSF, so that `user.name` or `process.command_line` means the same thing for Linux and Windows.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't assume a file exists because a list says so.** Paths vary by distribution and version (and some lists put `kern.log` and `ufw.log` under `/var/log/audit/`, which is wrong). Check real hosts and alert on silent sources.
    - **Don't rely on a volatile journal.** If `/var/log/journal` doesn't exist, logs vanish at reboot. Make storage persistent, and forward off the host anyway.
    - **Don't forward only plain syslog from the journal if you care about who wrote a line.** The trusted fields (`_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`) are dropped.
    - **Don't treat `.bash_history` as an audit log.** The user controls it. Use auditd, Sysmon for Linux, Snoopy or EDR.
    - **Don't `cat` or `grep` `wtmp`/`btmp`.** They're binary; use `last`/`lastb` (or the `wtmpdb` tools), or you'll miss or misread entries.
    - **Don't hard-code `sshd[` in detections.** Match `sshd-session` too, and test parsers after every major OS upgrade.

## Practice questions { #quiz }

### Question 1

A new Debian 13 web server was onboarded last month. The SIEM shows its Apache logs but **no SSH or sudo events at all**, even though admins log in every day. The agent is configured to tail `/var/log/auth.log`. What is the most likely reason, and how would you fix it so that you also keep the information that shows who really wrote each message?

??? success "Answer and explanation"
    **Most likely reason:** Debian 12 and later don't install rsyslog by default. Without a syslog daemon nobody creates `/var/log/auth.log` — the authentication events exist **only in the systemd journal**. The agent tails a file that isn't there and sends nothing, without an error. (Apache writes its own files directly, which is why those arrive.)

    **Checks:** `ls /var/log/auth.log` (no such file), `systemctl status rsyslog` (not installed), and `journalctl -u ssh --since today` (the logins are there). Also check `ls /var/log/journal` — if it doesn't exist, the journal is volatile and is lost at every reboot.

    **Fix:** the best fix is to have the agent **read the journal directly** (a journald input), filtering on units such as `ssh.service` and identifiers such as `sudo`, `su` and `sshd-session`. That keeps the trusted fields `_UID`, `_COMM`, `_EXE` and `_SYSTEMD_UNIT`. Installing rsyslog and tailing `auth.log` would also restore the events, but the plain text lines lose those fields. Make the journal persistent, update parsers for `sshd-session`, and add a "source went silent" alert per log type, not just per host — the host wasn't silent here, only one log type was.

### Question 2

On a Red Hat-family server you find this in `/var/log/secure`. Explain each line, name the ATT&CK techniques involved and say what you would check next.

```
Nov 20 02:14:09 db-02 sshd[3170]: Accepted password for svc_backup from 198.51.100.61 port 50544 ssh2
Nov 20 02:15:31 db-02 sudo: svc_backup : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -e
Nov 20 02:17:02 db-02 sudo: svc_backup : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/journalctl --vacuum-time=1s
```

??? success "Answer and explanation"
    **Line by line:**

    - 02:14:09 — an SSH **password** login to the service account `svc_backup` from the outside address `198.51.100.61`. Service accounts normally shouldn't log in interactively with a password; this may be a stolen or guessed credential (**T1078**, Valid Accounts; possibly **T1110**).
    - 02:15:31 — `svc_backup` used sudo to edit **root's crontab**. Working directory `/tmp` is also odd. Adding a root cron job is persistence (**T1053.003**).
    - 02:17:02 — sudo ran `journalctl --vacuum-time=1s`, which deletes journal files older than one second — wiping journal history. That's indicator removal (**T1070.002**). Note that the text file `/var/log/secure` still has the lines: the intruder cleaned the journal but not (yet) rsyslog's files, which is why it pays to have both and to forward off-host.

    **Next checks:**

    1. Preserve evidence now: copy `/var/log/secure*`, `/var/log/cron*`, `/var/log/messages*`, `/var/log/audit/`, the remaining journal and `wtmp`/`btmp` off the host.
    2. `sudo crontab -l -u root` and `/var/spool/cron/root` — what job was added? Check `/var/log/cron` for its runs.
    3. In the SIEM (already off-host), look at what the journal held before 02:17 and at auditd records with `auid` of `svc_backup` for every command run.
    4. `last -F` / `lastb` for other logins from `198.51.100.61`, and look for the same IP on other servers.
    5. Disable password login for service accounts, reset the credential, and consider journal sealing plus an alert on `journalctl --vacuum` and `--rotate` commands.

### Question 3

A text file shows `Nov 20 14:03:51 web-01 sshd[5120]: Accepted password for admin from 10.20.30.99 port 40022 ssh2`, but there's no matching login in `last`. Using the journal, how would you decide whether sshd really wrote this line? Give the command and the fields you'd compare, and explain why the text file alone can't answer this.

??? success "Answer and explanation"
    **Why the text file can't answer it:** the tag `sshd`, the PID, the facility and the message are all supplied by whoever sent the message. `logger -t sshd -p authpriv.info "..."` produces an identical-looking line, so the text proves only that **something** wrote this text.

    **Command:**

    ```
    journalctl -o json-pretty --since "2026-11-20 14:03:50" --until "2026-11-20 14:03:52" SYSLOG_IDENTIFIER=sshd
    ```

    - `-o json-pretty` shows every field of each entry.
    - `--since`/`--until` narrow to the second of the line.
    - `SYSLOG_IDENTIFIER=sshd` filters on the claimed tag.

    **Compare the trusted fields (set by journald, not the sender):**

    - `_COMM` / `_EXE` — real sshd shows `sshd` or `sshd-session` and `/usr/sbin/sshd` (or the `sshd-session` path). `logger` and `/usr/bin/logger` mean a forgery.
    - `_UID` — sshd runs as root (`0`); a normal user's UID means it wasn't sshd.
    - `_SYSTEMD_UNIT` — `ssh.service`/`sshd.service` for real sshd; `session-N.scope` means it came from someone's login session.
    - `_CMDLINE` — would show the full `logger ...` command.
    - `_PID` — compare with `SYSLOG_PID` and with the PID in the text line.

    The missing `last` entry fits a forgery too: a real accepted login normally also writes `wtmp`. If the trusted fields point to `logger`, find out who owns that UID and session, and treat the planted line as possible deliberate misdirection.

## Related { #related }

- [Syslog](syslog.md) — the format, transport, daemons, facility and severity this page builds on
- [Windows Logging](../windows-logging/index.md) — the structured, event-ID-based model to compare against
- [Linux Logs, Processes & Live Triage](../../../linux/logs-and-triage.md)
- [Linux Authentication & Shell History](../../../linux/auth-and-history.md)
- [Linux Persistence](../../../linux/persistence.md) — cron, systemd and SSH key persistence seen in these logs
- [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md) — SSH abuse from the network side
