---
title: conn.log
tags:
  - artifact
  - network
  - zeek
---

# Zeek `conn.log`

<div class="dfir-meta" markdown>
**Category:** Network · **Source:** Zeek · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    One row per connection (TCP, UDP, ICMP) with who/what/when/how-much and a compact record of how the TCP handshake went — the log you aggregate first, and the `uid` hub every other Zeek log hangs off.

## Fields

| Field | Type | Meaning | Analyst notes |
|---|---|---|---|
| `ts` | time | Time of the **first packet** | UTC epoch. Convert with `zeek-cut -d` |
| `uid` | string | Unique connection ID | Join key to every other log |
| `id.orig_h` / `id.orig_p` | addr / port | **Originator** (client) IP / port | Originator = who sent the first packet |
| `id.resp_h` / `id.resp_p` | addr / port | **Responder** (server) IP / port | Sort/count by this to find C2 |
| `proto` | enum | `tcp`, `udp`, `icmp` | |
| `service` | string | Protocol Zeek **detected** by content (`http`, `ssl`, `dns`, `smb`, `ssh`, `rdp`, `krb_tcp`, `ntlm`, `dce_rpc`…) | `-` = unknown/undetected. Multiple: `ssl,http`. **Mismatch with port = interesting** |
| `duration` | interval | Seconds from first to last packet | Very long + low bytes = interactive/keep-alive |
| `orig_bytes` / `resp_bytes` | count | **Payload** bytes from originator / responder (TCP: from sequence numbers, so retransmits don't inflate) | Asymmetry tells the direction of data flow |
| `conn_state` | string | Connection outcome summary (table below) | Scans: `S0`, `REJ`; normal: `SF` |
| `local_orig` / `local_resp` | bool | Is orig/resp in `Site::local_nets`? | Only set if you configured local nets |
| `missed_bytes` | count | Bytes lost due to packet drops | High = capture problems, distrust byte counts |
| `history` | string | Per-packet flag history (below) | Reads like a story of the handshake |
| `orig_pkts` / `orig_ip_bytes` | count | Packets / IP-level bytes from originator (includes headers) | Compare to `orig_bytes` |
| `resp_pkts` / `resp_ip_bytes` | count | Same for responder | |
| `tunnel_parents` | set | `uid`s of encapsulating tunnels (GRE, Teredo, VXLAN, AYIYA) | Non-empty = tunnelled traffic |
| `community_id` (if loaded) | string | Hash of the 5-tuple shared with Suricata/Arkime/Elastic | Pivot between tools |
| `orig_l2_addr` / `resp_l2_addr` (optional policy) | string | MAC addresses | Ties IP → device on local segment |
| `vlan`, `inner_vlan` (optional) | int | 802.1Q tags | |

### `conn_state` values

| State | Meaning | What it usually is |
|---|---|---|
| `S0` | SYN seen, no reply | **Port scan**, firewall drop, dead host |
| `S1` | Handshake done, not terminated | Still open at end of capture / long session |
| `SF` | Normal establish & teardown | Regular connection (**"Success Finished"**) |
| `REJ` | SYN → RST | Closed port (**scan hit a closed port**) |
| `S2` | Established, orig sent FIN, no FIN from resp | |
| `S3` | Established, resp sent FIN, no FIN from orig | |
| `RSTO` | Established, **originator** aborted with RST | Client killed it |
| `RSTR` | Established, **responder** aborted with RST | Server killed it (IDS/firewall reset, service crashed) |
| `RSTOS0` | Orig sent SYN then RST; no SYN-ACK from resp | Scanner sending RST after no reply |
| `RSTRH` | Resp sent SYN-ACK then RST; no SYN from orig seen | Asymmetric capture |
| `SH` | Orig SYN then FIN, no SYN-ACK | "Half-open" — often scans/evasion |
| `SHR` | Resp SYN-ACK then FIN, no SYN from orig | Asymmetric capture |
| `OTH` | No SYN seen, mid-stream | Capture started mid-connection, or UDP/ICMP |

### `history` letters

Uppercase = **originator**, lowercase = **responder**. Order = order seen (repeats are collapsed on later versions with `^` marking direction flips).

| Letter | Meaning |
|---|---|
| `S` / `s` | SYN (no ACK) |
| `H` / `h` | SYN-ACK ("handshake") |
| `A` / `a` | Pure ACK |
| `D` / `d` | Packet with **payload** ("data") |
| `F` / `f` | FIN |
| `R` / `r` | RST |
| `C` / `c` | Bad checksum |
| `G` / `g` | Content gap |
| `T` / `t` | Retransmission |
| `W` / `w` | Zero window |
| `I` / `i` | Inconsistent packet (SYN+RST) |
| `Q` / `q` | Multi-flag packet (SYN+FIN) |
| `^` | Direction flipped (Zeek guessed orig/resp wrongly and fixed it) |

Examples: `ShADadFf` = perfect normal connection. `S` = single SYN, nothing back (scan / dropped). `Sr` = SYN, RST back (closed port). `ShAD` then nothing = client sent data, got nothing, capture ended or hung. `ShADadR` = normal until server reset. `^d` = only saw responder data, mid-stream.

## Quick queries

=== "zeek-cut / shell"

    ```bash
    # Top talkers by destination (who is everyone connecting to?)
    zeek-cut id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn | head -20

    # Outbound connections from one host, readable time, longest first
    zeek-cut -d ts id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes conn_state < conn.log \
      | awk '$2=="10.0.0.25"' | sort -k6 -rn | head

    # Port scan detection: many S0/REJ from one source to many ports
    zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log \
      | awk '$4=="S0"||$4=="REJ"' | awk '{print $1, $2}' | sort | uniq -c | sort -rn | head

    # Services that don't match their port (443 that isn't ssl, 53 that isn't dns, 80 that isn't http)
    zeek-cut id.resp_p service < conn.log | awk '($1==443 && $2!="ssl" && $2!="-") || ($1==53 && $2!="dns") || ($1==80 && $2!="http")' | sort | uniq -c | sort -rn

    # Total bytes uploaded per internal host to external hosts (exfil hunt)
    zeek-cut id.orig_h id.resp_h orig_bytes < conn.log | awk '$1 ~ /^10\./ && $2 !~ /^10\./ {s[$1" -> "$2]+=$3} END {for (k in s) print s[k], k}' | sort -rn | head

    # Long-lived connections (> 1 hour)
    zeek-cut -d ts uid id.orig_h id.resp_h id.resp_p duration < conn.log | awk '$6>3600' | sort -k6 -rn
    ```

=== "Splunk (Zeek JSON, sourcetype bro:conn:json or zeek:conn)"

    ```spl
    index=zeek sourcetype=zeek:conn
    | stats count sum(orig_bytes) as up sum(resp_bytes) as down avg(duration) as avg_dur by id.orig_h, id.resp_h, id.resp_p, service
    | eval up_MB=round(up/1024/1024,1), down_MB=round(down/1024/1024,1)
    | sort - up_MB
    ```

    `stats … by` groups rows by the fields after `by` and computes one summary row per group; `sum(orig_bytes) as up` adds up the upload bytes and names the result `up`. `eval` creates new fields from a formula (here converting bytes to MB and rounding to 1 decimal). `sort - up_MB` puts the biggest uploader on top.

    ```spl
    index=zeek sourcetype=zeek:conn conn_state IN (S0, REJ)
    | stats dc(id.resp_p) as ports dc(id.resp_h) as hosts by id.orig_h
    | where ports > 50 OR hosts > 50
    ```

    `IN (…)` matches any listed value. `dc()` = distinct count — how many *different* ports/hosts one source touched; `where` keeps only rows over the threshold. This is a port-scan (`ports`) and host-sweep (`hosts`) detector.

## Analysis tips

!!! tip "Pivot pattern"
    Aggregate in `conn.log` → find the odd pair (`id.orig_h`, `id.resp_h`, `id.resp_p`) → grab its `uid`s → `grep <uid> *.log` → read the protocol detail. `grep CHhAvVGS1DHFjwGM9 http.log ssl.log dns.log files.log`.

- **Byte counts are payload only.** A 0-byte `SF` connection is a handshake with no data — TCP probe, health check, or a beacon that got nothing to do.
- **`orig_bytes` vs `orig_ip_bytes`**: if `orig_bytes` is 0 but `orig_ip_bytes` is large, the payload was in retransmits or Zeek couldn't reassemble (`missed_bytes`) — capture quality issue.
- **UDP "connections"** are flows grouped by 5-tuple with an inactivity timeout; `duration` can span many datagrams. DNS to the same resolver may show as one long UDP conn.
- **ICMP**: `id.orig_p` = ICMP type, `id.resp_p` = code. A lot of type 8/0 with large `orig_bytes` = ICMP tunnel.
- **Local vs. external**: set `Site::local_nets` in `local.zeek` so `local_orig/local_resp` populate — then "internal → external with big `orig_bytes`" is a one-liner.
- **Beaconing** lives here: same `id.orig_h`/`id.resp_h`/`id.resp_p`, near-constant interval between `ts` values, similar `orig_bytes`. See [Beaconing & C2](../beaconing-c2.md).
- **Lateral movement** looks like internal → internal `445` (`smb`), `135` + high port (`dce_rpc`), `3389` (`rdp`), `5985` (`http` on that port = WinRM), `22`. Count internal-to-internal pairs that never occurred before the incident window.
- **Zeek may flip orig/resp** when it starts mid-stream (`^` in history, `OTH` state) — sanity check port numbers when the "server" is on port 51234.

## Correlation

| Question | Then look at |
|---|---|
| What was actually said? | `uid` → [`http.log`](http-log.md), [`ssl.log`](ssl-x509.md), [`dns.log`](dns-log.md), `smb_*.log`, `ssh.log`, `rdp.log` |
| Which file went over it? | `uid` → [`files.log`](files-log.md) (`conn_uids`) → `fuid` → `pe.log`, `extract_files/` |
| Which process on the host made it? | Sysmon `3` (`SourceIp/SourcePort/DestinationIp` + time), Windows `5156`, [SRUM](../../windows/srum.md) hourly bytes per app |
| Which user? | `ntlm.log` / `kerberos.log` (`username`, `client`), Windows `4624` on the destination |
| Was it alerted on? | `notice.log`, Suricata `eve.json` (`community_id` / 5-tuple + time) |
| Packets | [`tshark -r cap.pcap -Y "ip.addr==A && tcp.port==P"`](../wireshark-tshark.md) |

## References

- [Zeek docs — conn.log](https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html)
- [Corelight conn.log cheat sheet](https://corelight.com/resources/zeek-cheatsheets)
- [Community ID spec](https://github.com/corelight/community-id-spec)
