---
title: "1.12 — Challenges and Opportunities in Network Investigations"
tags:
  - training
  - network-forensics
  - nat
  - encryption
  - tunneling
---

# 1.12 — Challenges and Opportunities in Network Investigations { #challenges-and-opportunities }

!!! abstract "Scope of this lesson"
    - Change is inevitable: a network diagram starts going stale the moment it's drawn
    - **NAT**: mapping one "address and port" reported from outside back to an inside PC (a correlation done by hand)
    - **Encryption**: [Changed] TLS you can decrypt with the server's private key has become rare (tested directly: only TLS 1.2 RSA decrypted)
    - **Tunnels**: BPF can't see traffic inside GRE and 6in4 (tested directly), DoH, and [Changed] ECH (RFC 9849)
    - **VPNs, WAN optimisation, wireless, cloud**: the challenges and opportunities of each
    - Traffic volumes grow, and malware still depends on the network

!!! note "Lab environment and notation"
    **(Actual output)** comes from this environment's tshark 4.2.2, tcpdump 4.99.4 and OpenSSL 3.0.13. The TLS experiment captured real connections made on loopback with `openssl s_server` and `s_client`, using a self-signed certificate I created (`files.lab.example`). The pcaps for the NAT and tunnel experiments were assembled in Python (private and documentation addresses only). Assembled pcaps are **for showing the principle**, and may differ in detail from traffic produced by real equipment.

## 1. Change: inevitable, and usually hard { #change }

**(Hypothetical)** In an incident response meeting, the network engineer puts up the diagram. "The lab is behind this firewall, and all web traffic goes to the proxy." But when you actually capture packets, some traffic is leaving by a completely different path because of a device installed three months ago. It isn't on the diagram.

Network investigation is a field of constant change. Every new technology, every new design approach (sometimes just a buzzword) brings something to add to analysis toolkits and response plans. Nobody wants to tell the executives that "a device installed a few months ago made the whole response procedure useless". If the security team is involved **from the moment** a new technology is adopted, though, you can make use of the opportunities it brings.

This isn't only about new technology. Most organisations have detailed diagrams and operating documents, but **they're never 100% accurate**; they start going stale as soon as they're written. In the end, success depends less on pressing a fixed sequence of buttons than on **adapting to the unexpected and seizing unexpected opportunities**.

This lesson goes through the structures that most often trouble investigators, and for each one sums up **the challenge** it brings and, at the same time, **the opportunity**.

## 2. NAT: who on the inside is that one outside address? { #nat }

### 2.1 What NAT is { #nat-what }

When RFC 760 (later superseded by RFC 791) set IP addresses at 32 bits in 1980, hardly anyone imagined more than four billion devices on the Internet. Today IPv4 exhaustion is real, and one response is **NAT** (Network Address Translation). A NAT device maps one or more **inside** addresses to one or more **outside** addresses, remembers the mapping per connection, and rewrites the addresses on returning packets. Each end sees only addresses consistent with its own place on the network.

NAT is commonly used between private ranges (RFC 1918) and public addresses, but also **between private and private, or public and public**. A typical case is after one company acquires another and the two networks' addresses overlap. NAT is often inserted as a workaround instead of proper network integration.

**What matters to the investigator is the observation point.** The same connection appears as `10.10.6.14:51000` inside the NAT and `203.0.113.5:61022` outside. Depending on which side a pcap was captured or a log was written, the "source" differs.

### 2.2 Opportunity: devices that record both, and correlation { #nat-correlation }

Some enterprise devices record NAT translations. Many flow deployments store **both the pre- and post-translation addresses** for each connection (the nfdump 1.7.3 used in lesson 1.11's lab also showed translated-address columns such as `X-Src IP Addr` the first time it printed in its default format; they were empty as `0.0.0.0` because softflowd doesn't do NAT). Then, when an outside party reports "your public address talked to a known C2 server", finding the connection in the flows gives you the inside address immediately.

Without such records, all is not lost. You can **correlate several pieces of evidence**; it just takes longer. I tried it.

**(Hypothetical)** The outside party's notification: "Around 2026-11-02 09:02:00 UTC, there was a connection from your `203.0.113.5`, source port **61022**, to `198.51.100.66:443`." We have `inside.pcap` captured inside the NAT and `outside.pcap` captured outside.

**① Inside, find every connection start (SYN) to that destination at that time**

```bash
tshark -n -r inside.pcap -Y 'ip.dst == 198.51.100.66 && tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields -e frame.time_utc -e ip.src -e tcp.srcport -e tcp.seq_raw
```

**(Actual output)**

```text
Nov  2, 2026 09:02:00.200000000 UTC	10.10.7.11	50110	3492838502
Nov  2, 2026 09:02:00.900000000 UTC	10.10.6.14	51000	3340291515
Nov  2, 2026 09:02:01.300000000 UTC	10.10.7.15	49822	1388325221
Nov  2, 2026 09:02:01.600000000 UTC	10.10.6.11	53001	3794726010
Nov  2, 2026 09:02:02.400000000 UTC	10.10.6.14	51001	1337529987
```

Five connections to the same C2 within three seconds, from four PCs. "Around 09:02:00" alone can't pick one, and the outside party's clock may be a few seconds off. The inside port was changed by NAT, so you can't search for 61022 either.

**② Outside, find the connection on the reported port and look at its TCP sequence number**

```bash
tshark -n -r outside.pcap -Y 'tcp.srcport == 61022 && tcp.flags.syn == 1 && tcp.flags.ack == 0' \
  -T fields -e frame.time_utc -e ip.src -e tcp.srcport -e tcp.seq_raw
```

**(Actual output)**

```text
Nov  2, 2026 09:02:00.900000000 UTC	203.0.113.5	61022	3340291515
```

`tcp.seq_raw` is the sequence number **actually written in the packet**, not the relative number Wireshark renumbers from 0 for readability. Ordinary NAT changes addresses and ports and leaves this value alone.

**③ Search for that sequence number inside**

```bash
tshark -n -r inside.pcap -Y 'tcp.seq_raw == 3340291515' -T fields -e ip.src -e tcp.srcport
```

**(Actual output)** `10.10.6.14	51000`. The time (09:02:00.9) matches exactly too. When **time, destination and sequence number** all line up, that's fairly strong support.

!!! warning "[Caution] When this method fails"
    - **Devices that rewrite sequence numbers:** some firewalls randomise the TCP initial sequence number for security (e.g. Cisco ASA's sequence number randomisation). Step ③ then fails, and you must match on other characteristics such as time, packet sizes and connection duration.
    - **No outside capture:** the **time and source port** in the notification alone can be matched against the NAT device's translation log. If even that is missing, narrow the candidates as in step ① and choose with other evidence.
    - **Proxy logs:** if the C2 used HTTP or HTTPS, the proxy logs (lesson 1.3) contain **the inside address, host name and URL**. If the connection seen from outside belongs to the proxy, the proxy log points directly to the inside PC.
    - The two pcaps in this lab were assembled to show the principle and assume a NAT that leaves sequence numbers unchanged.

## 3. Encryption: the biggest wall, and what remains { #encryption }

### 3.1 The challenge { #encryption-challenge }

The biggest wall in network investigation is encryption. There's no easy way to "crack" strong, properly deployed encryption, and plaintext services are disappearing fast. If your analytic methods are built on **being able to see the content**, their effectiveness drops immediately.

Still, encryption ultimately rests on **trust**, and trust is complicated. In enterprise environments, the TLS interception from lesson 1.2 (the proxy re-issues certificates from the organisation's CA) lets you inspect and capture most TLS in plaintext.

### 3.2 [Changed] "Capture now, decrypt later with the key" rarely works any more { #decrypt-later }

The source material explains, from a law enforcement perspective, that "if you might acquire the private key later (e.g. by a search warrant), capturing the encrypted traffic now is useful, and with the key, tools like Wireshark can decrypt it". I tested how true this is for today's TLS.

With the same server certificate and private key, I made three kinds of connection and sent a `GET /secret-report.txt` request in each. Then I gave tshark ① no key, ② **the server's private key**, and ③ **a key log** of session secrets written by the client, and checked whether the request path became visible.

```bash
# ② decrypt with the server private key
tshark -n -r t13.pcap -d tcp.port==8444,tls -o 'uat:rsa_keys:"srv.key",""' -Y http.request -T fields -e http.request.uri
# ③ decrypt with the key log
tshark -n -r t13.pcap -d tcp.port==8444,tls -o 'tls.keylog_file:t13.keys' -Y http.request -T fields -e http.request.uri
```

- `-d tcp.port==8444,tls`: "Decode As": dissect this port as TLS (lesson 1.9).
- `-o 'uat:rsa_keys:...'`: puts the server's private key file in Wireshark's RSA keys list.
- `-o 'tls.keylog_file:...'`: points to the file recording the keys created for each session. Browsers, `curl` and OpenSSL can write this file via the `SSLKEYLOGFILE` environment variable or the `-keylogfile` option.

**(Actual output)**

| Connection | Key exchange | No key | Server private key | Key log |
| --- | --- | --- | --- | --- |
| TLS 1.2, `AES128-GCM-SHA256` | RSA | not visible | **visible** | visible |
| TLS 1.2, `ECDHE-RSA-AES128-GCM-SHA256` | ECDHE | not visible | not visible | visible |
| TLS 1.3, `TLS_AES_256_GCM_SHA384` | (EC)DHE | not visible | not visible | visible |

**Why the difference?** In RSA key exchange, the client sends the material for the session key **encrypted with the server's public key**. So with the server's private key you can recover that material, even later, and rebuild the session key. (EC)DHE key exchange such as ECDHE builds the session key from temporary keys that both sides **use for that connection only and then discard**. The server's private key is used only to sign "this server is genuine", not to build the session key. So obtaining the private key later doesn't decrypt past connections. This property is called **forward secrecy**.

And **TLS 1.3** (RFC 8446) removed RSA key exchange altogether; every key exchange is designed to provide forward secrecy. Most TLS connections today are TLS 1.3 or TLS 1.2 with ECDHE, so assume that **seizing the server's private key will almost never decrypt traffic you've already captured**.

So what does work?

- **Key logs.** All three connections in the table decrypted. That's possible if you prepared endpoints or proxies to write key logs in advance. But obtaining such a log after the fact for an attacker's connections is hard.
- **Devices that are one end of the connection.** TLS-intercepting proxies and decryption appliances can see or record plaintext (lessons 1.2 and 1.11).
- So a "capture now, decrypt later" plan is only possible after checking **which key exchange the connections use**. You can see it in the pcap from the Server Hello's `tls.handshake.ciphersuite`: in the experiment above, `0x009c` (RSA), `0xc02f` (ECDHE) and `0x1302` (TLS 1.3).

!!! info "[Supplement] SSH and other protocols"
    The source material notes that decrypted SSHv2 content isn't accessible at this time. SSHv2's key exchange is also Diffie-Hellman based, so after-the-fact decryption is effectively hard for the same reason. There is research and tooling for extracting keys from endpoints, but that belongs to endpoint forensics.

### 3.3 Opportunity: flow analysis works the same on encrypted traffic { #flow-analysis }

If you can't see the content, do **analysis that doesn't need content**: **flow analysis**. Addresses and ports, and also **packet sizes and timing**, are enough to generate leads and build hypotheses, just as lesson 1.11 found five-minute-interval connections of identical size (717 bytes) and a 20 MB upload without any content. And even with TLS 1.3, the Client Hello is still mostly plaintext, so unless ECH is used, **the server name being contacted (SNI)** is visible (lesson 1.2).

## 4. Tunnels: traffic inside traffic { #tunnels }

### 4.1 What a tunnel is { #tunnel-what }

In a tunnel, one stream of traffic becomes **the payload** of another. Some protocols are designed for tunnelling, such as **GRE** (IP protocol 47); others, such as HTTP, DNS and ICMP, are **repurposed** as tunnels. There's also **6in4** (IP protocol 41), joining two IPv6 enclaves across an IPv4 network, **SOCKS**, somewhere between a proxy and a tunnel, and SSH tunnels.

**The challenge:** many tools aren't tunnel-aware, and there are so many tunnel types that detecting, let alone managing, them is hard. Investigators must first **notice that a tunnel exists** and decide **how to strip it** before content analysis can begin.

### 4.2 Tested: BPF can't see inside a tunnel { #tunnel-test }

I built a pcap containing the same HTTP request in three shapes: ① plain TCP 80 over IPv4, ② IPv4 TCP 80 inside GRE, ③ IPv6 TCP 80 inside 6in4.

**(Actual output)**

| Filter | Tool | Matching packets |
| --- | --- | --- |
| `tcp port 80` | tcpdump (BPF) | **1** |
| `ip proto 47` | tcpdump (BPF) | 1 (the GRE packet) |
| `ip proto 41` | tcpdump (BPF) | 1 (the 6in4 packet) |
| `host 10.20.1.5` (inner GRE address) | tcpdump (BPF) | **0** |
| `tcp.port == 80` | tshark (display filter) | **3** |
| `ip.addr == 10.20.1.5` | tshark (display filter) | 1 |
| `http.request` | tshark (display filter) | 3 |

BPF's `tcp port 80` looks only at **the outer header** (lesson 1.7). The GRE packet's outside is "IP protocol 47" and the 6in4 packet's outside is "IP protocol 41", so neither looks like TCP. Had `tcp port 80` been the capture filter, **the web traffic inside the tunnels wouldn't even have been saved**. Wireshark's dissectors, on the other hand, strip tunnels and dissect what's inside, so the display filter found all three.

One more thing: printing `ip.src` for the GRE packet gave **two values**, `192.0.2.1,10.20.1.5` **(actual output)**, because both the outer and inner IP headers are present. The "multi-value fields" of lesson 1.9 appear in tunnels even for an ordinary field like `ip.src`. A filter like `ip.src != 10.20.1.5` may behave unexpectedly on such packets.

**The opportunity:** for **engineered tunnels** such as GRE or 6in4, the points of encapsulation and decapsulation are fixed. Identify them and place the capture platform **after decapsulation**, and you receive traffic in its original shape without messy preprocessing.

### 4.3 Everything over HTTPS: DoH and ECH { #doh-ech }

There's a strong recent trend towards repurposing HTTPS for all sorts of new uses. Visibility into network behaviour falls, and the importance of intercepting encrypted communication rises.

- **DoH** (DNS over HTTPS, RFC 8484) puts DNS queries inside HTTPS. From outside it's an ordinary web connection on 443, so the premise from lesson 1.11, "force every endpoint to use the internal DNS servers and you see all DNS in one place", breaks down. There's also **DoT** (DNS over TLS, RFC 7858, usually port 853) and **DoQ** (DNS over QUIC, RFC 9250) for the same purpose. DoT uses a dedicated port, so it's easy to block or spot; DoH blends in with normal web traffic. Organisations therefore usually disable DoH or allow only an internal DoH server through endpoint and browser policy, and check proxies and firewalls for connections to known public DoH servers.
- **[Changed] ECH** (Encrypted Client Hello) encrypts even the server name in the Client Hello. When lesson 1.2 was written it was treated mainly as a technology trend, but it was **published as RFC 9849 in March 2026**. As ECH spreads, the "server name from SNI" mentioned in section 3.3 also disappears from packet sensors. That's why **records kept at one end of the connection**, such as an explicit proxy's `CONNECT` log, matter even more.

## 5. VPNs: an opportunity, if placement is right { #vpn }

A VPN is a special case of tunnelling, used in nearly every network. Remote users send all their traffic into the corporate network inside an **encrypted tunnel**.

**The challenge:** place the capture platform **outside the VPN endpoint** and you see only the encrypted tunnel. That shows who connected, when and how much, so it isn't useless, but most investigations need the traffic after decryption, flowing "natively" inside the network. So understand the VPN architecture fully before choosing a capture location.

**The opportunity:** clear that small hurdle, and a VPN lets you watch and capture most of your scattered remote users' traffic **in one place**. Cross-check with the **VPN authentication logs**, and it becomes easy to tie traffic of interest to a source device, a user account, and sometimes a location.

!!! info "[Supplement] Not all traffic may go through the VPN"
    Modern VPNs commonly use **split tunnelling**: only corporate destinations go through the tunnel, and other Internet traffic goes straight out over the user's own connection. In that case remote users' web activity **won't appear** in the corporate proxy or in capture behind the VPN. Check first whether the VPN is full tunnel or split tunnel.

## 6. WAN optimisation: flows that don't match the diagram { #wan-optimization }

Devices that improve network speed and efficiency also change the flow. The most common is the web proxy: identical content is fetched from the remote server **once** and served to many inside users over the fast LAN (the cache in lessons 1.2 and 1.5). Extending that idea beyond HTTP gives **WAN optimisation appliances**. The source material cites commercial products such as Riverbed SteelHead and F5 BIG-IP, which act transparently like proxies for email, web applications, file sharing, video and more.

**The challenge:** the client thinks it connected to the remote server, but the optimiser in the middle may answer **from its own cache**. The remote server (and every segment outside the optimiser) may not even know the request happened, or who made it. From outside, every connection appears to come from the optimiser. In short, **the actual flows differ from what the diagram leads you to expect**. "Not in the outside pcap" doesn't mean no request was made inside.

**The opportunity:** these devices generally **log very well**, which is valuable for correlating activity seen on either side of the optimiser. And since they usually sit at the edge of large networks, that position itself may be **a good place** for capture or monitoring.

## 7. Wireless: it doesn't stop at the wall { #wireless }

Wireless is now a major part of networks. Not long ago many enterprises refused to deploy it, but user demand, mobile devices, security-conscious deployment options and convenience made it spread fast.

**The challenges:**

- **The network is everywhere.** A wireless network's reach depends not only on the infrastructure but also on **the client's equipment**. Transmit power is regulated, but people with bad intent aren't guaranteed to comply, and large or highly directional **receive** antennas often aren't regulated. So even physically "controlled" wireless networks reach well beyond their designed area. As the source slide's picture shows, the perceived coverage (inside the office) and the actual coverage differ.
- **Legal requirements change a lot.** Laws on capturing wireless signals vary by jurisdiction and are often stricter than for wired networks. Always get **legal advice** first. The source material cites, as a warning, the case of a mapping service's street-imagery vehicles collecting wireless data, which caused major trouble.

**The opportunities:**

- **One big shared medium.** Unlike wired networks, where switches separate traffic per port, radio is shared by every device on that channel, so the capture constraints of lesson 1.11's mirror ports don't apply.
- **Location can be estimated.** Commercial and free tools use signal strength and known location data (GPS, or points on a map) to find the approximate physical location of a device of interest.
- **Good logs.** Large wireless deployments usually have controllers that record associations, authentication and roaming well.

!!! warning "[Caution] What's different in today's wireless networks"
    - **A shared medium, but the content is encrypted.** Even capturing frames in monitor mode (lesson 1.11, section 3.1), data frames encrypted with WPA2 or WPA3 can't be read without keys. WPA2-Personal can be decrypted if you have the passphrase and also capture the 4-way handshake at connection start, but WPA3-Personal (SAE) is designed so that knowing the password doesn't let you passively decrypt traffic already captured. So controller logs and capture on the wired side have become more important in wireless investigations too.
    - **MAC addresses change.** Today's phone and laptop operating systems use **randomised MAC addresses** by default, per network (or periodically). Lesson 1.11 called DHCP logs "the key for mapping an IP back to a device", but with random MACs that key may not point to a single device. Look at it together with the wireless controller's **user authentication records** (802.1X accounts and so on).

## 8. The cloud: activity beyond the perimeter { #cloud }

"Cloud" became a buzzword quickly, but the shift back to centralised, remote computing is real: hosted applications, remote storage, elastic compute. The enterprise no longer ends at its traditional perimeter, and since these services' core functions depend on network connectivity, investigations must cover them.

**The challenges:**

- **Lack of visibility and control.** For example: "How many failed logins came before the successful one that exported the whole customer database? From which IPs?" Depending on the service, that record may not exist at all, and if it does, the provider may not hand it over **without legal process**.
- **New and changing fast.** Each service can be completely different, so be ready to "start from zero" when a new service comes into scope. The Azure NSG flow log retirement seen in lesson 1.11 is a good example.

**The opportunity:** most cloud services expose data and functions through **structured HTTP requests: APIs**. HTTP(S) can be proxied, so requests and responses can be intercepted and logged, and since providers publish their API documentation, you can use it to **interpret, or reconstruct as a transcript**, what happened in the service.

!!! info "[Supplement] Check the cloud-side records first"
    Major cloud and SaaS providers today offer **audit logs** recording administrative actions and logins. But what's on by default, how long it's kept, and which items are recorded at which subscription tier varies by service and changes often. For any incident involving the cloud, check **whether that service's audit logs were enabled and how long they're kept** first, alongside the network evidence.

## 9. Trend 1: everything over the network { #everything-over-network }

The once underused office LAN is now a high-speed switched fabric divided into VLANs, and it still never seems fast enough. Voice (VoIP), storage (SAN, iSCSI), backups, remote synchronisation, video and security cameras have all moved onto the network.

**The challenge:** new data brings new analytic challenges, and **the volume is enormous**. Links of tens of Gbps carrying several GB per second are common, so separating out the relevant data takes a lot of work. That's why this course spends so much time on flow analysis and data reduction: use flows to **characterise** large volumes of traffic quickly and find the **time windows** worth a deep look, then use data reduction (tcpdump and BPF from lesson 1.10, section 8) to pull out just that window's traffic and dig in.

**The opportunity:** as the source material jokes, more work means job security.

## 10. Trend 2: malware depends on the network { #malware-needs-network }

Malware's basic nature is to **take commands** from its master and **return** something. Spy films aside, malware almost always communicates over the network. There are clever ways to "hide" from host-based detection tools, but the network path involves many devices and fairly strict protocols, so hiding there is much harder. That's why **finding and analysing malware from the network is sometimes faster and more fruitful** than starting from the host and working up.

Attackers use encryption, obfuscation and more to make discovery and analysis harder, but the data is **on the wire** and can be found in a properly instrumented environment. This work is always an arms race: when we gain a new capability, attackers find a way around it, and round it goes.

Right now, the network is malware's **weakness**: malware relies on the network for its core functions, but can't control or manipulate the network extensively. We should seize on that weakness while it lasts.

!!! info "[Supplement] Today's C2 tries to look ordinary"
    Recent malware often uses **legitimate services everyone uses** (cloud storage, collaboration tools, well-known CDNs) as its command channel instead of unfamiliar attacker-owned servers. Destination addresses or names alone make it hard to tell apart from normal traffic. That makes the **size and timing patterns** this course keeps stressing (the 900-second interval in lesson 1.10, the repeated identical sizes in lesson 1.11) and **deviation from normal**, such as "does that PC normally use that service?", even more important.

## 11. How to use this in real investigations { #in-practice }

1. **Trust the diagram, but verify.** Check it against the actual paths in captured traffic (which device's address appears as the source, what tunnels exist).
2. **At every NAT boundary, note "which side's address is this?"** When you get an outside notification, always obtain the time, public address and **source port**, then correlate in the order: translation logs, captures on both sides, proxy logs.
3. **For encrypted traffic, look at the key exchange first.** Judge whether after-the-fact decryption is possible from the Server Hello's cipher suite; if not, turn to flow analysis and records from devices at the connection's ends.
4. **Make capture filters tunnel-aware.** BPF like `tcp port 80` can't see inside tunnels. On segments with tunnels, keep capture filters generous, or capture after decapsulation.
5. **State the scope of "nothing".** Check for paths that bypass your observation (DoH, split tunnels, WAN optimisation, QUIC) and qualify conclusions with "from this observation point".

## 12. Summary { #summary }

- Networks keep changing and diagrams are always out of date. **Adapting and seizing opportunities** decides the outcome more than fixed procedures.
- **NAT** makes the source depend on the observation point. Flows or translation logs recording both sides are easiest; otherwise you can match on **time, port and TCP sequence number** (done by hand here; fails on devices that rewrite sequence numbers).
- **[Changed]** The only TLS the server's private key decrypted was TLS 1.2 with RSA key exchange. ECDHE and TLS 1.3 needed **a key log** (tested directly). "Capture now, decrypt later with the key" rarely works now.
- When content can't be seen, **flow analysis** (addresses, ports, sizes, timing) works regardless of encryption.
- BPF can't see traffic inside **tunnels** (`tcp port 80` caught 1 of 3). Display filters see inside, but fields like `ip.src` become multi-valued.
- **DoH** undermines visibility centred on internal DNS servers, and **[Changed] ECH**, published as RFC 9849 (March 2026), hides even SNI. Records from devices at the connection's ends matter more.
- With the right capture placement, a **VPN** lets you see remote users' traffic in one place, and authentication logs tie it to people. Watch out for split tunnelling.
- **WAN optimisers** change flows but offer good logs and good capture positions.
- **Wireless** doesn't stop at the wall and has heavy legal constraints, but offers a shared medium, location estimation and controller logs. Today, factor in encryption and random MACs too.
- **The cloud** lacks visibility and changes fast, but APIs and audit logs are opportunities.
- Traffic keeps growing, and malware still depends on the network. Exploiting that weakness is the job of this field.

## Review questions { #review }

**Question 1. (Application)** An outside party reports only "around 2026-11-02 09:02:02 UTC there was a connection from your `203.0.113.5` to `198.51.100.66:443`". No port number. Can you tell which PC it was from the `inside.pcap` results in section 2.2 alone? What would you ask for?

??? success "Answer and explanation"
    No. Between 09:02:00 and 09:02:03 there were five connections to the same destination from four PCs, and around 09:02:02 both `10.10.6.11` (09:02:01.6) and `10.10.6.14` (09:02:02.4) are candidates. The outside party's clock may be a few seconds off too. Ask the outside party for **the source port**, and if possible **the exact time (milliseconds) and packet sizes or byte counts**; on your side, look for the NAT device's translation logs, outside captures or flows, and proxy logs. Until then, the report says "two candidates".

**Question 2. (Changed conditions)** In the situation of section 2.2, if the NAT firewall had TCP initial sequence number randomisation enabled, what happens to steps ②–③, and what could you match on instead?

??? success "Answer and explanation"
    The outside SYN's sequence number differs from the inside one, so the `tcp.seq_raw` search in step ③ finds nothing. Don't read "not found" as "not inside". Instead, match on ① time (down to milliseconds, if both capture boxes' clocks are right), ② the size of the first data packet and the sequence of subsequent packet sizes, ③ connection duration and bytes exchanged, and ④ the NAT device's translation logs. In this lab, four of the five candidates had the same size (517 bytes), so one size alone isn't enough; use several characteristics together. Whether both capture boxes' clocks are synchronised by NTP is decisive (lesson 1.11, section 10.2).

**Question 3. (Common misconception)** "We've secured the incident server's TLS private key, so we can decrypt all of that server's HTTPS traffic we captured last month." What condition must hold for this to be true?

??? success "Answer and explanation"
    Those connections must be **TLS 1.2 or earlier using RSA key exchange**. In section 3.2's experiment, only the `AES128-GCM-SHA256` (RSA key exchange) connection decrypted with the server's private key; `ECDHE-RSA-...` and TLS 1.3 did not. Those build session keys from per-connection temporary keys (forward secrecy), so the server's private key isn't used in computing them. Most servers today use TLS 1.3 or ECDHE, so first check the cipher suite in the Server Hello in the pcap. The alternatives are key logs, or records from the proxy or load balancer that terminates TLS.

**Question 4. (Interpretation)** After seeing section 4.2's experiment, a colleague says, "Then it's better never to use capture filters at all." How would you respond?

??? success "Answer and explanation"
    The direction is right, but the conclusion goes too far. The experiment showed that **BPF conditions that look only at the outer header** (`tcp port 80`, the inner address) miss what's inside tunnels. Capture filters are still often needed for storage and throughput reasons (lessons 1.7 and 1.11). The realistic answer is: ① first find out what tunnels exist on that segment; ② set filters **generously** so tunnel protocols (`ip proto 47`, `ip proto 41`, etc.) aren't excluded; ③ where possible, capture after decapsulation; ④ record the capture filter used in the capture notes.

**Question 5. (Changed conditions)** Lesson 1.11 said "force every endpoint to use only the internal DNS servers and you can see DNS in one place". Give three cases where this premise breaks, and how you'd check each.

??? success "Answer and explanation"
    ① **DoH**: a browser or malware puts DNS inside HTTPS and sends it to a public DoH server. Check proxy logs or firewalls for port 443 connections to known DoH servers, and the browser and endpoint policy settings. ② **DoT**: goes directly to an external DNS server on port 853. Look for outbound port 853 connections at the firewall. ③ **Direct port 53 queries**: an endpoint asks an external DNS server on 53 directly instead of the internal one. Look in firewall or flow records for outbound port 53 from sources other than the internal DNS servers. Others include DoQ (QUIC) and queries that leave directly over the user's own connection through a VPN split tunnel. Qualify conclusions with "based on internal DNS logs".

**Question 6. (Calculation)** In section 2.2's `inside.pcap`, the five SYNs were at 09:02:00.2, 00.9, 01.3, 01.6 and 02.4. If the outside party's clock may differ from ours by up to ±1 second and the reported time is 09:02:00.0, how many candidates are there? How many after finding the outside sequence number by port?

??? success "Answer and explanation"
    09:02:00.0 ± 1 s is 09:01:59.0 to 09:02:01.0. The SYNs in that range are 00.2 (`10.10.7.11`) and 00.9 (`10.10.6.14`): **two**. Finding the SYN on port 61022 outside and searching the inside for sequence number `3340291515` reduced it to **one** (`10.10.6.14:51000`). The calculation shows that time only narrows candidates; a value unique to each connection (port, sequence number) is what pins down one.

**Question 7. (Application)** A remote worker's laptop appears to be infected. There's a tap at the perimeter outside the VPN appliance, and no capture inside it. The VPN uses split tunnelling. What do you secure, and where?

??? success "Answer and explanation"
    ① **VPN authentication logs**: when the user connected, from which public address, and which internal address they were given. ② **The outside tap**: the user's VPN tunnel is encrypted so the content isn't visible, but connection times and volumes are. ③ Traffic to and from that internal address **inside** the VPN appliance: internal server logs, firewalls, flows. If needed, place a temporary capture box behind the VPN (lesson 1.11's standby kit). ④ **With split tunnelling, Internet traffic may have gone straight out over the user's own connection**, so that part isn't in corporate records. Separately secure the endpoint's own records (browser, DNS cache, security product logs) or records from any cloud security service the endpoint uses.

**Question 8. (Interpretation)** At a branch office with a WAN optimiser, the head office file server's access log has no record of branch employee A opening a file. Yet the file was found on A's PC. What explanations are possible, and what should you check?

??? success "Answer and explanation"
    The most likely explanation is that the optimiser served the file **from its own cache**. If someone else had opened it first and it was cached, A's request may never have reached the head office server, and even if it did, the source would be recorded as the optimiser. So check ① **the optimiser's logs** (which client was served which object), ② capture or flows on the branch LAN (traffic between A's PC and the optimiser), and ③ head office server log entries recorded under the optimiser's address. Of course, keep other routes such as email or USB open as well.

**Question 9. (Common misconception)** "Wireless is one big shared medium, so one monitor-mode capture box lets you see all the communication content of everyone on that floor." Point out what's wrong.

??? success "Answer and explanation"
    ① Monitor mode sees **one channel at a time** (lesson 1.11, section 3.1). If the APs use several channels and bands (2.4/5/6 GHz), you see only part. ② Data frames are **encrypted with WPA2 or WPA3**. WPA2-Personal needs the passphrase plus the 4-way handshake, and WPA3-Personal (SAE) is designed so that knowing the password still doesn't allow passive decryption. ③ The capture box's wireless chip must support the standard and channel width the network uses. ④ Wireless capture carries heavy **legal constraints**, so get legal advice first. In practice, wireless controller logs and capture on the wired side behind the APs are the more realistic evidence sources.

## References { #references }

- Tools used in this environment: tshark 4.2.2, tcpdump 4.99.4, OpenSSL 3.0.13 (`s_server`, `s_client`, `-keylogfile`). Outputs were obtained on 2026-11-05.
- IETF, [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446), section 1.2. Static RSA and static DH cipher suites removed; all public-key-based key exchange provides forward secrecy.
- IETF, [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849) (published March 2026; checked through search results on 2026-11-05).
- IETF, [RFC 8484: DNS Queries over HTTPS](https://www.rfc-editor.org/rfc/rfc8484), [RFC 7858: DNS over TLS](https://www.rfc-editor.org/rfc/rfc7858), [RFC 9250: DNS over Dedicated QUIC Connections](https://www.rfc-editor.org/rfc/rfc9250).
- IETF, [RFC 2784: GRE](https://www.rfc-editor.org/rfc/rfc2784), [RFC 4213: Basic Transition Mechanisms for IPv6 (IPv6 over IPv4 tunnels)](https://www.rfc-editor.org/rfc/rfc4213), [RFC 1918: private addresses](https://www.rfc-editor.org/rfc/rfc1918), [RFC 791: IP](https://www.rfc-editor.org/rfc/rfc791).

!!! note "About this page"
    A personal study note, rewritten in my own words from several learning resources. The experiment pcaps and certificate are my own, and the scenarios are hypothetical.
