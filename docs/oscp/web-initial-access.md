---
title: Web & Initial Access
tags:
  - oscp
---

# Web & Initial Access

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per standalone (`local.txt`) · **Last updated:** 2026-10-22
</div>

!!! abstract "In one sentence"
    Getting the first shell on a standalone: usually a web application or an exposed service, often a public exploit that needs fixing before it works.

!!! info "Skeleton page"
    Structure only for now — the headings below are the plan. Fill each section as you study.

## Web enumeration { #web-enumeration }

- Directory, vhost and subdomain fuzzing; tech fingerprinting; reading the source

## SQL injection (manual) { #sqli }

## File upload bypasses { #file-upload }

## LFI / path traversal → RCE { #lfi }

- Reading SSH keys; chaining with an upload to get code execution

## SSRF { #ssrf }

## CMS & known applications { #cms }

- WordPress plugins and users, default credentials

## Public exploits { #public-exploits }

- searchsploit, adapting and fixing old exploit code

## Client-side attacks { #client-side }

- A file someone will open → reverse shell or NTLMv2 hash leak

## Non-web services { #other-services }

- FTP, SMB, NFS, SNMP (UDP)

## Related pages

- [Nmap](../pentesting/recon/nmap/index.md) · [Well-known ports](../basics/well-known-ports.md) · [HTTP status codes](../basics/http-status-codes.md)
- [Red Team: Initial Access](../redteam/initial-access.md) · [Phishing delivery](../adversary/phishing-delivery.md)

## References

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
