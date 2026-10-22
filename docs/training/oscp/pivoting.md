---
title: Pivoting & Tunnelling
tags:
  - oscp
---

# Pivoting & Tunnelling

<div class="dfir-meta" markdown>
**Where it matters:** AD set — reaching internal subnets · **Priority:** High · **Last updated:** 2026-10-22
</div>

!!! abstract "In one sentence"
    The failure that shows up most in 2025–2026 write-ups: owning the first machine but never getting traffic into the internal network behind it.

!!! info "Skeleton page"
    Structure only for now — the headings below are the plan. Fill each section as you study.

## When you need to pivot { #when-to-pivot }

- Signs: a second network interface, internal routes, services listening only on `127.0.0.1`

## Internal subnet discovery { #subnet-discovery }

- Finding live hosts and ports from the foothold

## Ligolo-ng { #ligolo-ng }

- Proxy, agent, `tun` interface, routes
- Listener so reverse shells can come back through the pivot

## Chisel { #chisel }

- Reverse SOCKS as a fallback

## SSH forwarding { #ssh-forwarding }

- Local `-L`, remote `-R`, dynamic `-D`

## proxychains { #proxychains }

- Which tools work through SOCKS and which do not

## Double pivot { #double-pivot }

- Chaining a second hop

## File transfer through the pivot { #file-transfer }

- Getting tools onto internal hosts

## Related pages

- [Nmap](../../pentesting/recon/nmap/index.md) — scanning through a tunnel
- [Network](../../network/index.md) — what tunnelled traffic looks like to a defender
- [Active Directory](active-directory.md)

## References

- [netguardia — OSCP in 2026 (failure patterns)](https://netguardia.com/learning-development/certifications/oscp-in-2026-is-it-still-the-gold-standard-and-is-the-new-format-harder/)
