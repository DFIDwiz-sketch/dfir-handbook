---
title: Account Compromise & BEC
tags:
  - playbook
  - identity
  - cloud
---

# Account Compromise & Business Email Compromise

<div class="dfir-meta" markdown>
**Scenario:** Suspicious sign-in, mailbox rule, or fraudulent email from a legitimate account · **Last updated:** 2026-09-17
</div>

!!! abstract "When to use this"
    A user's credentials were phished or stolen and someone is signing in as them — impossible-travel logins, MFA-fatigue approvals, a new inbox rule that hides replies, mail sent from the account the user didn't write, or an OAuth app consent the user doesn't recognise. In BEC the goal is usually **invoice/payment fraud** or onward phishing from a trusted mailbox. Most evidence is in **cloud logs** (Entra/M365, Google Workspace), not on an endpoint.

## 1. Triage (first 15 minutes)

- Confirm the suspicious sign-in: source IP/country/ASN, device, whether MFA was satisfied and how (push approved? token? legacy auth bypassing MFA?).
- Check for **inbox rules** and **forwarding** — attackers create a rule that moves replies containing "invoice/payment/bank" to RSS/Archive/Deleted so the user never sees the fraud thread.
- Check **OAuth app consents** granted recently — a malicious app keeps access even after a password reset.
- If money is in motion (a fraudulent payment request), escalate to finance/leadership **immediately** — recovery is time-critical.

## 2. Collect

| Source | What | Key fields |
|---|---|---|
| Entra ID / Azure AD sign-in logs | Every auth attempt | `UserId`, `IPAddress`, `AppDisplayName`, `Status`, `MfaDetail`, `DeviceDetail`, `ConditionalAccessStatus` |
| M365 Unified Audit Log | Mailbox & admin actions | `Operation` (`New-InboxRule`, `Set-Mailbox`, `Add-MailboxPermission`, `UpdateInboxRules`, `Consent to application`), `ClientIP`, `UserId` |
| Message trace | Mail sent/received | sender, recipient, subject, status |
| Google Workspace (if used) | Login + admin + Gmail logs | `login`, `token`, Gmail settings audit |
| Endpoint (if creds phished via a page/malware) | The phishing artifact | [phishing delivery](../adversary/phishing-delivery.md) |

## 3. Analyse

- **The malicious session**: pin the attacker's IP/ASN/user-agent from the sign-in logs, then find **every action** in the audit log with that `ClientIP` and session — rules created, mail read/sent, files accessed (SharePoint/OneDrive), permissions added.
- **Inbox rules & forwarding**: enumerate all rules and forwarding addresses on the mailbox; attackers hide the fraud thread and auto-forward to an external address. Note creation time and the rule's conditions/actions.
- **OAuth grants**: list app consents; a malicious "app" (illicit consent grant) survives password resets and re-reads mail via token — revoke it.
- **Blast radius**: did they send phishing to internal/external contacts from this mailbox? Message trace for outbound in the window. Did they access shared files? Check SharePoint/OneDrive audit.
- **MFA**: was MFA bypassed (legacy auth, token theft/AiTM) or approved (MFA fatigue)? AiTM (adversary-in-the-middle) phishing steals the **session token**, so the sign-in shows MFA satisfied from an odd IP — a password reset alone won't help; you must **revoke sessions/tokens**.

## 4. Contain / Eradicate

- **Reset the password AND revoke all sessions/refresh tokens** (Entra: "Revoke sessions"; Google: sign out all sessions) — a token-theft attacker ignores a password change.
- Re-register / require MFA; remove attacker-registered MFA methods and devices.
- **Delete malicious inbox rules and forwarding**; remove mailbox permissions the attacker added.
- **Revoke suspicious OAuth app consents**.
- Block the attacker infrastructure; if a phishing page harvested the creds, take it down / report it.
- Reset any **other accounts** that shared the password or were phished by the same campaign.

## 5. Recover & lessons

- Notify recipients of any phishing/fraud sent from the mailbox; correct any fraudulent payment instructions with finance and the counterparty (contact them out-of-band).
- Report per obligations (privacy regulator, bank, insurer).
- Harden: enforce **phishing-resistant MFA** (FIDO2/passkeys) especially for finance/execs, block **legacy authentication**, tighten **Conditional Access** (block risky sign-ins, restrict countries), restrict **OAuth app consent** (admin approval), alert on **new inbox rules / forwarding**, and run BEC-aware user training + payment-verification procedures.

## Useful queries

```spl
index=<your_o365_index> sourcetype="o365:management:activity" Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox")
| table _time, UserId, ClientIP, Operation, Parameters
| sort 0 _time
```

`Operation` names the mailbox action; `New-InboxRule`/`UpdateInboxRules` with a `ClientIP` from the attacker's session, especially a rule that moves "payment/invoice/bank" mail to a hidden folder, is the BEC signature. `Parameters` holds the rule's conditions and actions.

```spl
index=<your_aad_index> sourcetype="azure:aad:signin"
| stats values(IPAddress) as ips, values(AppDisplayName) as apps, dc(IPAddress) as ip_count, values(Status.errorCode) as codes by UserPrincipalName
| where ip_count > 5
```

Groups sign-ins per user and counts distinct source IPs; an account suddenly authenticating from many IPs/countries (or a new `AppDisplayName`) is a takeover indicator. Adapt field names to your M365/Entra add-on — check with [data discovery](../splunk/data-discovery.md).

```spl
index=<your_o365_index> sourcetype="o365:management:activity" Operation="Consent to application"
| table _time, UserId, ClientIP, ObjectId, ApplicationId
```

Illicit OAuth consent grants — a user (or attacker acting as them) approving an app that then reads mail via token. These persist past password resets, so they must be found and revoked.

## References

- [Microsoft — Responding to a compromised email account](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account)
- [CISA — Business Email Compromise](https://www.cisa.gov/) · [FBI IC3 BEC](https://www.ic3.gov/)
- [Microsoft — Unified Audit Log / AiTM investigation](https://learn.microsoft.com/en-us/defender-xdr/)
- Pages: [Phishing delivery](../adversary/phishing-delivery.md) · [Data discovery](../splunk/data-discovery.md)
