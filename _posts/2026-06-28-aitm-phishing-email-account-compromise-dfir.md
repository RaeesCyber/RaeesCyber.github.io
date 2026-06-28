---
title: "AiTM Phishing & Email Account Compromise: A DFIR Walkthrough"
date: 2026-06-28 12:00:00 +0500
categories: [DFIR, Incident Response]
tags: [aitm, phishing, email-compromise, dfir, microsoft-365, threat-hunting, entra-id, bec, session-hijacking]
description: A DFIR deep-dive into Adversary-in-the-Middle phishing targeting corporate email accounts — attack chain, artifact analysis, KQL hunting queries, and remediation playbook.
image:
  path: /assets/img/posts/aitm-phishing/cover.png
  alt: AiTM Phishing DFIR Investigation
toc: true
comments: true
pin: false
math: false
mermaid: false
---

## Overview

Adversary-in-the-Middle (AiTM) phishing is a session hijacking technique that **bypasses Multi-Factor Authentication** by proxying the victim's authentication flow in real-time. Unlike traditional credential harvesting, AiTM steals the **post-authentication session cookie** — giving the attacker persistent account access without ever needing the victim's password or OTP.

**Scenario for this post:**
> A corporate Microsoft 365 email account is compromised via an AiTM phishing campaign. The SOC fires an alert on anomalous sign-in activity. You are the DFIR analyst assigned to the case.
{: .prompt-info }

**What this post covers:**
- End-to-end AiTM attack chain
- How the email account gets taken over
- DFIR investigation methodology and artifact sources
- KQL hunting queries for Microsoft 365 / Entra ID
- Containment sequence and remediation hardening

---

## How AiTM Phishing Works

Traditional phishing captures credentials. AiTM goes further — it intercepts the **live authentication session** by acting as a transparent reverse proxy between the victim and the legitimate Identity Provider (e.g., Microsoft Entra ID).

![AiTM Attack Chain Diagram](/assets/img/posts/AitmPhishng/AitmPhishingCookiesTheft.png){: w="700" h="400"}


**Attack Chain Breakdown:**

| Step | What Happens |
|------|-------------|
| 1 | Victim receives a phishing email with a malicious link |
| 2 | Link redirects to attacker-controlled reverse proxy (Evilginx2 / Modlishka / Muraena) |
| 3 | Proxy forwards all traffic transparently to `login.microsoftonline.com` |
| 4 | Victim authenticates — including completing MFA — on the proxy page |
| 5 | Proxy captures the **authenticated session cookie** in transit |
| 6 | Attacker replays the cookie from their own machine — MFA already satisfied |
| 7 | Full M365 access: Outlook, Teams, SharePoint, OneDrive |

> MFA is **not** a silver bullet against AiTM. The attacker bypasses it by stealing the post-authentication session cookie — not the MFA factor itself. Cookie = authenticated session.
{: .prompt-warning }

---

## The Phishing Delivery

AiTM campaigns abuse trusted infrastructure to evade email security controls and gain victim trust.

![Sample AiTM Phishing Email](/assets/img/posts/AitmPhishng/AitmPhishingEmail.png){: w="700" h="400"}
_

**Common lure themes used in AiTM campaigns:**

- Fake Microsoft security alerts — *"Unusual sign-in activity detected on your account"*
- Shared document notifications — OneDrive / SharePoint file lures
- Invoice and voicemail notifications — *"You have a new voicemail — click to listen"*
- Sent from a **previously compromised legitimate account** — bypasses sender reputation checks entirely

> If the phishing email was sent from a legitimate compromised account in the same org or a known partner, standard email authentication (SPF/DKIM/DMARC) will **pass**. Do not rely solely on email auth for detection.
{: .prompt-danger }

---

## DFIR Investigation Methodology

### Phase 1 — Initial Triage

**Trigger:** SOC alert — successful sign-in from an unfamiliar IP, impossible travel, or anomalous user agent.

**First 15 minutes — answer these:**

- Which account was signed into?
- What IP authenticated successfully? What ASN / hosting provider?
- Was MFA satisfied? Which method?
- What was the time delta between the victim's last known-good login and the anomalous one?
- Did the location make geographic sense?

```bash
# Pull sign-in logs for the affected user via Graph API (quick triage)
GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userPrincipalName eq 'victim@domain.com'&$top=50
```
{: .nolineno }

---

### Phase 2 — Log Sources

| Log Source | Where to Find It | Key Artifacts |
|---|---|---|
| **Entra ID Sign-In Logs** | Azure Portal → Entra ID → Sign-ins | IP, ASN, user agent, MFA method, token claims |
| **Unified Audit Log (UAL)** | Microsoft Purview / M365 Compliance | MailboxLogin, FileAccessed, InboxRule created |
| **Mailbox Audit Log** | Exchange Online PowerShell | MailItemsAccessed, SendAs, Create (rules) |
| **Microsoft Defender XDR** | security.microsoft.com | AiTM-specific alerts, identity incidents |
| **Defender for Cloud Apps** | MDA / MCAS | Impossible travel, mass download alerts |
| **Message Trace** | Exchange Admin Center | Phishing email delivery, originating IP |

![Microsoft 365 Log Source Map](/assets/img/posts/AitmPhishng/mappingLogSoucese.png){: w="700" h="400"}


> Preserve raw logs **before** any containment action. Revoking sessions can modify token state and overwrite evidence in some log sources. Export first.
{: .prompt-danger }

---

### Phase 3 — KQL Hunting Queries

**Hunt for successful MFA logins from non-compliant/unnamed locations:**

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where AuthenticationRequirement == "multiFactorAuthentication"
| where NetworkLocationDetails !contains "compliant"
| where NetworkLocationDetails !contains "named"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          UserAgent, DeviceDetail, CorrelationId, RiskLevelDuringSignIn
| order by TimeGenerated desc
```
{: file="hunt_aitm_signin.kql" }

**Detect suspicious inbox rules created post-compromise:**

```kql
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "RedirectTo", "DeleteMessage", "MoveToFolder")
| project TimeGenerated, UserId, ClientIP, Parameters, OperationProperties
| order by TimeGenerated asc
```
{: file="hunt_inbox_rules.kql" }

**Detect session cookie replay — same session ID, multiple source IPs:**

```kql
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType == "MailItemsAccessed"
| where RawEventData has "REST"
| extend SessionId = tostring(parse_json(tostring(RawEventData)).SessionId)
| summarize
    IPList = make_set(IPAddress),
    IPCount = dcount(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SessionId, AccountDisplayName
| where IPCount > 1
| order by IPCount desc
```
{: file="hunt_cookie_replay.kql" }

> The cookie replay query is your **highest-fidelity AiTM indicator** in M365. One session ID appearing from two geographically distinct IPs is a near-definitive confirmation of cookie theft and replay.
{: .prompt-tip }

---

### Phase 4 — Timeline Reconstruction

Build a chronological timeline correlating all log sources before concluding anything.

![Attack Timeline Visualization](/assets/img/posts/AitmPhishng/AttackTimeLine.png){: w="700" h="400"}


**Key timestamps to correlate:**

```
[ ] Phishing email delivery time           → Message Trace
[ ] Victim click time                       → URL detonation / proxy access log
[ ] Successful Entra sign-in from attacker → Entra Sign-in Logs (new IP)
[ ] First MailItemsAccessed from attacker  → Mailbox Audit / CloudAppEvents
[ ] Inbox rule creation                     → UAL / OfficeActivity
[ ] Any outbound emails sent by attacker   → Message Trace / UAL
[ ] Any OAuth app consent granted          → Entra ID → Enterprise Apps
```
{: .nolineno }

---

### Phase 5 — Post-Compromise Activity

Once the attacker has a valid session, they follow a predictable pattern:

![Post-Compromise Activity Kill Chain](/assets/img/posts/AitmPhishng/%20KillChainDiagram.png){: w="700" h="400"}


| Activity | What to Look For |
|---|---|
| **Mailbox Recon** | High volume of `MailItemsAccessed` events shortly after session replay |
| **Inbox Rules** | `New-InboxRule` with ForwardTo external address or DeleteMessage on keywords |
| **BEC Outbound** | Emails sent impersonating victim — check Message Trace for outbound after attacker session |
| **Lateral Phishing** | Same AiTM lure sent to victim's contacts from the compromised account |
| **Data Exfil** | Mass `FileDownloaded` / `FileSyncDownloadedFull` from SharePoint or OneDrive |
| **OAuth Persistence** | New OAuth app granted Mail.Read or Mail.ReadWrite scope |

> If you find an inbox forwarding rule created within 30 minutes of the first attacker session — that is a **confirmed compromise indicator**. Do not wait for further evidence; escalate and contain immediately.
{: .prompt-tip }

---

## IOC Extraction Checklist

```
[ ] Attacker IP address(es) from Entra sign-in logs
[ ] AiTM proxy domain extracted from phishing URL
[ ] Hosting ASN / datacenter range (check Shodan / ASN lookup)
[ ] User agent string used during attacker session (often headless or generic)
[ ] Session ID(s) involved in cookie replay
[ ] Forwarding rule destination email address
[ ] Outbound BEC email recipients and subject lines
[ ] Phishing email sender address and X-Originating-IP header
[ ] Any OAuth application IDs consented during attacker session
[ ] Timestamps for all above (UTC + local)
```
{: .nolineno }

---

## Containment

**Execute in this exact order.** Sequence matters.

1. **Revoke all active sessions** → Entra ID → User → Revoke Sessions
2. **Reset password** → Force reset to invalidate existing token lineage
3. **Remove inbox rules** → Exchange Admin Center or PowerShell
4. **Block attacker IPs** → Conditional Access Named Locations (block) or firewall ACL
5. **Purge phishing email** → Defender Threat Explorer → Hard Delete from all mailboxes
6. **Revoke OAuth grants** → Entra ID → Enterprise Apps → Review and revoke attacker-consented apps
7. **Notify downstream recipients** → If BEC emails were sent, alert recipients to disregard

> **Revoke sessions BEFORE resetting the password.** Resetting first can generate a new session state that the attacker's existing cookie briefly rides before expiry. Revoke, then reset.
{: .prompt-warning }

---

## Remediation & Hardening

| Control | Action |
|---|---|
| **Phishing-Resistant MFA** | Migrate to FIDO2 hardware keys, Windows Hello for Business, or Passkeys. These are AiTM-proof — they bind to the origin domain. |
| **Conditional Access** | Enforce compliant device + named location policy. Block sign-ins from non-managed devices or unknown networks. |
| **Token Lifetime** | Reduce access token and refresh token lifetime. Enable Continuous Access Evaluation (CAE) for real-time revocation. |
| **Safe Links** | Enable Defender for Office 365 Safe Links with URL rewriting for all users — rewrites and inspects redirect chains at click-time. |
| **Mailbox Audit** | Ensure `MailItemsAccessed` auditing is enabled (requires E5 or Microsoft 365 Audit add-on). |
| **Alert Rules** | Alert on: new inbox rules from non-compliant IPs; impossible travel; first-time ASN sign-in. |
| **UEBA Baseline** | Baseline normal login behavior per user. Anomalous session patterns (new country, new ASN, new device) should auto-trigger high-priority alert. |

---

## Detection Engineering — Sigma Rule

```yaml
title: AiTM Phishing - Session Cookie Replay Detected
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects the same session ID authenticating MailItemsAccessed from
  multiple distinct IPs, indicative of AiTM cookie theft and replay.
references:
  - https://www.microsoft.com/security/blog/2022/07/12/from-cookie-theft-to-bec/
  - https://attack.mitre.org/techniques/T1539/
author: VeXor
date: 2026-06-28
logsource:
  product: microsoft365
  service: cloudappevents
detection:
  selection:
    ActionType: MailItemsAccessed
    RawEventData|contains: REST
  condition: selection
  timeframe: 1h
  groupby:
    - AccountDisplayName
    - SessionId
  having:
    distinct_count|IPAddress: ">1"
falsepositives:
  - Mobile users roaming across carrier NATs
  - VPN split-tunneling scenarios
level: high
tags:
  - attack.credential_access
  - attack.t1539
  - attack.initial_access
  - attack.t1566.002
```
{: file="sigma_aitm_cookie_replay.yml" }

---

## References

- [Microsoft MSRC — From Cookie Theft to BEC (2022)](https://www.microsoft.com/security/blog/2022/07/12/from-cookie-theft-to-bec/)
- [MITRE ATT&CK — T1539: Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK — T1566.002: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [Microsoft Docs — Detect and Remediate AiTM Phishing](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-remediate-aitm-phishing)
- [Kuba Gretzky — Evilginx2](https://github.com/kgretzky/evilginx2)
- [AADInternals — Token Theft and Replay Research](https://aadinternals.com)
