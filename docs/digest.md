# The digest, verdicts and evidence

The digest email is the product. If it is good enough you never open the console, and that is success.

## What arrives

Daily at 07:30 local on weekdays (configurable), plus an immediate email whenever a new **Fix today** appears:

1. A headline: "3 to fix today, 5 this week. 41 CVEs since Monday you did not need to read."
2. **Fix today**: one sentence each, with Details, Done and Snooze 7 days links.
3. **Fix this week**: same.
4. **Check these**: matched on product name but the version could not be confirmed. Never emailed as Fix today; add the installed version to settle them.
5. **Changed since last digest**: promoted, demoted, closed or re-opened, with the reason ("now in CISA KEV", "public exploit published", "patched, closed", "re-opened: snooze expired"). A re-open is always listed here, whether or not the verdict moved tier: something you marked done that comes back under Fix today says why.
6. **Overdue**: anything open past its fix window.
7. **Next patch cycle**: a count and a link.
8. A coverage line: assets seen, sources, unknown hosts, watchlist size, when the feeds were last current.
9. Attribution for EPSS and the other feeds that ask for it. Nothing else.

The same events can also go to Teams or Slack: see [chat.md](chat.md).

## Done and Snooze from the email

Each Fix today and Fix this week item has a **Done** and a **Snooze 7 days** link that work without signing in to the console. They are for the recipient who reads the digest on a phone, or who has no console login at all.

What happens when a link is followed:

1. The link opens a small page on the console showing the verdict and one button, **Confirm**. Opening the page changes nothing. Mail scanners, link previewers and "safe links" services fetch every link in an email, so an action that happened on opening would be taken by a robot before anyone read the message.
2. Pressing Confirm marks the verdict done, or snoozes it for seven days. The page then says so.

The security model:

- **The link is the authority.** It carries a token signed and encrypted by the console (ASP.NET Data Protection, under a purpose used for nothing else), so it cannot be forged or altered, and a token made for anything else the console signs is not accepted. The keys are the ones in the `data` volume that already protect stored credentials.
- **A token allows one action on one verdict.** It names the digest it was sent in, the verdict, and Done or Snooze. A Done link cannot snooze and neither can touch a different verdict.
- **It expires after 7 days.**
- **Tokens exist only in the email.** The copy of each digest the console keeps (under Digests, and in the database and its backups) has the ordinary console links, so a console user who was not sent the digest does not get the links by looking it up.
- **It stops working when the verdict changes.** The token records the verdict's state and tier as they were when the digest was built. If it has since been done, snoozed, re-opened, promoted or demoted, by anyone or by a re-evaluation, the page says "This has changed since the email" with a link to the console, and does nothing. This is also what makes a link single-use.
- **The change needs a POST from the confirmation page**, with an antiforgery token tied to a cookie that page set. A GET never changes anything.
- **Requests are rate limited** per address (60 a minute).
- **It is recorded.** The verdict's history and the audit log show the action as done by "digest link (digest 3f2a91c4)", naming the digest it came from, and the audit log also keeps the address the confirmation came from.

What it does not do: identify a person. The digest is one email to every recipient, so every recipient gets the same links, and anyone the email is forwarded to can use them. The token is in the link's address, so it can appear in a proxy's access log. The most a link can do is close or snooze one verdict, either of which is visible in the audit log and undone in the console; a verdict closed this way still re-opens if it gets worse. If that is more than you want from an email, switch **Done and Snooze links in the digest email** off under Settings: links already sent stop working at once, and the Done link goes back to opening the verdict in the console, where the reader signs in.

The links need the **Console address** in Settings, and the recipient must be able to reach it. They are in the daily digest and in a digest sent by hand from the console; the immediate Fix today email links to the console only.

## The four verdicts

| You see | Meaning | Fix window |
|---|---|---|
| Fix today | exploited in the wild and reachable, or a public exploit that works at scale against something internet-facing | 48 hours |
| Fix this week | serious but not that | 7 days |
| Next patch cycle | real, not urgent | 30 days |
| (not shown) | Ignore (tracked) and Not affected: counted in "dismissed", re-evaluated whenever a feed changes, browsable in the console | none |

## How a verdict is decided

Four inputs, computed, never tuned: exploitation status (CISA KEV, vendor advisories, Exploit-DB, Metasploit, Nuclei, EPSS, Vulnrichment), whether it can be done at scale (the CVSS vector, not the score), where the asset sits (internet-facing, internal, isolated, or not installed), and how much the asset matters. A physical or local attack vector on an internet-facing box is treated as internal, because network exposure does not help that attacker. A documented compensating control (WAF in front, MFA enforced, feature disabled) lowers a verdict one step and is named in the sentence; it never lowers "exploited in the wild and internet-facing".

The decision table is in `src/VulnVerdict.Core/Engine/DecisionTable.cs`; every rule has a unit test.

## The sentence

Product, version, asset: what the attacker has, how they get in, where it is, what fixes it. "FortiOS 7.2.5 on FW-EDGE-01: exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8." Something you can repeat to your boss.

## Evidence

Every verdict, including Not affected, stores an evidence chain: each claim, its source and when it was retrieved. Open any verdict to read it. The **Explain** section on the same page is the only place the jargon appears: SSVC inputs, the CVSS vector decoded into English, EPSS, KEV status, vendor advisories.

## Workflow

Done, snooze (until a date), accept risk (owner, reason, expiry), suppress (a CVE, a product, or an asset, with expiry). A promotion re-opens snoozed and accepted items and reports them under "Changed", as is every other re-open: a snooze or accepted risk that ran out, a suppression that was removed, something closed that is affected again. A fixed version observed by a connector closes the verdict automatically with the reason "patched, closed".

## Weekly report

For the person who asks "are we affected by the thing on the news": new CVEs published, how many concerned what you run, how many needed action, done, open, overdue, dismissed. Printable HTML and CSV under Reports, emailed on the configured day.
