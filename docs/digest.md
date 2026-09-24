# The digest, verdicts and evidence

The digest email is the product. If it is good enough you never open the console, and that is success.

## What arrives

Daily at 07:30 local on weekdays (configurable), plus an immediate email whenever a new **Fix today** appears:

1. A headline: "3 to fix today, 5 this week. 41 CVEs since Monday you did not need to read."
2. **Fix today**: one sentence each, with Details and Done links.
3. **Fix this week**: same.
4. **Check these**: matched on product name but the version could not be confirmed. Never emailed as Fix today; add the installed version to settle them.
5. **Changed since last digest**: promoted or demoted, with the reason ("now in CISA KEV", "public exploit published", "patched, closed").
6. **Overdue**: anything open past its fix window.
7. **Next patch cycle**: a count and a link.
8. A coverage line: assets seen, sources, unknown hosts, watchlist size, when the feeds were last current.
9. Attribution for EPSS and the other feeds that ask for it. Nothing else.

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

Done, snooze (until a date), accept risk (owner, reason, expiry), suppress (a CVE, a product, or an asset, with expiry). A promotion re-opens snoozed and accepted items and reports them under "Changed". A fixed version observed by a connector closes the verdict automatically with the reason "patched, closed".

## Weekly report

For the person who asks "are we affected by the thing on the news": new CVEs published, how many concerned what you run, how many needed action, done, open, overdue, dismissed. Printable HTML and CSV under Reports, emailed on the configured day.
