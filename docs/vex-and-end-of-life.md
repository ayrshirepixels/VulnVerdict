# Vendor statements (VEX) and end of life

Two sources that refine verdicts the decision table has already made. Neither adds a tier, and neither changes the table.

## Vendor VEX statements

Vendors publish machine-readable statements saying which of their products a CVE affects, which have a fix, which are not affected and why, and which they are still looking at (CSAF 2.0, the `csaf_vex` profile). The console reads them and puts them in the evidence chain.

| The vendor says | What the console does |
|---|---|
| fixed, with a version | Adds the fixed version to the evidence, and to the sentence when the CVE record names none. |
| known affected | Strengthens the match: a "check this" becomes likely or exact, and an exact statement settles a version the CVE record could not be read against. |
| known not affected | On an **exact** match only (the same product, the installed version, the same product stream), the verdict becomes **Not affected**, with the vendor's reason, the document link and its date in the evidence. The verdict stays listed like any other not-affected verdict: it is not closed and not hidden. |
| known not affected, weaker match | An evidence line: "vendor says not affected for X: check". The tier does not move. |
| known not affected, but the CVE is in KEV or exploited in the wild | The tier is **not** lowered. The verdict keeps its tier and says "Check this: the vendor states this product is not affected ...; confirm before closing". A person decides. |
| under investigation | An evidence line. |

A missed vulnerability is the dangerous mistake, so a not-affected statement is also left unapplied when the same vendor's data lists the product as affected, as under investigation, or as fixed in a version later than the one installed.

When a vendor revises a document and withdraws not-affected, the verdict returns to the tier the decision table gives it, with a fresh fix window and the reason "the vendor withdrew its not-affected statement". If someone had closed the verdict on the vendor's word, it re-opens.

### What "exact" means

- **A product on the watchlist or in the inventory**: the same vendor and product name (or CPE), and the statement either covers the product as a whole, names the installed version, or gives a range the installed version is inside. A statement for a branch ("7.2" when 7.2.5 is installed) confirms the product, not the version, and is evidence only.
- **A package on a Linux host**: the same package, as a component of the host's own product stream. An `openssl` statement for Red Hat Enterprise Linux 9 is exact for a RHEL 9 host, says nothing about a RHEL 8 host, and is evidence only for an extended-support stream (9.2 EUS) or a rebuild (AlmaLinux, Rocky Linux).

### Providers

The provider list is a setting (Settings, **Vendor statements and end of life**). Blank means the built-in list:

| Provider | Default | Notes |
|---|---|---|
| Red Hat | on | `https://security.access.redhat.com/data/csaf/v2/vex/`, one file per CVE |
| SUSE | on | `https://ftp.suse.com/pub/projects/security/csaf-vex/`, one file per CVE |
| Microsoft | off | `https://msrc.microsoft.com/csaf/vex/`; Microsoft is already covered by the MSRC feed |
| Siemens | off | provider-metadata.json leading to a ROLIE feed |
| Cisco | off | provider-metadata.json; Cisco is already covered by the openVuln feed |

Adding a provider is one more entry:

```json
[
  { "id": "redhat", "name": "Red Hat", "url": "https://security.access.redhat.com/data/csaf/v2/vex/", "vendors": ["Red Hat", "AlmaLinux", "Rocky Linux"], "enabled": true },
  { "id": "acme", "name": "Acme", "url": "https://acme.example/.well-known/csaf/provider-metadata.json", "vendors": ["Acme"], "enabled": true }
]
```

`url` is a CSAF distribution directory (it must hold `changes.csv`), a `provider-metadata.json` (the directory whose name contains "vex" is used, or `distribution` to name another, else its ROLIE feeds), or a ROLIE feed. `vendors` are the vendor names, or Linux distributions, the provider speaks for.

### What is fetched

Red Hat alone publishes hundreds of thousands of VEX files, some of them several megabytes. The console does not mirror them:

- a provider is only contacted when one of its vendors' products is on the watchlist or in the inventory;
- a per-CVE document is only fetched when that CVE already has a verdict against one of those products;
- only the statements about those products are stored, with a link to the vendor's document.

A statement can only adjust a verdict that exists, so nothing is lost. A CVE published today gets its verdict from the CVE record first and its vendor statement on the feed's next run (every six hours, or **Run now** on the Sources page). Providers whose files are not named by CVE are small and are read in full.

Each run takes at most 150 documents per provider and carries on in the next pass until it has caught up. A document that fails is retried on the next run and its stored statements are kept meanwhile. The Sources page shows, per provider, the newest change everything is stored up to; "held" means older documents are still to do.

## End of life

Release cycles and support end dates come from [endoflife.date](https://endoflife.date) (MIT-licensed data, refreshed daily). The console maps what is installed to a release and flags:

- **End of life**: the vendor has stopped patching this release.
- **End of life in N days**: support ends within the window set in Settings (180 days by default).

The flags appear in the **End of life** list on the Watchlist and Assets pages, and in the evidence of every verdict for that product. For a release that is past support, the sentence ends "No fix will be released for this version: upgrade or replace." instead of naming a fixed version, unless the fix is in that same release (it shipped before support ended). The digest carries one line: "3 products are past vendor support; 2 reach end of support within 90 days."

End of life is not a verdict tier and not an input to the decision table. It tells you that waiting for a patch is not a plan.

### What is mapped

A curated map covers what a small business usually runs: Windows and Windows Server, Office, SQL Server, Exchange, SharePoint, .NET and .NET Framework, FortiOS, PAN-OS, Cisco IOS XE, F5 BIG-IP, OPNsense, VMware ESXi and vCenter, Proxmox VE, Ubuntu, Debian, RHEL, AlmaLinux, Rocky Linux, CentOS, SLES, Oracle Linux, Amazon Linux, macOS, iOS, PHP, Node.js, Python, Java (Oracle, Temurin, Corretto, Zulu, Microsoft), Apache HTTP Server, Tomcat, nginx, MySQL, MariaDB, PostgreSQL, MongoDB, Redis, OpenSSL and a few common applications.

Anything else is tried by name against the endoflife.date product list. A match found that way is only ever shown as "possibly" under the list. It flags nothing, changes no sentence and is not counted in the digest.

Not covered: SonicOS, Sophos Firewall and pfSense (endoflife.date does not track them), and evergreen software with no release to outlive (Microsoft 365 Apps, Chrome, Edge, Firefox). Distribution packages are not flagged one by one; the distribution release they belong to is. Where a release has editions with different end dates (Windows 11 Home and Pro against Enterprise and Education), the later date is used, so a release is never called out of support while one of its editions is still in.

## Signed bundles and air-gapped sites

When the console is fed by signed bundles, neither feed calls out. The data travels in the bundle instead, as two optional files:

| File | Contents |
|---|---|
| `vex.jsonl` | one VEX statement per line |
| `eol.json` | an array of release cycles |

They are listed in the manifest under `extras`, with their size and SHA-256, and `extrasSignature` signs that list together with the bundle version and build time. The console verifies the signature and every hash exactly as it does for the six required files, and refuses the bundle if either is wrong. A console from before these files existed does not read `extras`, verifies the same main signature, unpacks the six files it knows and applies the bundle as before.

A bundle's statements replace the stored ones. Only statements about products on the watchlist or in the inventory are kept, so a product added later gets its statements from the next bundle. A bundle without the optional files leaves stored VEX and end-of-life data untouched.

## Cisco openVuln credentials

The Cisco PSIRT feed needs a client id and secret from Cisco's API console. They are entered on the Settings page and stored encrypted, like every other secret. An install that had them in the two plain `psirt:cisco:*` rows of an earlier release has them moved, encrypted, the first time settings are read; the old rows are deleted.
