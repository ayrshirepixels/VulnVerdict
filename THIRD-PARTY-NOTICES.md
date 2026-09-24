# Third-party notices

VulnVerdict is licensed under the AGPL-3.0 (`LICENSE`). It builds on the following, each under its own licence.

## Libraries (NuGet)

| Package | Licence | Used for |
|---|---|---|
| Microsoft.EntityFrameworkCore, .Sqlite, .Design | MIT | data access and migrations |
| Npgsql.EntityFrameworkCore.PostgreSQL | PostgreSQL licence | PostgreSQL provider |
| MailKit / MimeKit | MIT | SMTP transport |
| SSH.NET (Renci.SshNet) | MIT | Linux and Windows-over-SSH collectors |
| Lextm.SharpSnmpLib | MIT | SNMP adapter |
| System.ServiceModel.Syndication | MIT | RSS parsing |
| Anthropic (official C# SDK) | MIT | optional AI explanations |
| ASP.NET Core, Blazor, Microsoft.Extensions.* | MIT | console and host |
| Microsoft.AspNetCore.Authentication.OpenIdConnect | MIT | single sign-on |

## Images and runtime

| Component | Licence |
|---|---|
| .NET runtime and SDK images | MIT |
| PostgreSQL 16 | PostgreSQL licence |
| Caddy | Apache-2.0 |
| Ubuntu (appliance base) | various, see Ubuntu licensing |

## Fonts (self-hosted under `wwwroot/fonts` and `site/assets/fonts`)

| Font | Licence |
|---|---|
| Inter | SIL Open Font License 1.1 |
| Space Grotesk | SIL Open Font License 1.1 |

## Data feeds

| Feed | Terms |
|---|---|
| CVE List V5 (CVE Program) | CC0. "CVE" is a registered trademark of The MITRE Corporation, used as a data reference only |
| CISA Known Exploited Vulnerabilities, CISA Vulnrichment | public |
| EPSS (FIRST) | free with attribution to FIRST; every digest and report carries it |
| OSV.dev | public (Apache-2.0 data) |
| Exploit-DB, Metasploit module index, Nuclei templates | referenced and linked only; never redistributed |
| Vendor advisories (Fortinet, Microsoft MSRC, Cisco openVuln, Broadcom/VMware, Ubuntu, Debian, Red Hat) | each vendor's public terms; referenced and linked, with the vendor's affected and fixed statements stored for matching |
| Shodan (optional) | requires the customer's own API key and acceptance of Shodan's terms |

SSVC is published by CISA and the Carnegie Mellon University Software Engineering Institute; the decision table here is derived from the deployer tree.
