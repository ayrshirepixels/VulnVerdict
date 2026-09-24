# Connectors

Every source is an adapter. Every adapter is one credential form: a hostname and a read-only account. Adapters never write to the source, credentials are stored encrypted and never logged, every record is stamped with when it was last seen, and three failures in a row email the administrator.

Assets seen by several sources are merged (MAC address first, then hostname, then a unique IP). Software is tied to the vendor's CVE naming automatically where possible; the rest lands in **Needs mapping** for a one-click decision that is remembered as an alias.

| Connector | Sees | Needs | Notes |
|---|---|---|---|
| Windows servers (WinRM) | OS build and hotfixes, installed software (32 and 64 bit), roles and features (SMBv1, WebDAV, print spooler, RDP), listening ports and owning processes, IIS version, sites and bindings, SQL Server version and patch level, .NET runtimes, Hyper-V VM list | a member of *Remote Management Users* (not local admin), WinRM over HTTPS or HTTP, or Windows OpenSSH | Roles, features and listeners decide reachability, which is why this adds value even where an endpoint agent lists software. |
| FortiClient EMS | endpoints, installed software, EMS vulnerability-scan findings | an EMS admin with a custom read-only role | Findings are stored as a second opinion, never as the verdict. |
| FortiGate | firmware, managed FortiSwitch and FortiAP firmware, and exposure for free: SSL-VPN and admin on WAN interfaces, VIPs behind accept policies | a REST API admin with a read-only profile and a trusted host | Marks the firewall and the VIP targets internet-facing with the policy id as evidence. |
| VMware vCenter | vCenter version, ESXi hosts, the complete VM list with guest hostnames, IPs and MACs | a vCenter user with the Read-Only role | The VM list is the coverage set: VMs no server collector has seen appear as "unknown coverage". |
| Linux servers (SSH) | os-release, package list (dpkg, rpm, apk), listening sockets, running containers | an ordinary user, no sudo | Packages are matched through OSV by package URL, not by product name. |
| SBOM (upload, API, or URL) | application components from CycloneDX or SPDX | none, or a bearer token for a CI artifact URL | Joins a library CVE to a named, exposure-tagged site. |
| Management network (SNMP) | switches, printers, UPS, NAS, out-of-band management (iDRAC, iLO) | a read-only community or SNMPv3 user | Firmware is parsed from sysDescr; unknown families go to Needs mapping. |
| Discovery sweep | hosts answering on common ports, reverse DNS, service banners | subnets to sweep | Discovery only: no vulnerability scripts, ever. Unclaimed hosts are listed as unknown. |
| External cross-check | which public names and addresses answer from outside | your DNS names and IP ranges; a Shodan key is optional | Anything answering is tagged internet-facing regardless of what the firewall adapter says. |

## Ticket channels

Tickets go by email to the helpdesk intake address by default (one per Fix today or Fix this week verdict, correlation key in the subject). Native adapters for Jira, ServiceNow, Freshservice, Zendesk, Azure DevOps, HaloPSA and Autotask are configured on the same Connectors page and selected under Settings.

## Writing an adapter

Implement `IInventoryAdapter` (`src/VulnVerdict.Core/Adapters/Contracts.cs`): metadata (id, display name, what it sees, the credential form and the minimum permission), `TestAsync`, and `CollectAsync` returning asset, software, exposure and finding records. Register it in `AdapterRegistry`. The console builds the form from the metadata; nothing else changes.
