# Contributing to VulnVerdict

Thanks for looking. VulnVerdict is built for the one-person IT team, and the best contributions keep it that way: fewer knobs, plainer words, more sources seen with a read-only account.

## Ground rules

- **The digest is the product.** Anything that adds noise to the email needs a very good reason. Anything that removes noise while keeping the evidence is welcome.
- **Rules decide, models explain.** Do not put a language model, a heuristic score or a tunable weight on the path that produces a verdict. The decision table in `src/VulnVerdict.Core/Engine/DecisionTable.cs` is the only thing that decides, and every rule has a test.
- **Adapters are read-only, one credential form each.** They never write to the source, never log credentials, and state the minimum permission they need. See `docs/connectors.md` and `src/VulnVerdict.Core/Adapters/Contracts.cs`.
- **Not a scanner, not a patch tool.** Pull requests that add vulnerability probing or remediation actions will be declined with thanks.
- **Plain English.** No jargon in anything the customer sees by default. SSVC, EPSS, KEV and CVSS appear only on the Explain section.

## Before you open a pull request

1. `dotnet build` and `dotnet test tests/VulnVerdict.Tests` pass. New adapters and feeds come with fixture-based tests; live tests are marked so they can be skipped offline.
2. Schema changes come with a migration for both providers: `src/VulnVerdict.Core/Data/Migrations/Sqlite` and `.../Postgres` (see `docs/install.md` for the `dotnet ef` commands). Migrations must be additive so an older image can roll back.
3. No hostnames, addresses, usernames or real credentials in fixtures. Use `example.local`, `192.0.2.x` and `00-11-22-33-44-55`.
4. British English, one idea per sentence, no marketing.

## Adding an inventory source

Implement `IInventoryAdapter`, register it in `AdapterRegistry.cs`, add fixtures and tests, and add a row to the table in `docs/connectors.md`. The console builds the credential form from your metadata; nothing else changes.

## Adding a vendor advisory feed

Implement `IFeed` under `src/VulnVerdict.Core/Feeds/Psirt/`, store rows in the `Advisory` table with the vendor's own affected and fixed statements, and register it. Say in the metadata what the feed reliably provides.

## Reporting bugs

The console has two shortcuts that fill an issue in for you, in your own browser, with nothing sent until you submit it:

- **A wrong verdict**: "Report it on GitHub" under the evidence chain on the verdict page opens the *Wrong verdict* form with the CVE, product, version, rule and evidence filled in, and asset names and addresses left out. Say what is actually true.
- **A connector problem**: "Report a problem" next to the connector opens the *Connector problem* form. An administrator can also download **Diagnostics** there: one collection run that changes nothing, saved with what the system's API returned and with credentials, device names, users, serial numbers and addresses replaced by placeholders. Look through it, then attach it.

Anything else: open an issue with the console version (Licence and updates page) and what happened. Never paste credentials or your asset list. Security problems in VulnVerdict itself go by email, as SECURITY.md describes.

## Support

Issues here are answered on a best-effort basis by the maintainers and the community. VulnVerdict is offered free and without warranty. For anything that does not fit an issue, or to get involved beyond one, email hello@ayrshirepixels.co.uk.

## Licence

VulnVerdict is licensed under the GNU Affero General Public License v3.0 (`LICENSE`). By contributing you agree that your contribution is licensed the same way. The VulnVerdict name and logo are trademarks of Ayrshire Pixels and are not covered by the software licence; see `TRADEMARK.md`.
