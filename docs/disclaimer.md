# Advisory notice

What a verdict is, and what it is not. This text also appears in the console at `/docs/disclaimer`, at the foot of every digest and weekly report, and on every verdict page.

**Verdicts are advice, not a guarantee.** VulnVerdict works each verdict out from public vulnerability data (the CVE Program, CISA, EPSS, exploit indexes, vendor advisories) and from what your connectors and watchlist report about your estate. Both can be incomplete, late or wrong: a vendor's affected-version list can be inaccurate, a connector can miss a host, a version string can be ambiguous, and a compensating control you rely on may be one the console has no way to see.

**No automated assessment can fully account for your environment.** Whether a vulnerability matters to you depends on configuration, network layout, who can reach what, and what you have already done about it. VulnVerdict makes its reasoning visible so a person can check it; it does not replace that person.

**Check the evidence before you act, and treat "not affected" with the same care as "fix today".** A missed match looks like silence. The evidence chain on every verdict, including the dismissed ones, exists so a bad match can be found.

**Decisions about patching, and their consequences, remain yours.** Applying, delaying or declining a fix is an operational decision for the people who run the systems.

**No warranty, no liability.** VulnVerdict is provided "as is", without warranty of any kind, and its authors and distributors accept no liability for any loss arising from its use or from reliance on its output, to the fullest extent permitted by law. The software licence (GNU AGPL-3.0, sections 15 and 16) says the same in longer words. Support subscriptions cover the services described in the subscription agreement and nothing else.

The short form, as printed on digests:

> Verdicts are advisory. They are worked out from public vulnerability data and what your connectors and watchlist report, and no automated assessment can fully account for your environment, configuration or compensating controls. Check the evidence before you act. Decisions about patching, and their consequences, remain yours. VulnVerdict is provided without warranty and its authors accept no liability for loss arising from its use.
