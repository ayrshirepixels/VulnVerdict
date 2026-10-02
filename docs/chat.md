# Teams and Slack

Optional. The console can post to a Microsoft Teams channel, a Slack channel, or both. Messages go out only: Teams and Slack run in someone else's cloud and cannot call back into an on-prem console, so a message has a link to the console and no buttons that act. To mark something done from a message, follow the link.

## What is sent

Choose under **Settings > Teams and Slack**:

| Event | When |
|---|---|
| A new Fix today | as soon as the worker has evaluated it, usually within a minute |
| Promotions and re-opens | a verdict promoted to Fix this week or Fix today, or re-opened at either |
| The daily digest | a short summary when the digest is due: the headline and the counts |
| Feeds overdue | at most once a day |

"Check these" verdicts (product matched, version not confirmed) are never announced.

A verdict message carries the verdict, the CVE, the product and version, the one-sentence explanation, the fix-by date, how many assets are affected and a link to the verdict. One CVE is one message however many machines it is on.

## What is not sent

Asset names and addresses stay on the box. A message says "Affected assets: 12", not which twelve; the explanation is the verdict's sentence with the asset cut off the front, and the wording of a compensating control (which is in its owner's words and may name a host) is replaced with "Lowered one step by a compensating control". If an asset name still turns up in the text, the explanation is dropped and the message says to open the verdict.

**Include asset names in chat messages** (off by default) adds an "Assets" line with up to five names. For a host known only by its address, the name is the address. Leave it off unless your Teams or Slack tenant is somewhere you are content to keep an inventory.

The link uses the **Console address** from Settings. With no console address the message is sent without a link.

## Teams

Teams retired Office 365 connectors; the console uses the Workflows (Power Automate) webhook that replaced them.

1. In the channel, open **Workflows** and choose the template **Post to a channel when a webhook request is received**.
2. Pick the team and channel, create the flow, and copy the URL it gives you.
3. Paste it into **Teams webhook address** and press **Save and test Teams**.

The body is a message with one Adaptive Card (version 1.4):

```json
{ "type": "message",
  "attachments": [ { "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": null,
    "content": { "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
      "body": [
        { "type": "TextBlock", "text": "Fix today: CVE-2024-21762", "weight": "Bolder", "size": "Medium", "wrap": true, "color": "Attention" },
        { "type": "TextBlock", "text": "Exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8.", "wrap": true },
        { "type": "FactSet", "facts": [
          { "title": "Product", "value": "Fortinet FortiOS 7.2.5" }, { "title": "Verdict", "value": "Fix today" },
          { "title": "Fix by", "value": "26 Sep 2026" }, { "title": "Affected assets", "value": "2" } ] } ],
      "actions": [ { "type": "Action.OpenUrl", "title": "Open in VulnVerdict", "url": "https://vulnverdict.internal/verdicts/..." } ] } } ] }
```

The old connector format (`MessageCard`) is not produced.

## Slack

1. Create a Slack app for your workspace (or use an existing one), switch on **Incoming Webhooks** and add a webhook for the channel.
2. Paste the URL (`https://hooks.slack.com/services/...`) into **Slack webhook address** and press **Save and test Slack**.

The body is Block Kit with a plain `text` for notifications: a header, the explanation, the facts as fields, and the link as text. The link is not a button, because Slack reports button presses to the app that posted them and there is no app to answer.

## The addresses are secrets

Anyone holding a webhook address can post to the channel, so both are stored encrypted with the console's data-protection keys, like the mail password, and are never shown again: the field says "saved - leave blank to keep". Only an administrator can set, test or remove them. The address is not written to the audit log, the outbox or any error message.

## Delivery

A message is queued in the database in the same transaction as the change it reports and sent by the worker, so it survives a restart and does not matter which container noticed the change. A message that fails is retried after 30 seconds, then 1, 2, 4, 8, 16 and 32 minutes (longer if Teams or Slack answers 429 with a Retry-After). After eight attempts it is given up: the console shows a banner, and the administrator alert address gets an email, the same as for a digest that could not be sent. The banner clears when a later message gets through, or after a week. A verdict that is closed before its message goes out is not announced.

The Test button sends one message straight away and does not retry.

## Air-gapped sites

A console fed by uploaded bundles with no bundle URL is in air-gap mode: the site has no route out by choice, so nothing is sent to Teams or Slack, queued messages are dropped rather than held, and Settings says so. The settings are kept. Messages start again if the console goes back to pulling its own feeds (seven days after the last uploaded bundle) or is given a bundle URL.

Outbound HTTPS is needed to the host in each address: for Slack `hooks.slack.com`; for Teams the host in the workflow's URL, which varies by region.
