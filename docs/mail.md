# Mail

The console sends the daily digest, immediate Fix-today alerts, ticket emails and the weekly report. Choose how under **Settings > Mail**, then use **Save and send a test email**.

| Option | Use it when | Needs |
|---|---|---|
| SMTP server | you have a mail server or relay that accepts it (on-premises Exchange, a hosted relay, Mailgun, Amazon SES, Postmark, Google Workspace with an app password or its SMTP relay) | host, port, and a user name and password if the server asks for one |
| Microsoft 365 | your mail is in Exchange Online | an Entra ID app registration allowed to send as one mailbox; outbound HTTPS |
| SendGrid | you use SendGrid | an API key with Mail Send permission and a verified sender |
| Brevo | you use Brevo | a v3 API key and a verified sender |

## Microsoft 365

Exchange Online is retiring password sign-in for SMTP, so on Microsoft 365 use this option rather than smtp.office365.com. The console signs in as an app (client credentials) and sends through Microsoft Graph as the from mailbox. Nothing is saved to that mailbox's Sent Items.

1. **Pick the from mailbox.** A shared mailbox such as vulnverdict@yourdomain works well and needs no licence.
2. **Register an app.** Entra admin centre > App registrations > New registration, named VulnVerdict, single tenant, no redirect URI. Note the **Directory (tenant) ID** and **Application (client) ID**.
3. **Create a client secret.** Certificates & secrets > New client secret. Copy its **Value** (not its ID). Note when it expires: mail stops on that date until a new secret is entered.
4. **Allow it to send as that one mailbox, and nothing else.** In Exchange Online PowerShell (`Connect-ExchangeOnline`), with the app's client ID and the **Object ID shown on its Enterprise applications page** (not the App registrations page):

   ```powershell
   New-ServicePrincipal -AppId <client-id> -ObjectId <enterprise-app-object-id> -DisplayName "VulnVerdict"
   New-ManagementScope -Name "VulnVerdict mailbox" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'vulnverdict@yourdomain'"
   New-ManagementRoleAssignment -App <client-id> -Role "Application Mail.Send" -CustomResourceScope "VulnVerdict mailbox"
   ```

   This is Exchange's role-based access for applications: the app can send as that mailbox only. Do not also grant Mail.Send under the app registration's API permissions, which would allow it to send as every mailbox in the tenant. (The older route, granting Mail.Send there and limiting it with `New-ApplicationAccessPolicy`, still works but Microsoft now recommends the role assignment.) Changes can take up to an hour to apply.
5. **Enter the details** in Settings > Mail: Microsoft 365, the from mailbox, tenant ID, client ID and secret. Save and send a test email.

What the errors mean:

- *Microsoft 365 sign-in refused*: the tenant ID, client ID or secret is wrong, or the secret has expired.
- *403, may not send as*: the role assignment in step 4 is missing, does not include this mailbox, or has not applied yet.
- *404, not a mailbox in this tenant*: the from address is an alias, a group or a mailbox elsewhere; use a user or shared mailbox.

The appliance or container needs outbound HTTPS to login.microsoftonline.com and graph.microsoft.com.
