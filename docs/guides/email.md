# Email Management Guide

## Prerequisites

Before setting up email, make sure:

- **Port 25 is open** -- Many cloud providers (AWS, GCP, Azure, Oracle) block outbound port 25 by default. You may need to request an unblock from your provider, or use SMTP relay (see below).
- **rDNS / PTR record is set** -- Your server's IP must have a reverse DNS record pointing to a hostname (e.g., `mail.example.com`). Set this in your VPS provider's control panel (Vultr, Hetzner, DigitalOcean, etc.), not in your domain DNS.
- **A domain with DNS access** -- You need to add MX, SPF, DKIM, and DMARC records.

Check if port 25 is open:

```bash
telnet smtp.gmail.com 25
```

If the connection times out, port 25 is blocked on your network.

## One-Click Install

DockPanel installs a complete mail server stack with one click.

1. Go to **Mail** in the sidebar
2. If the mail server is not installed, click **Install Mail Server**
3. DockPanel installs and configures:
   - **Postfix** -- SMTP server for sending and receiving email
   - **Dovecot** -- IMAP/POP3 server for reading email
   - **OpenDKIM** -- DKIM signing for email authentication

The installation takes about 30 seconds. It also opens the mail ports (25, 587, 465, 143, 993,
110, 995) in the firewall, sets Postfix's HELO name from your panel domain, and hands Dovecot
your Let's Encrypt certificate if the box has one.

### One thing DockPanel cannot do for you: reverse DNS

Set a **PTR record** for your server's IP, pointing at your mail hostname. Only whoever owns
the IP can do this -- your hosting provider, usually under "reverse DNS" in their control
panel. Without it receivers add a spam score for an unknown sending host no matter how good
your SPF, DKIM and DMARC are: on a freshly-installed test box, the missing PTR was worth 2.5
points on its own once everything else was correct.

## Add a Mail Domain

1. Go to **Mail** > **Domains**
2. Click **Add Domain**
3. Enter your domain name: `example.com`
4. DockPanel generates the DKIM keys and shows the DNS records you need to add

## DNS Records

After adding a mail domain, you must add these DNS records at your domain registrar or DNS provider.

**Read them from the panel, not from here.** Open the domain, go to the **DNS Records** tab, and copy each record — every field is copyable and each one is marked *published* or *missing* once you press **Verify DNS**. The values depend on your server's address and on the DKIM key generated for your domain, so a page like this one cannot state them without going stale.

This guide used to spell the records out, and every one of them was wrong in some way by the time you read it: it named the DKIM selector `default` when DockPanel has always used `dockpanel`, and it described the mail host as `mail.example.com` when the records DockPanel publishes use the domain itself. Following it produced a DKIM record that could never verify.

What the panel gives you, and why each one exists:

| Record | What it does |
|---|---|
| `A` | The address other mail servers connect to. Must not be proxied. |
| `MX` | Where mail for this domain is delivered. |
| `TXT` (SPF) | Authorises this server to send mail for the domain. |
| `TXT` (DKIM) | The public key receivers use to verify our signature. |
| `TXT` (DMARC) | Tells receivers what to do when SPF or DKIM fails. |

If DockPanel manages the domain's DNS zone, these are created for you when you add the domain — there is nothing to copy.

### Checking them

**Verify DNS** on the same tab checks that each record resolves *and points at this server*, rather than merely that something exists. A domain whose MX belongs to another provider is reported as such. See [What DockPanel checks for you](prerequisites.md) for the full behaviour, including what happens when a lookup cannot be run at all.

### DMARC policy

DockPanel suggests `p=quarantine`, which asks receivers to flag suspicious mail. Once you have confirmed everything works, tightening it to `p=reject` (block spoofed email outright) is a change worth making by hand at your DNS provider.

### SPF

DockPanel publishes `v=spf1 mx ip4:<server> -all`. The `mx` and explicit `ip4:` terms
authorise this server, and `-all` states that nothing else may send. There is deliberately
no `a` term: an `a` mechanism follows your domain's A record, so on a domain whose web
address is proxied — an orange-cloud Cloudflare record, say — it would authorise that
CDN's shared addresses to send as your domain. That is an authorisation nobody intended,
and receivers read a shared CDN address in an SPF record as a spam signal. If you also
send through a relay or a second host, add its `include:` or `ip4:` before the `-all`.

### Who signs outbound mail

OpenDKIM signs everything DockPanel sends, using the `dockpanel` selector published in
your DKIM record. Rspamd is installed to filter mail, not to sign it, and its signer is
switched off on purpose: left on, it looks for keys under `/var/lib/rspamd/dkim` under a
`dkim` selector, for which no DNS record exists, so any signature it produced could never
verify. Both facts are recorded in the daemon and the panel's own DNS hints so the
configuration does not drift back.

## Create Mailboxes

1. Go to **Mail** > **Mailboxes**
2. Click **Add Mailbox**
3. Enter:
   - **Email address**: `user@example.com`
   - **Password**: A strong password
   - **Quota** (optional): Storage limit in MB
4. Click **Create**

You can also create:

- **Aliases** -- Forward `info@example.com` to `user@example.com`
- **Catch-all** -- Route all unmatched addresses to a single mailbox
- **Autoresponders** -- Out-of-office or auto-reply messages

### Who may send as what

A mailbox may put its own address in the envelope sender, and any address at a
domain it has a mailbox on. It may **not** send as an address on a domain it
holds no mailbox on -- so on a server hosting mail for several customers, one
customer cannot send mail claiming to be another, and cannot borrow the other's
DKIM signature by doing so. Postfix answers such an attempt with
`553 5.7.1 Sender address rejected: not owned by user`.

The rule is an **allow-list**, and that is the part worth reading twice: an
authenticated client may use an envelope sender only if it is a mailbox on this
server, or sits at a domain hosted on this server. Anything the server does not
host is refused -- not ignored.

The case that trips people is a **subdomain**. `shop.example.com` is a different
domain from `example.com`. If you host `example.com` and try to send as
`orders@shop.example.com` without adding the subdomain as its own mail domain,
that send is refused. Add it as a mail domain, or send as an address at a domain
you already host.

Consequences worth knowing before you design around it:

- Mailboxes **inside one domain** may send as each other, and as any address at
  that domain. They belong to the same customer, so this is not a boundary
  DockPanel tries to enforce -- if you need per-mailbox sender restrictions
  within a single domain, that is not something this provides.
- You cannot use this server as an authenticated relay for a domain it does not
  host. If you need that, host the domain here or relay through a provider that
  is authoritative for it.
- The check applies only to **authenticated** submission. Mail arriving from the
  internet with one of your domains in the envelope sender is unaffected, which
  is what keeps mailing lists, forwarders and third-party senders working. Use
  SPF and a DMARC policy for that direction; see [DNS Records](#dns-records).
- Sites' PHP `mail()` and anything else using the local `sendmail` command are
  unaffected -- local submission never passes through these restrictions.
- If you point the panel's own **SMTP relay at this same server**, authenticate
  as an address on the domain you send from. Authenticating as one mailbox and
  sending as an unrelated address is now refused, the same as it would be for
  any other customer.

This is applied automatically. A server already hosting mail picks it up the
next time you add or change a mailbox, alias or domain. Re-running the mail
installer is safe: it keeps the sender list a running server already has, and on
a server with no mailboxes yet it leaves the check disarmed rather than arming
it against an empty list -- which would have refused every authenticated send on
the box until the next mailbox change.

## Test Sending and Receiving

### Test sending

Send a test email from the server:

```bash
echo "Test from DockPanel mail server" | mail -s "Test Email" recipient@gmail.com
```

Or use the mail queue viewer in the panel (Mail > Queue) to monitor outgoing messages.

### Test receiving

Send an email from an external account (Gmail, Outlook) to `user@example.com` and check:

1. The mailbox in the panel (Mail > Mailboxes > user@example.com)
2. Or connect with an IMAP client (Thunderbird, Outlook) using:
   - **IMAP server**: `mail.example.com`
   - **Port**: `993` (SSL/TLS)
   - **Username**: `user@example.com`
   - **Password**: The mailbox password

### Verify DNS records

Press **Verify DNS** on the domain's DNS Records tab — that checks the records point at *this* server, which a raw lookup cannot tell you.

To check by hand, substituting your own domain (and noting that DockPanel's DKIM selector is `dockpanel`, not the `default` many guides assume):

- **MX**: `dig MX example.com +short`
- **SPF**: `dig TXT example.com +short`
- **DKIM**: `dig TXT dockpanel._domainkey.example.com +short`
- **DMARC**: `dig TXT _dmarc.example.com +short`

Use [mail-tester.com](https://www.mail-tester.com) to check your overall email deliverability score.

## SMTP Relay

If your provider blocks port 25 (most cloud providers do), configure an SMTP relay to send email through a third-party service.

Supported relay providers: SendGrid, Mailgun, Amazon SES, Brevo, or any SMTP server.

1. Go to **Mail** > **Settings**
2. Enable **SMTP Relay**
3. Enter relay credentials:
   - **SMTP host**: `smtp.sendgrid.net`
   - **Port**: `587`
   - **Username**: `apikey`
   - **Password**: Your SendGrid API key
4. Save

DockPanel configures Postfix to route all outbound email through the relay. Incoming email still arrives directly to your server (port 25 inbound is not blocked by providers, only outbound).

## Webmail (Roundcube)

Roundcube provides browser-based email access. There are two ways to install it, and they do
not behave the same.

### On its own domain (recommended)

1. Go to **Docker Apps**
2. Search for **Roundcube**
3. Click **Deploy**
4. Set a domain (e.g., `webmail.example.com`)

Your users then read their mail at `https://webmail.example.com`. Prefer this. Roundcube expects
to own the root of the site it is served from, and giving it its own hostname avoids the problem
below entirely.

### Under `/webmail/` on the panel domain

The **Mail** page can also install Roundcube as a path on the panel's own domain. It is quicker to
set up and needs no second DNS record.

> **Known issue (v2.36.0).** Installed this way, the message list can render empty even though the
> mailbox has mail in it — a frame is navigated to the panel root, whose security policy refuses
> it, and the error stops the list from loading. Logging in, IMAP, POP3 and delivery are all
> unaffected, and any desktop or phone mail client works normally against the same account. If you
> hit this, deploy Roundcube on its own domain as described above.

## Mail API (send from your apps)

DockPanel runs a small REST service for sending mail from applications, so a script or app
does not need to hold a mailbox password. Every message is injected locally, which means it is
DKIM-signed and delivered on the same path as mail sent from the webmail — and a copy is filed
into the sender's **Sent** folder, so it shows up in Roundcube like any other message.

### Getting a token

1. Open the panel and go to **Mail**
2. Under **Mail API — Tokens & Permissions**, type the mailbox's address under *Mint a token for
   a mailbox*
3. Tick the permissions the token should have, give it a label if you like, and click
   **Create token** — it is shown only once

A token belongs to the mailbox you name and can only send as that address. Rotate or revoke it
from the same card when it is no longer needed.

### Permissions

A token carries its own permissions, from a catalog of two:

| Permission | Grants |
|---|---|
| `me` | `/v1/me/*` and `/v1/send` — manage and send as the token's own mailbox |
| `domain` | `/v1/domains/*` and `/v1/queue` — administer the whole server's mail |

`domain` implies `me`. A token's permissions are an **upper bound**: on every request the
service intersects them with what the mailbox is currently allowed, which is recorded per
mailbox as a *role* in the panel. Two things follow, and they are the point of the design:

* **A `/me`-only token stays `/me`-only**, even if its mailbox is an administrator's. An
  application gets exactly what it needs and no path to the rest of the server.
* **Revoking is immediate.** Move a mailbox off `mail-admin`, or drop an extra permission, and
  tokens already handed out lose `domain` on their next request — no need to hunt them down.

**Roles** are named permission bundles, managed on the same card. Two are built in and cannot be
edited or deleted:

| Role | Permissions |
|---|---|
| `mail-user` | `me` — the default for every mailbox |
| `mail-admin` | `me`, `domain` |

Add a custom role when a mailbox needs something between the two, then assign it (with any
extra permissions) under *Mailbox permissions*. A mailbox with no assignment gets `mail-user`.

### Sending

```bash
curl -X POST https://mail-api.example.com/v1/send \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"to":"someone@example.com","subject":"Hello","text":"Hi there"}'
```

`to`, `cc` and `bcc` accept a single address or an array; `html` is accepted alongside or
instead of `text`; `reply_to` is optional. `from` defaults to the token's own mailbox and is
refused if it names any other address. The reply carries the message's `Message-ID` and the
accepted recipient list.

The same endpoint also accepts the panel's own JWT as a bearer token, for server-side callers
that already hold one.

### Endpoint

The API is published at `mail-api.<domain>` as an ordinary DockPanel **site** — runtime *proxy*,
forwarding to `127.0.0.1:8081` — so it appears under **Sites** and its certificate is issued and
renewed like any other site's. The service itself listens on loopback only. Tokens are stored
(hashed, never in the clear) in the panel's own database, which the service reads directly to
authenticate a request. Roundcube's own `dockpanel_mailapi_tokens` table is still honoured for
tokens minted before the panel took over, but only at `me` — see **Permissions** above.

### API reference

The service documents itself:

* **`/docs`** — a Swagger UI listing every route with its request and response bodies, and a
  **Try it out** button that takes your token. E.g. <https://mail-api.dsm-groups.com/docs>.
* **`/openapi.json`** — the same description as a machine-readable OpenAPI 3.0 document, for
  code generators and client tooling.

Both are served by the daemon itself: the spec is compiled into the binary rather than served
from disk, so it cannot come to describe a different build than the one answering requests. They
are unauthenticated, like `/health` — a description of the API is not access to it, and every
route they document still demands a bearer token.

### Managing mail

The same token manages as well as sends. What it may do follows from the **permissions it carries**,
bounded by what its mailbox is currently allowed, and there are two levels:

* **Its own mailbox** — the `me` permission, which every token has. Read and change the display
  name, password, forwarding and the out-of-office reply; list, create and delete folders and
  read, save, move and delete the mail in them; read quota usage.
* **The whole server** — the `domain` permission, granted per token in the panel. This is opt-in
  on purpose: a token is handed to an application, and a permission is not an address.

`GET /v1/me` reports the permissions your token currently holds.

Webmail's **Settings → Mail API** tab lists a mailbox's tokens, read-only, so you can see what
exists and when each was last used; creating and revoking happens in the panel.

Self-service, with any token:

| Method | Path | Body |
|---|---|---|
| `GET` | `/v1/me` | — |
| `PUT` | `/v1/me` | `{"display_name": "…"}` |
| `POST` | `/v1/me/password` | `{"new_password": "…"}` |
| `GET`/`PUT` | `/v1/me/forward` | `{"forward_to": "…"}` — an empty string clears it |
| `GET`/`PUT` | `/v1/me/autoresponder` | `{"enabled": true, "subject": "…", "body": "…"}` |
| `GET` | `/v1/me/quota` | — |
| `GET` | `/v1/me/folders` | — |
| `POST` | `/v1/me/folders` | `{"name": "Archive"}`, or `INBOX/Sub` to nest |
| `DELETE` | `/v1/me/folders?name=Archive` | — |
| `GET` | `/v1/me/messages?folder=Sent` | — |
| `POST` | `/v1/me/messages` | `{"folder": "Drafts", "to": "…", "subject": "…", "text": "…", "flags": ["\\Draft"]}` |
| `GET` | `/v1/me/messages/{uid}?folder=Drafts` | — |
| `DELETE` | `/v1/me/messages/{uid}?folder=INBOX` | `permanent=true` expunges instead of trashing |
| `POST` | `/v1/me/messages/{uid}/move` | `{"folder": "Trash", "to": "INBOX"}` |
| `POST` | `/v1/me/messages/{uid}/flags` | `{"folder": "INBOX", "add": ["Seen"], "remove": ["Flagged"]}` |
| `POST` | `/v1/me/trash/empty` | — |
| `GET`/`POST` | `/v1/me/contacts` | `{"name": "Jane Doe", "email": ["jane@example.com"]}` |
| `GET`/`PUT`/`DELETE` | `/v1/me/contacts/{id}` | any subset of the contact fields on `PUT` |
| `GET`/`POST` | `/v1/me/contactgroups` | `{"name": "Friends"}` |
| `GET`/`PUT`/`DELETE` | `/v1/me/contactgroups/{id}` | `{"name": "Friends"}` on `PUT` |
| `PUT` | `/v1/me/contactgroups/{id}/contacts` | `{"contact_ids": [1, 2]}` |
| `GET`/`POST` | `/v1/me/identities` | `{"email": "me@example.com", "name": "Me", "standard": true}` |
| `PUT`/`DELETE` | `/v1/me/identities/{id}` | any subset of the identity fields on `PUT` |
| `GET`/`POST` | `/v1/me/responses` | `{"name": "Thanks", "data": "Thank you!", "is_html": false}` |
| `PUT`/`DELETE` | `/v1/me/responses/{id}` | any subset of the response fields on `PUT` |
| `GET`/`PUT` | `/v1/me/settings` | `{"language": "id"}` — merged; `null` removes a key |
| `GET` | `/v1/me/collected-addresses?type=1` | — |
| `DELETE` | `/v1/me/collected-addresses/{id}` | — |
| `GET` | `/v1/me/autocomplete?q=jane` | — |

The folder to delete is a query parameter rather than a path segment because folder names
legitimately contain `/`. `INBOX`, `Sent` and `Trash` are refused.

Messages are addressed the same way, by `folder`: `Drafts`, `Sent` and `Trash` are folders
rather than routes, so the same handful of calls reads and manages all of them — and every
other folder besides. `GET /v1/me/messages` reads a folder newest first by default, with
`limit` and `offset` over that order, and reports each message's `uid`, which is what the rest
of these take. A `uid` belongs to its folder: a message moved to another folder gets that
folder's next `uid`, so re-read it after a move.

That same call carries the search and the sort the bundled Webmail offers:

* `q=` is free text, matched across the fields `search=` names — the Webmail's own default of
  `subject`+`from`, or `subject`+`to` in `Sent`/`Drafts`. The tokens a Roundcube user types
  into the search box are understood here too: `from:alice`, `-to:bob`,
  `subject:"two words"`, `is:unread`, `is:flagged`, `larger:1M`, `smaller:500k`,
  `since:2024-01-01`, `older_than:1M`, `has:attachment`, and `OR` between two terms.
* `filter=` is the Webmail's filter dropdown — `unread`, `read`, `flagged`, `unflagged`,
  `answered`, `deleted`, `draft`, `attachment`, the `priority-*` names and their opposites,
  comma-separated to combine. `read=true|false` is the same thing for the read/unread case
  alone.
* `interval=1W` — or `1M`, `1Y`, and the negated `-1W`, `-1M`, `-1Y` — keeps mail from the last
  week, month or year, or older than that.
* `scope=sub` adds a folder's subfolders and `scope=all` reads every folder; each message then
  carries the `folder` its `uid` belongs to.
* `sort=date|arrival|subject|from|to|fromto|cc|size|none` picks the column, and `order=asc|desc`
  the direction — `date`/`desc` by default, where `date` is the `Date:` header and `arrival` is
  when Dovecot received the message. `fromto` is the Webmail's smart column (`to` in
  `Sent`/`Drafts`, `from` elsewhere), and `none` is Dovecot's own `uid` order (`order` still
  applies).

The search is run by Dovecot, so `body:` and `text:` do not pull every message body through the
API; the sort and the page are applied to what comes back.

* **Saving a draft** is `POST /v1/me/messages` with `folder: "Drafts"` and `flags: ["\\Draft"]`.
  It is not a send: the message is written into the folder and stays there. It takes the same
  fields as `/v1/send` — the same code builds both — except that no recipient is required.
* **A delete is a move to `Trash`.** `DELETE` with `permanent=true` expunges instead, and a
  message already in `Trash` is expunged either way. `POST /v1/me/trash/empty` clears the lot
  and answers with how much was in there.
* **Flags** are limited to the five IMAP system flags — `\Seen`, `\Answered`, `\Flagged`,
  `\Draft` and `\Deleted` — spelled with or without the backslash. The answer is the flags the
  mailbox holds afterwards rather than the ones you asked for, because `\Recent` is Dovecot's
  to set.
* A folder that the mailbox does not have is a `404` rather than an empty listing, so a typo
  cannot quietly look like an empty mail folder.

### Address book and settings

The address book and the settings are **Roundcube's own**. Contacts, their groups, sender
identities, canned responses, the preference blob and the addresses the Webmail collected all
live in the SQLite database the webmail already keeps for the mailbox — the same one the service
reads to authenticate a token minted before the panel took that over. There is no second store:
a contact added through the API is in the webmail's address book on the next page load, a
signature changed here is the one the compose window uses, and a contact added in the webmail
comes back from the API. (Tokens minted *now* live in the panel's database instead; see
**Getting a token** above.)

These routes need the mailbox to have signed in to the Webmail at least once, because that is
what creates its Roundcube account; before that they answer `404` and say so.

* **Contacts** — `GET /v1/me/contacts` lists them, newest change last, with `q=` free text
  matched across name, addresses, organisation, notes and the rest, `group=` to read one group,
  `sort=name|firstname|surname|email|changed` and `order=asc|desc`, and `limit`/`offset` over
  that order. `POST` adds one and `PUT`/`DELETE` change or remove it by `id`. The fields are
  `name`, `firstname`, `surname`, `organization`, `jobtitle`, `department`, `email`, `phone`,
  `mobile`, `street`, `locality`, `region`, `zipcode`, `country`, `website`, `notes`,
  `birthday` and `gender`; `email`, `phone` and `mobile` take either one value or a list. A
  `PUT` changes only the fields it names, and a delete is the same soft delete the webmail does.
* **Groups** — `GET`/`POST /v1/me/contactgroups` lists and creates them, `PUT` renames and
  `DELETE` removes one, and `GET /v1/me/contactgroups/{id}` answers with the group plus the
  `contact_ids` in it. `PUT /v1/me/contactgroups/{id}/contacts` replaces that membership
  wholesale; every id must be a contact the same mailbox owns.
* **Identities** — the `From` name, address and signature the webmail composes with. `GET`/`POST
  /v1/me/identities` lists and adds, `PUT`/`DELETE /v1/me/identities/{id}` change and remove.
  The first identity becomes the standard one, as does any created with `"standard": true`, and
  the last identity cannot be deleted — a mailbox needs one to send as.
* **Canned responses** — `GET`/`POST /v1/me/responses` and `PUT`/`DELETE /v1/me/responses/{id}`
  manage the storable replies the webmail can drop into a message.
* **Preferences** — `GET /v1/me/settings` returns the webmail's preferences as JSON, under
  Roundcube's own keys (`language`, `timezone`, `pagesize`, `message_sort_col`, and so on).
  `PUT` is a shallow merge: the keys you send are set and everything else is left alone, so a
  preference set in the webmail is not lost by setting an unrelated one here. A key sent as
  `null` is removed.
* **Collected addresses** — `GET /v1/me/collected-addresses` lists the addresses Roundcube
  saved on its own, `type=1` for the recipients of mail you sent and `type=2` for trusted
  senders, and `DELETE /v1/me/collected-addresses/{id}` forgets one.
* **Autocomplete** — `GET /v1/me/autocomplete?q=jane` returns `name`/`email` suggestions,
  contacts first and then collected addresses, deduplicated — what the webmail's recipient field
  offers.

```bash
# Add a contact
curl -X POST https://mail-api.example.com/v1/me/contacts \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"name":"Jane Doe","email":"jane@example.com","organization":"Acme"}'

# Search the address book
curl "https://mail-api.example.com/v1/me/contacts?q=acme&sort=name" \
  -H "Authorization: Bearer <TOKEN>"

# Read and change a preference
curl https://mail-api.example.com/v1/me/settings -H "Authorization: Bearer <TOKEN>"
curl -X PUT https://mail-api.example.com/v1/me/settings \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"language":"id"}'
```

Server-wide, with a token carrying the `domain` permission, or a panel API key:

| Method | Path |
|---|---|
| `GET`/`POST` | `/v1/domains` |
| `GET`/`PUT`/`DELETE` | `/v1/domains/{domain}` |
| `GET`/`POST` | `/v1/domains/{domain}/accounts` |
| `PUT`/`DELETE` | `/v1/domains/{domain}/accounts/{email}` |
| `GET`/`POST` | `/v1/domains/{domain}/aliases` |
| `DELETE` | `/v1/domains/{domain}/aliases/{id}` |
| `GET` | `/v1/queue` |
| `POST` | `/v1/queue/flush` |
| `DELETE` | `/v1/queue?id=<queue_id>` |

A mailbox that is not an admin gets `403` from each of these, naming its own address, rather
than a bare refusal.

```bash
# Add a mailbox
curl -X POST https://mail-api.example.com/v1/domains/example.com/accounts \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"email":"sales@example.com","password":"…","quota_mb":2048}'

# Point an alias at it
curl -X POST https://mail-api.example.com/v1/domains/example.com/aliases \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"source_email":"info@example.com","destination_email":"sales@example.com"}'
```

### A panel API key instead of a mailbox token

If you would rather not hand out a mailbox token, mint a **panel API key** under
**Settings → API keys** and use it as the bearer token. It is an ordinary panel credential,
so the panel's own authorization governs it — and since creating and deleting domains is an
administrator action, the key must belong to an admin account or those routes answer `403`.

The service needs such a key for its own use as well. It does not write the mail database
itself; it calls the panel's existing mail API, so that each operation exists in one place and
one policy governs both the UI and the API. Configure it once in
`/etc/dockpanel/mailapi.env`:

```
MAILAPI_BACKEND_API_KEY=dp_…
```

then restart the service (`rc-service dockpanel-mailapi restart`, or
`systemctl restart dockpanel-mailapi`). Without it the routes that only ask Dovecot
(`/v1/me/quota`, `/v1/me/folders`) still work, and the rest answer `503` with that
instruction.

The service reads the panel's own `DATABASE_URL` (from `/etc/dockpanel/api.env`) to look up
mail-API tokens and their permissions, so there is nothing else to configure for that. If the
database is unreachable it answers `503` on an authenticated request rather than falling back to
the webmail's token table — a broken connection must not look like a token that was narrowed.

## Spam Filter (Rspamd)

Rspamd provides spam filtering, greylisting, and DKIM verification for incoming mail.

1. Go to **Docker Apps**
2. Search for **Rspamd**
3. Click **Deploy**

Rspamd includes a web interface for viewing spam statistics and adjusting filter rules.
