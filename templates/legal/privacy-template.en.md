# Privacy policy of {{node_name}}

> **This is a template, not legal advice. Review it with a lawyer before publishing.** Remove this notice only after that review.

Effective date: {{effective_date}}

This policy explains which personal data the tavrn node {{node_name}} at `{{node_domain}}` (the "node") processes, why, for how long, and which rights you have under the EU General Data Protection Regulation (GDPR).

## 1. Controller and contact (Art. 13(1)(a), (b) GDPR)

The controller is:

{{operator_name}}\
{{operator_address}}\
E-mail: {{contact_email}}

Data protection officer: [[OPERATOR: data protection officer, if any (name and contact); otherwise remove this line]]

## 2. Data we process

tavrn is an end-to-end encrypted chat. Your devices create and keep your private keys; **private keys never leave your devices**. The node therefore cannot read encrypted messages, encrypted voice and video, or encrypted files. It holds the following data:

- **Account:** username, e-mail address (optional, unless this node requires it), password hash (never the password), second factors if you set them up (TOTP secret stored encrypted, passkey public keys, hashed recovery codes), accepted terms version with time stamp, settings.
- **Profile:** display name, avatar, header image, bio, links, status and custom status text. Your profile is visible to other users.
- **Devices and keys:** your devices and their public keys (MLS key packages, device attestations) and, if you create one, an encrypted key backup the node cannot open.
- **Sessions and IP addresses:** active sessions (device, time of last use). IP addresses appear in the server logs and, for registrations, in the audit log.
- **Messages in unencrypted (plaintext) channels:** content, author, time, edits, reactions, attachments. The node can read these.
- **Encrypted messages:** the node stores only the ciphertext plus the metadata it needs to deliver them: author, time, list of mentioned users and attachment sizes.
- **Attachments and files:** files you upload. They are stored encrypted at rest on the node by default (`TAVRN_STORAGE_ENCRYPTION=on`); files in encrypted conversations are additionally end-to-end encrypted.
- **Voice and video:** media is relayed by the LiveKit media server running on the node. Voice and video are end-to-end encrypted; the media server forwards them without being able to decrypt them. Nothing is recorded. Your IP address is processed to transport the media; if the node's TURN relay is used, it relays your media through the node.
- **Search index:** the node indexes only plaintext channels for search. Encrypted conversations are searched only on your own device.
- **Presence and activity:** online status, idle state and an activity text you set (you can hide activity).
- **Social data:** friends, friend requests, blocks and direct-message requests, memberships in rooms, DMs and group DMs, roles.
- **Applications and bots** you create or install, their tokens and settings, and **incoming webhooks** you create.
- **Legal notices (takedown reports):** the report, the reported content's location, and the reporter's name, contact details and statements; answers and counter-notices of the affected user.

## 3. Purposes and legal bases (Art. 6 GDPR)

- **Providing the service** (account, messaging, voice, files, profile, search, federation you use): Art. 6(1)(b) GDPR (contract).
- **Security and abuse prevention** (server logs, audit log, rate limits, captcha, automatic spam protection, blocking abusive nodes): Art. 6(1)(f) GDPR. Our legitimate interest is a secure and usable service for all users.
- **Legal obligations** (handling notices of illegal content under the EU Digital Services Act and copyright notices under the US DMCA, keeping records of notices): Art. 6(1)(c) GDPR.
- **Consent** where we ask for it (for example an optional e-mail address, or link previews): Art. 6(1)(a) GDPR. You can withdraw consent at any time with effect for the future.

## 4. Federation with other nodes

tavrn is federated: users of different nodes can talk to each other. When you interact with users or rooms of another node, the following data leaves this node to that node:

- your address (for example `alice@{{node_domain}}`), your public profile and your public keys;
- messages and attachments you post in rooms hosted on other nodes (encrypted where the conversation is encrypted);
- notification hints (for example "new message for you") and deletion requests;
- legal notices about content hosted on another node, which we may forward to that node with the case data.

**Other nodes are run by separate, independent controllers** with their own privacy policies. We may block nodes (blocklist). When you delete content or your account, we forward deletion requests to the nodes involved; we cannot enforce that they comply, we can only request it and log the request.

## 5. Service providers and optional features

The operator keeps the paragraphs that apply to this node and removes the others.

**Hosting (optional – remove if not used).** The node runs on servers of [[OPERATOR: hosting provider, location]] under a data processing agreement (Art. 28 GDPR).

**E-mail delivery (optional – remove if not used).** E-mails (confirmation, password reset, notices) are sent through [[OPERATOR: SMTP provider, location]], which processes your e-mail address and the message.

**Captcha (optional – remove if not used).** Registration (and login, if enabled) is protected by Cloudflare Turnstile (Cloudflare, Inc., USA). Cloudflare processes your IP address and browser data to tell humans from bots. [[OPERATOR: transfer basis, e.g. EU-US Data Privacy Framework]]

**GIF search (optional – remove if not used).** GIF search uses [[OPERATOR: Giphy or Tenor]]. Your search terms are sent to that provider through the node; the node keeps the API key.

**Single sign-on (optional – remove if not used).** You can sign in with [[OPERATOR: OpenID Connect provider]]. The provider tells the node your user name, display name, e-mail address and group memberships.

**External file storage (optional – remove if not used).** Files channels may store their files on external S3-compatible or WebDAV storage at [[OPERATOR: storage provider, location]].

**Cache for several instances (optional – remove if not used).** When the node runs as several instances, they share a Valkey/Redis cache at [[OPERATOR: cache host, location]], which holds short-lived data such as presence and rate-limit counters.

**Link previews (optional – remove if not used).** When you post a link, the node fetches the page to create a preview. The linked website sees the node's IP address, not yours.

## 6. Retention

| Data | Retention |
|---|---|
| Access tokens | 60 minutes (`TAVRN_SESSION_ACCESS_MINUTES`) |
| Sessions (refresh tokens) | 90 days after last use (`TAVRN_SESSION_REFRESH_DAYS`); single sign-on sessions at most 7 days |
| Devices not used | deleted after 180 days without use (`TAVRN_DEVICE_STALE_DAYS`), never your only device |
| Messages | until deleted by you, a moderator or account deletion (section 7) |
| Attachments | until deleted; [[OPERATOR: attachment retention; default: kept (TAVRN_ATTACHMENT_RETENTION_DAYS=0), rooms can set a shorter period]] |
| Users of other nodes | deleted 90 days after their last federated login if nothing else ties them to this node (`TAVRN_FEDERATION_REMOTE_USER_RETENTION_DAYS`) |
| Legal notices | 3 years (1095 days, `TAVRN_LEGAL_NOTICE_RETENTION_DAYS`) |
| Deleted accounts | tombstone with reserved username for 30 days (`TAVRN_ACCOUNT_DELETE_GRACE_DAYS`) |
| Server logs (incl. IP addresses) | [[OPERATOR: log retention, e.g. 14 days]] |
| Audit log | [[OPERATOR: audit log retention]]; entries about you are pseudonymised when your account is deleted |
| Backups | [[OPERATOR: backup retention]] |

## 7. Your rights

**Access and data portability (Art. 15, 20 GDPR).** In the profile settings, "My data" downloads everything the node holds about you in readable form: a JSON archive plus a readable summary. You do not need to ask us.

**Rectification (Art. 16 GDPR).** You can correct your profile and account data in the profile settings.

**Erasure (Art. 17 GDPR).** "Delete account" in the settings offers two options:

1. **Default:** your account, profile, devices, keys, sessions, friends, DM memberships and applications are deleted immediately. Your messages stay visible as "Deleted user", without name, avatar or link to you.
2. **"Also delete my messages and files":** additionally, the content of your messages and your attachments are removed; a placeholder keeps conversations readable.

If an account was deleted by mistake, the operator can restore it within 30 days; after that the username becomes free again. Deletion requests are forwarded to the federated nodes involved (section 4).

**Restriction and objection (Art. 18, 21 GDPR).** Contact us at {{contact_email}}.

**Complaint (Art. 77 GDPR).** You can complain to a supervisory authority, for example [[OPERATOR: supervisory authority]].

## 8. Automated decision-making (Art. 22 GDPR)

We do not use automated decision-making with legal or similarly significant effect. An automatic spam limit temporarily mutes users who send floods of messages; this is a short technical protection, not such a decision.

## 9. Cookies and local storage

We use no tracking cookies and no analytics. The app stores your session tokens and the encrypted key store of the end-to-end encryption in your browser's local storage and IndexedDB. This is strictly necessary to provide the service you request (ePrivacy Directive, Art. 5(3)) and needs no consent.

## 10. Children

You must be at least [[OPERATOR: minimum age, e.g. 16]] years old to use this node.

## 11. Changes to this policy

We version this policy; the effective date is shown at the top. When we change it, we publish the new version at `https://{{node_domain}}/legal/privacy` and show it to existing users in the app. When the terms of service change, existing users are asked to accept the new version at their next sign-in.
