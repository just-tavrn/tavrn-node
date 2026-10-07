# Operating a node

The operator guide of tavrn-node: everything beyond the quick start in the [README](../README.md). All
configuration variables are documented in [`deploy/.env.example`](../deploy/.env.example); the reverse proxy
(TLS, WebSockets, TURN over TLS, delegation of an identity domain) in
[`deploy/REVERSE-PROXY.md`](../deploy/REVERSE-PROXY.md); several instances of one node behind a load balancer in
[`SCALING.md`](SCALING.md); incoming webhooks for integrations in [`WEBHOOKS.md`](WEBHOOKS.md). The commands
below run in the directory that holds your `docker-compose.yml` and `.env`.

## Keys, backups and the storage key

**Back up the data volume** (`./data`, mounted at `/data`) together with the database. Besides uploaded
files it holds `keys/node-<kid>.pem` (the node's signing keys) and `keys/secrets.key` (32 random bytes that
encrypt data at rest, such as the users' TOTP secrets). Both are created at the first start. Losing
`secrets.key` makes every TOTP enrollment unusable (users then need a passkey, a recovery code or an admin
reset of their second factor); never replace or delete it.

**Stored files are encrypted at rest** (`TAVRN_STORAGE_ENCRYPTION=on`, the default): attachments, avatars,
headers, room icons, custom emojis and soundboard clips lie in `data/blobs` as AES-256-GCM ciphertext, each file
with its own key, and those keys are wrapped with the node's **storage key** `keys/storage.key` (32 random
bytes, mode 0600, created at the first start) and kept in the database (`blob_keys`). The node decrypts while
streaming a download, so the blob directory can be copied, synced or later moved to object storage without
exposing content. This protects the storage layer, it is not end-to-end encryption (the node holds the keys;
attachments of encrypted conversations are ciphertext anyway and are simply wrapped once more).
**Back up `keys/storage.key` together with the database and the volume: without it every stored file is
unreadable.** The node refuses to start when the file is missing or does not match the stored keys, instead of
creating a new one. Files written by older versions are encrypted in place in the background after the
start (resumable, about 32 MB/s, progress in the log). `TAVRN_STORAGE_ENCRYPTION=off` stores new files
unencrypted (for debugging only; encrypted files stay readable, a warning is logged at every start).

To rotate the storage key, stop the node, run the rotation, start it again and back up the new key file:

```bash
docker compose stop tavrn
docker compose run --rm tavrn tavrn-node rotate-storage-key
docker compose start tavrn
```

The rotation creates `keys/storage.key.next`, re-wraps every file key with it (the files themselves are not
re-encrypted, so it takes seconds) and then replaces `keys/storage.key`. An interrupted run is finished by
running it again; a node started in between reads files wrapped with either key. Because the files are not
re-encrypted, an old key together with an old database backup still opens the files of that time.

## Node administration

The first account registered on a node becomes node admin (plus anyone listed in `TAVRN_ADMIN_USERS`).
Node admins get a "Node administration" page in the client: overview and effective configuration, users
(disable, promote, room-creation grants, delete all content, reset a locked-out user's second factor), account invites for `TAVRN_REGISTRATION=invite`,
node-wide bans, reports (see "Moderation" below), other nodes with their conformance results (block, unblock, check)
and the node audit log.

## Moderation: reports and auto-moderation

What the node does is specified in [MODERATION.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/MODERATION.md).

- **Reports.** Members report messages, members and rooms from the context menus. Reports about room content land
  in the room's "Reports" settings tab (moderators with `moderate_members`); reports about direct messages, about
  users without a room, about rooms and about a room's owner land in Admin → Reports, where node admins also see
  every room report. Reporters are visible to moderators; the reported user is never told. For end-to-end encrypted
  messages the reporter can release the plaintext of the reported message and up to ten messages before it: the
  inbox shows it labelled "released by the reporter", the node cannot verify it. Plaintext messages are linked and
  snapshotted instead. The inbox offers shortcuts (delete the message, time out, kick, ban, delete the user's
  content) that run the normal moderation actions and note the report in the audit log.
  `TAVRN_REPORTS_RATE_PER_HOUR` (default 10) limits reports per user, `TAVRN_REPORTS_RETENTION_DAYS` (default 90)
  deletes resolved and dismissed reports with their evidence; admins can delete a report at any time.
- **Flood detection** (`TAVRN_AUTOMOD_BURST_LIMIT`, `TAVRN_AUTOMOD_TIMEOUT_MINUTES`) works everywhere, encrypted
  or not.
- **Content rules** only work where the node can read: unencrypted channels. Rooms define their own rules
  (room settings → Auto-moderation: word lists with `*` wildcards, link allow and block lists, exempt roles and
  channels, block, delete or timeout). As operator you can add node-wide lists that block in every unencrypted
  conversation: `TAVRN_AUTOMOD_WORDS_FILE=/data/automod/words.txt` (one term per line, whole words, `#` comments)
  and `TAVRN_AUTOMOD_LINKS=/data/automod/domains.txt` (one domain per line, subdomains included). Both files are
  read at start (at most 1 MiB and 10000 entries; `check-config` names problems); restart the node after a change.
  Matches are audited with the matched term, never the message text, and show up in the moderators' inbox.
- **The welcome channel** is the room's security log: its entries cannot be deleted or purged by anyone.
- **Room ownership** moves with room settings → Overview → "Transfer ownership" (the owner confirms with their
  password or passkey). Accounts that own rooms must transfer or delete them before they can be deleted.

## Voice and video

The node runs `livekit-server` (bundled in the image) as a supervised child process: it generates LiveKit's
API key once (`/data/keys/livekit.key`, back it up with the volume; a lost file is simply regenerated) and its
config at every start, restarts it with a backoff when it crashes and stops it on shutdown. `/healthz` reports
`"voice": "running"`, `/readyz` includes `"livekit": true`. What operators have to provide:

- **Ports:** signaling runs through the reverse proxy (`wss://<domain>/rtc`, WebSocket support on). Media uses
  the UDP range `TAVRN_RTC_UDP_PORT_RANGE` (default `61000-61100`) plus ICE over TCP on `TAVRN_RTC_TCP_PORT`
  (default 7881, the fallback when UDP is blocked), both published 1:1 to the container, **open in the firewall**
  (`ufw allow 61000:61100/udp`, `ufw allow 7881/tcp` or your cloud's security group) and forwarded by the router.
  LiveKit's own port 7880 stays inside the container. Every connected participant uses one or two ports of the
  range (one per WebRTC peer connection), so 101 ports carry about 50 participants node-wide.
- **Addresses:** LiveKit announces where clients send media: the public IPv4 and IPv6 detected via STUN at start,
  or `TAVRN_RTC_EXTERNAL_IP` plus `TAVRN_RTC_ADVERTISE_IPS` (e.g. the host's global IPv6, or its LAN address when
  the router has no NAT loopback for clients at home). Docker's container addresses are never announced. The start
  log names what is announced; the connection test in the voice settings checks it from any device.
- **Limits:** `TAVRN_VOICE_MAX_BITRATE_KBPS`, `TAVRN_VOICE_MAX_PARTICIPANTS`, `TAVRN_SCREENSHARE_*`, `TAVRN_CAMERA_*`;
  `TAVRN_VOICE_ENABLED=false` switches voice off completely (no LiveKit process).
- **Dropped connections:** a participant whose connection breaks stays in the channel as "reconnecting" for
  `TAVRN_VOICE_RECONNECT_GRACE_SECS` (default 45) while the client rejoins by itself; a join from another
  device of the same user replaces the first.
- **Firewalls of users:** for clients behind very strict NATs or firewalls enable the embedded TURN server
  (`TAVRN_RTC_TURN_ENABLED=true`: TURN over UDP on 3478 and/or TURN over TLS on port 443 through the proxy,
  see [deploy/REVERSE-PROXY.md](../deploy/REVERSE-PROXY.md)).

Voice is end-to-end encrypted (frame keys from the channel's MLS group); the node and LiveKit only forward
encrypted media. Details: [protocol/VOICE.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/VOICE.md), [deploy/REVERSE-PROXY.md](../deploy/REVERSE-PROXY.md).

## Profiles, presence and message requests

Users edit their profile under *Settings → Profile*: display name, avatar and profile header (PNG, JPEG,
GIF, WebP or a short MP4/WebM; the node crops and converts them, animated ones loop for up to ten seconds and
only move while someone hovers them or while the user speaks in voice), a short Markdown bio and up to ten
linked accounts (Steam, Battle.net, Xbox, PlayStation, Nintendo, Twitch, YouTube, X, Mastodon, a website; shown
as "not verified"). A click on a name or avatar opens the profile card. The footer card sets the status
(online, idle, do not disturb, invisible), a custom status and an activity; the client reports idle after ten
minutes without input. *Settings → Privacy & safety* sets who can message you (friends, friends and shared
rooms, everyone), hides your activity and lists the people you blocked with your private notes. Messages from
people who are not your friends wait under *Message requests* until you accept them; friend requests can carry
a short message. The "+" in the room list also joins rooms from an invite link or code.

Operators: the image contains a minimal static `ffmpeg` (6.7 MB). Uploads are limited to 20 MB and 30 seconds,
converted without network access with a 30-second limit per job, `TAVRN_MEDIA_WORKERS` (default 1) at a time;
results are at most 1 MB per variant for avatars and icons and 2 MB for headers. `TAVRN_MEDIA_FFMPEG=off`
turns the conversion off (static images only). `TAVRN_DM_POLICY` is the upper bound of what users may allow
(`friends`, `everyone_shared`, `everyone`; default `everyone`). Presence is kept per node: clients push it to
every node they use, nodes never forward it to each other.

## Whiteboard

Every conversation has a whiteboard: the 🖍 button in the header of a channel, DM or group DM opens it full
screen (Excalidraw: text, shapes, freehand, images). The one who opens it presents it; the others see a live
dot on the button and join on demand ("Join whiteboard session"), watch live with named cursors and can leave
again. Only the presenter edits until they open the board for everyone, grant single participants ("Who can
edit") or lock it again. The presenter sets a background color or image, keeps a personal library of scenes
(save, load, rename, delete; the current scene is saved every 30 seconds), and closes the board for everyone.
Anyone in the session can save the board as PNG or SVG or share it as an image into a channel or DM. Phones
pan and zoom the board with the usual gestures; the board's actions sit in the "⋯" menu there. In a voice call
the 🖍 control presents a board on your tile (instead of a screen share; one at a time): the others see a badge
and a live preview on your tile (and a badge in the channel list), join from the tile (or by double-clicking it) and get
it as a large tile they can focus, maximize or pop out into its own window. Changes travel
end-to-end encrypted like messages and are never stored on the node; scenes are stored encrypted on your home
node ([WHITEBOARD.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/WHITEBOARD.md)). Operators limit the library with `TAVRN_WHITEBOARD_MAX_SCENES` (default 50
scenes of at most 5 MB per user).

## Getting listed in the directory

Nodes find each other through **reference nodes** (`TAVRN_REFERENCE_NODES`, several comma-separated are
fine). The setting is empty by default; `deploy/.env.example` and `deploy/docker-compose.yml` set the project
owner's public test node as an example, which you may replace or remove. Without a reference node a node
neither announces itself nor pulls a node list; its Discover page then shows only the nodes that announce
themselves to it. With `TAVRN_DIRECTORY_LISTING=true` (the default) a node announces
itself to each of them at startup, every 6 hours and whenever a room is listed or unlisted. The reference
node verifies the announce against the node's own `/.well-known/tavrn` (it must be reachable over HTTPS
with a valid certificate, and federation must be on), then lists the node and fetches its discoverable
rooms from the node itself; every room comes with a listing the node signs, so no other node can forge
it. A node not heard from for 48 hours drops out of the list. Nodes also pull the node lists of their
reference nodes, so the Discover page of every node shows the whole directory.

- To be listed: keep `TAVRN_DIRECTORY_LISTING=true`, make sure the reference node can reach your
  `https://<domain>/.well-known/tavrn`, and let room owners mark public rooms as listed. Only rooms marked
  that way appear; the node's name and description come from `TAVRN_NAME` and `TAVRN_DESCRIPTION`.
- Not to be listed: `TAVRN_DIRECTORY_LISTING=false`. The node still federates and its users can still use
  Discover; other nodes refuse to list it.
- To run a reference node: there is nothing extra to switch on, every node accepts announces. Point other
  nodes' `TAVRN_REFERENCE_NODES` at your domain. `TAVRN_DIRECTORY_MAX_ROOMS` (default 5000) caps the cached
  rooms of other nodes (at most 200 per node). Announces are limited to one per domain every 10 minutes.
- Moderation: node admins remove a node or a single room from their directory with
  `DELETE /api/v1/admin/directory/nodes/{domain}` or `DELETE /api/v1/admin/directory/rooms/{node}/{room_id}`
  (undo with `POST /api/v1/admin/directory/relist`); delisted entries are neither shown nor passed on.
  Blocked domains (`TAVRN_FEDERATION_BLOCKLIST`, node bans of a domain) are never listed.
- A listing node lists itself: its own entry (built from `TAVRN_NAME`, `TAVRN_DESCRIPTION` and its
  discovery document) and its listed rooms appear in its own directory, so a reference node shows up in the
  lists other nodes pull from it.
- Reports: users report other nodes or their rooms from the Discover page ("Report"). Reports go to the
  admins of the user's own node, never to the reported node, and never block anything on their own: the
  Federation tab of the node administration shows the count per node and the reports, and removes a node
  from the directory from there. Three different users reporting the same node within 7 days leave a notice
  in the audit log. Each user can send 10 reports a day; reports are kept 180 days.

## Conformance checks of other nodes

A node checks the behavior of every node it federates with (not its code): shortly after the first
contact, then daily, and on demand ([FEDERATION.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/FEDERATION.md) §9). The checks use
the reserved system account `tavrn-conformance` (created at the first start, no password, hidden from user
lists; the username cannot be registered) and a throwaway room on the other node, and verify among other
things that forged, replayed, expired or misaddressed tokens are refused, that the inbox refuses unsigned
and tampered messages, that the MLS delivery service refuses stale, replayed and tampered commits, that
plaintext is refused in encrypted channels, and that logins are rate-limited.

- **Hard failures** (e.g. a forged signature is accepted) and spoofing seen in live traffic (a token for a
  user of another domain, a forged `from`, repeated tampered inbox messages) **block the node
  automatically**. A later check without hard failures lifts an automatic block. Warnings never block.
- `keys.consistent` also fetches the other node's discovery document from every address its domain resolves
  to (IPv4 and IPv6, several hosts): different keys on different addresses are a hard failure (a split view
  or an interception on one path). Roll out new signing keys to all hosts of a node at once.
- `TAVRN_FEDERATION_REQUIRE_CONFORMANCE=true` (default `false`) additionally refuses federated logins and
  inbox messages of nodes that were not checked yet (`503 federation.conformance_pending`, the check starts
  at once) or failed.
- The **Federation** tab of the node administration lists the known nodes with their result, failure and
  violation counts; it runs a check now, blocks and unblocks a node (all audited). The same over the API:
  `GET /api/v1/admin/federation/peers`, `POST …/peers/{domain}/check`, `…/block`, `…/unblock`.
- From the command line, with the node's configuration, keys and database (the node should be running, the
  other node claims the probe's keys from it):

  ```bash
  docker compose exec tavrn tavrn-node doctor --peer community.example
  ```

  prints one line per check (`pass`, `warn`, `fail`, `skip` with a reason) and exits with `1` on a hard
  failure (`2` if the check could not run). The result is stored like an admin's check.
- Users see a warning above the rooms of a node that failed the check of their home node; rooms of a node
  their home node blocks are not shown at all.

## SSO with Authentik/Keycloak

A node can sign users in through an OpenID Connect provider ([APPLICATIONS.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/APPLICATIONS.md)
§8): the login page gets a "Sign in with SSO" button, accounts are created on the first SSO login, and
provider groups can grant node admin rights, room creation grants and memberships with roles.

1. Create a confidential OAuth2/OpenID client at the provider with the **authorization code flow and PKCE
   (S256)** and register exactly this redirect URI: `https://<TAVRN_DOMAIN>/api/v1/auth/oidc/callback`.
   As post-logout redirect URI register `https://<TAVRN_DOMAIN>/login`. Sign ID tokens with RS256, PS256,
   ES256 or EdDSA (never HS256). Add a `groups` claim if you want the group mapping.
   - **Keycloak**: client type OpenID Connect, client authentication on, standard flow only, "PKCE method"
     S256. For groups add a "Group Membership" mapper (token claim name `groups`, "Full group path" off).
     Issuer: `https://keycloak.example/realms/<realm>`.
   - **Authentik**: provider type "OAuth2/OpenID Provider", client type confidential, signing key set (RS256).
     The default scope mappings include `groups`. Issuer: `https://authentik.example/application/o/<slug>/`
     (with the trailing slash, exactly as shown in the provider's overview).
2. Configure the node (secrets preferably through a file):

   ```bash
   TAVRN_OIDC_ISSUER=https://keycloak.example/realms/company
   TAVRN_OIDC_CLIENT_ID=tavrn
   TAVRN_OIDC_CLIENT_SECRET_FILE=/data/keys/oidc-client-secret
   # optional:
   TAVRN_OIDC_BUTTON_LABEL=Sign in with Company SSO
   TAVRN_OIDC_GROUP_MAP={"it-admins":{"node_admin":true},"staff":{"room_creation":5},"devs":{"rooms":[{"room":"01J…","roles":["01J…"]}]}}
   TAVRN_OIDC_GROUP_SYNC=add          # sync also revokes what an earlier sync granted (never manual grants)
   TAVRN_OIDC_ONLY=false              # true: password logins only for TAVRN_ADMIN_USERS (break-glass)
   ```

3. Check it: `docker compose exec tavrn tavrn-node check-config` fetches the
   provider's discovery document and keys and prints the redirect URI to register.

Notes: the issuer must match the provider's `issuer` exactly; provider requests use verified TLS, follow
no redirects and may target LAN addresses. SSO logins need no tavrn second factor (the provider is
responsible), but end-to-end encryption still asks for the recovery key on the first login. Existing password
accounts link their provider identity themselves in Settings → Security (the node never links by email or
username). Without `TAVRN_OIDC_GROUP_MAP` admins edit the mapping in Admin → SSO (rooms and roles are picked by
name; `PUT /api/v1/admin/sso/group-map` underneath);
group changes take effect at the next SSO login, at the latest after `TAVRN_OIDC_SESSION_DAYS` (default 7).
With `TAVRN_OIDC_ONLY=true` keep at least one account in `TAVRN_ADMIN_USERS`, so an outage of the provider
cannot lock you out; those names are never given to accounts created by SSO.

## Legal setup

Imprint, privacy policy, terms, takedown notices and the users' data rights ([LEGAL.md](https://github.com/just-tavrn/tavrn-protocol/blob/main/LEGAL.md)).
Nothing here is legal advice: you run the node and remain responsible for it.

1. **Designated contact.** Admin → Legal → "Contact for notices": name, postal address and e-mail of the person who
   receives notices (the DMCA designated agent and the DSA point of contact). For the US safe harbour, also register
   the agent with the US Copyright Office.
2. **Pages.** Admin → Legal: pick the document, "Insert template" (privacy policy in English or German, a German
   imprint, a terms skeleton from `templates/legal/`), replace every `[[OPERATOR: …]]` note, review the text with a lawyer,
   remove the template notice, publish. Check at least: controller and data protection officer, hosting provider,
   the third parties you actually use (SMTP, Turnstile and its transfer basis, GIF provider, SSO provider, external
   file storage, Valkey), attachment, log, audit log and backup retention, the supervisory authority, the minimum
   age; in the imprint the full postal address (no P.O. box), representatives, register and VAT numbers and the
   person responsible under § 18 Abs. 2 MStV. The pages appear at `https://<domain>/legal/<kind>` and behind the
   "Legal" link of every sign-in screen.
3. **Terms.** Once terms are published, registration asks for them. Each new version is shown to every user once;
   `TAVRN_LEGAL_TERMS_MODE=require` blocks accounts until they accept (declining signs out).
4. **Notices.** `TAVRN_LEGAL_NOTICES=on` opens the public form `https://<domain>/legal/notice` (captcha when
   configured, `TAVRN_LEGAL_NOTICE_RATE_PER_HOUR`). Cases appear in Admin → Notices: remove content (with a
   statement of reasons for the uploader), disable the account, reject, or forward to the node that hosts the
   content. Configure SMTP (`TAVRN_SMTP_URL`) so reporters and uploaders get their mails.
5. **Retention.** Cases are kept `TAVRN_LEGAL_NOTICE_RETENTION_DAYS` (default 1095 = 3 years) after their last
   change; export them as JSON from the Notices tab for your records. Deleted accounts can be restored for
   `TAVRN_ACCOUNT_DELETE_GRACE_DAYS` (default 30) in Admin → Users, then they are erased.
6. **Data rights.** Users download their data under Settings → Profile → "My data" and delete their account under
   Settings → Privacy & safety. On request you can do both for them in Admin → Users (your confirmation is required
   and audited).
