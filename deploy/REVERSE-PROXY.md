# Running behind a reverse proxy

tavrn speaks plain HTTP only (default port 8080). TLS, certificates and HTTP/2 are always handled by a
reverse proxy in front of it. This is mandatory, not optional: nodes only federate over HTTPS (the identity
domain's `/.well-known/tavrn` and the endpoints it names, see [Delegation](#identity-domain-and-node-host-delegation)).

The proxy has to do three things:

1. **Pass WebSockets through** (`Upgrade`/`Connection` headers) for `/api/v1/ws` and for the voice signaling
   under `/rtc` (`/rtc`, `/rtc/v1`; the HTTP checks `/rtc/validate` and `/rtc/v1/validate` are plain GETs).
   Use a long read timeout (an hour): both are long-lived connections.
2. **Set `X-Forwarded-For`.** tavrn only trusts the header when the connection comes from an address in
   `TAVRN_TRUSTED_PROXIES` (default: private networks and localhost). If your proxy lives elsewhere, add its
   address, otherwise rate limits and bans apply to the proxy address instead of the client.
3. **Allow large bodies**, at least as large as `TAVRN_UPLOAD_MAX_BYTES`.

## Voice and video

- **Signaling** goes through the proxy like everything else: `wss://<domain>/rtc`. tavrn checks the LiveKit
  token of every connection (signature, expiry, and that its holder may still join the channel or call) before it
  forwards it to LiveKit, which listens on `127.0.0.1:7880` inside the container only. Do not publish or proxy
  port 7880, and do not route `/rtc` anywhere but to tavrn.
- **Media** does **not** go through the proxy. Publish and forward (router port forwarding to the host running
  the container, firewall open) these ports 1:1 — same numbers outside and inside, because LiveKit announces them:

  | What | Port(s) | Setting |
  |---|---|---|
  | Media | UDP `61000-61100` | `TAVRN_RTC_UDP_PORT_RANGE` (keep it outside the Linux ephemeral range 32768-60999, or random outgoing UDP sockets on the host block the publication) |
  | ICE over TCP (fallback when UDP is blocked) | TCP `7881` | `TAVRN_RTC_TCP_PORT` (0 = off) |
  | TURN over UDP (optional) | UDP `3478` | `TAVRN_RTC_TURN_UDP_PORT` with `TAVRN_RTC_TURN_ENABLED=true` |

  `docker-compose.yml` publishes the first two; the TURN line is commented out.
- **Addresses** (protocol/VOICE.md §10.2): LiveKit tells clients where to send media. Inside Docker the container
  only knows its private addresses, so the node announces either the public addresses detected via STUN at start
  (IPv4 and IPv6, default) or the ones you configure: `TAVRN_RTC_EXTERNAL_IP` (public IPv4) and
  `TAVRN_RTC_ADVERTISE_IPS` (more, comma-separated). Both also accept hostnames (dynamic DNS, see below). The
  startup log line `LiveKit starting media=…` lists what is announced and which ports are open; compare it
  with the router.
- **Clients in the same network as the node** reach the public address only if the router supports NAT loopback
  ("hairpin NAT"). Many home routers do not; then put the host's LAN address into `TAVRN_RTC_ADVERTISE_IPS`
  (e.g. `TAVRN_RTC_ADVERTISE_IPS=192.168.0.23`): clients add it as an extra candidate, LAN clients connect directly,
  others ignore it. IPv6 avoids the problem entirely (no NAT), see the next point.
- **IPv6**: Docker's default bridge network has no IPv6, and an IPv6-enabled network gives the container only a
  private ULA (`fd…`) — announcing that is useless. Give the network an IPv6 subnet (the commented `networks:`
  block in `docker-compose.yml`), so Docker publishes the ports on the host's global IPv6 as well, open them in the
  host firewall (IPv6 needs no port forwarding on the router, but the router's IPv6 firewall must allow inbound
  traffic to the host for these ports), and let STUN detect the global address or add it to
  `TAVRN_RTC_ADVERTISE_IPS`. The node never announces link-local addresses (`fe80::`).
- `/api/v1/voice/webhook` receives LiveKit's events from inside the container; requests from outside are
  rejected unless signed with the node's LiveKit secret, so the proxy does not need to block it (it may).

**Connection test**: in the web client, *Settings → Voice & video → Test connection* tries every path from the
current device (UDP to each announced address, TCP, TURN) and says which failed and what to check. Run it once from
inside the LAN and once from a phone on mobile data.

Check from outside: `curl -s https://chat.example.org/rtc/validate` must answer `401` with the code
`voice.token_invalid` (the proxy reaches tavrn, tavrn refuses without a token).

### TURN (optional, for strict networks)

Some networks (corporate Wi-Fi, some mobile carriers, hotel networks) allow nothing but outgoing HTTPS. For those,
enable LiveKit's embedded TURN server: `TAVRN_RTC_TURN_ENABLED=true`. Clients get short-lived TURN credentials
from LiveKit and relay their media through it; the relay reaches LiveKit inside the container, so no router
hairpin is needed.

- **TURN over UDP** (`TAVRN_RTC_TURN_UDP_PORT`, default 3478): publish and forward that UDP port. Helps behind
  symmetric NATs.
- **TURN over TLS on port 443** (`TAVRN_RTC_TURN_TLS_PORT`, default 5349): clients connect to
  `turns:<TAVRN_RTC_TURN_DOMAIN>:443` (default `turn.<TAVRN_DOMAIN>`). tavrn never terminates TLS, so the proxy does:
  give the TURN domain its own DNS record pointing at the proxy, a certificate for it, and a **TCP stream** that
  terminates TLS and forwards plain TCP to the container's TLS port (publish it on `127.0.0.1` only, see
  `docker-compose.yml`). Port 443 of the TURN domain must not be an HTTP virtual host at the same time. nginx:

  ```nginx
  stream {
      server {
          listen 443 ssl;                       # a separate IP, or use ssl_preread to share 443 (below)
          ssl_certificate     /etc/letsencrypt/live/turn.chat.example.org/fullchain.pem;
          ssl_certificate_key /etc/letsencrypt/live/turn.chat.example.org/privkey.pem;
          proxy_pass 127.0.0.1:5349;
          proxy_timeout 1h;
      }
  }
  ```

  To share port 443 with the web server, route by name with `ssl_preread` in a `stream` block in front: the TURN
  name goes to a TLS-terminating stream server on an internal port, everything else to the HTTPS server. Clients
  always use port 443 (LiveKit announces `turns:<domain>:443`). Nginx Proxy Manager: a *Stream* (TCP) listening on
  443 of an address its proxy hosts do not use, with an SSL certificate for the TURN domain (stream SSL needs a
  recent NPM release), forwarding to `tavrn:5349`. Without a TLS-terminating stream proxy, leave `TAVRN_RTC_TURN_TLS_PORT=0` and use TURN over UDP.
- Relays only go to LiveKit itself (loopback); the TURN server refuses every other private address, so it cannot be
  used to reach other machines in your network. Each participant may hold at most 12 relay allocations.

### Dynamic addresses and proxies like Cloudflare

Media ports cannot be proxied: HTTP reverse proxies and CDNs like Cloudflare forward neither UDP nor arbitrary TCP
ports, so the media path must reach your host directly. Keep the web/API/`/rtc` hostname behind the proxy if you
like, but use direct (DNS-only, "grey cloud") records for media. With a home connection whose address changes:

- **Hostname entries with dynamic DNS**: `TAVRN_RTC_EXTERNAL_IP=home.dyndns.example` (and/or hostnames in
  `TAVRN_RTC_ADVERTISE_IPS`). The node resolves them (A and AAAA) at start and every minute, or after the record's
  TTL if longer, announces their public addresses (private ones only with `TAVRN_RTC_ADVERTISE_PRIVATE=true`) and
  restarts LiveKit when they change; calls reconnect within the grace period. Give the record a low TTL (60–300 s)
  and keep it unproxied. If a name does not resolve the node keeps its last known addresses; if none ever
  resolved, `/healthz` shows `voice_problem` and LiveKit falls back to the STUN detection.
- **TURN with a hostname**: `TAVRN_RTC_TURN_ENABLED=true` with TURN over TLS, clients use
  `turns:turn.<host>:443` and resolve that name themselves at every reconnect, so a new address takes effect at the
  next reconnect without the node noticing. Give `turn.<host>` a low TTL; it must reach your TLS-terminating stream
  proxy directly (not through an HTTP-only CDN). This is the most robust path for rotating addresses and strict
  networks at once.
## Nginx Proxy Manager (Portainer)

Create a proxy host:

| Field | Value |
|---|---|
| Domain Names | `chat.example.org` |
| Scheme | `http` |
| Forward Hostname | `tavrn` (container on the same Docker network) or the host IP |
| Forward Port | `8080` |
| Websockets Support | **on** (covers `/api/v1/ws` and `/rtc`) |
| Block Common Exploits | on |
| SSL | request a Let's Encrypt certificate, enable **Force SSL**, **HTTP/2** and HSTS |

Under "Advanced" add: `client_max_body_size 100m;` and `proxy_read_timeout 3600s;`

If NPM shares a Docker network with the tavrn container, `tavrn` does not need a published TCP port (remove the
`8080` entry in `docker-compose.yml` and attach the tavrn service to NPM's network). The media ports (UDP range,
TCP 7881, optionally TURN) stay published on the host.

## nginx and Caddy

See `nginx.conf.example` and `Caddyfile.example`.

## Identity domain and node host (delegation)

The identity of a node is its domain (`TAVRN_DOMAIN`): addresses `alice@tavrn.org`, node keys, tokens. The node
itself may run on another host (`TAVRN_PUBLIC_URL`, default `https://<TAVRN_DOMAIN>`), for example because the
domain already carries a website:

```bash
TAVRN_DOMAIN=tavrn.org                 # addresses alice@tavrn.org
TAVRN_PUBLIC_URL=https://app.tavrn.org # where the web client and the API live
# TAVRN_WEBAUTHN_RP_ID=tavrn.org       # the default; passkeys keep working if the app host moves later
```

The node serves its discovery document on its own host as usual; it names `domain: tavrn.org` and the endpoints
on `app.tavrn.org`. Clients and other nodes always resolve the identity domain first:
`https://tavrn.org/.well-known/tavrn`. So the website on `tavrn.org` has to answer that one path (CORS-open,
`application/json`). There are two ways:

1. **Reverse-proxy rule (preferred)**: forward `/.well-known/tavrn` of the website to the node. The document
   always carries the current node keys, so key rotation needs no further step.

   nginx (in the `server` block of `tavrn.org`):

   ```nginx
   location = /.well-known/tavrn {
       proxy_pass https://app.tavrn.org;      # or http://127.0.0.1:8080 when the node runs on the same machine
       proxy_set_header Host app.tavrn.org;
       proxy_ssl_server_name on;
   }
   ```

   Caddy:

   ```caddyfile
   tavrn.org {
       handle /.well-known/tavrn {
           reverse_proxy https://app.tavrn.org {
               header_up Host app.tavrn.org
           }
       }
       # … the website
   }
   ```

   Do not redirect instead of proxying: nodes follow redirects only on the same host, browsers not at all.
2. **Static copy**: `docker exec tavrn tavrn-node well-known > well-known.json` prints the document; serve it as
   `/.well-known/tavrn` with `Content-Type: application/json`, `Access-Control-Allow-Origin: *` and
   `Cache-Control: max-age=300`. **Caveat**: the copy must be refreshed whenever the node keys change (rotation,
   compromise) and whenever settings in it change (name, registration, policies, capabilities). Peers cache it
   for at most an hour and refuse tokens signed with a key they do not find in it, so a stale copy breaks
   federation until it is updated. Prefer the proxy rule.

Check: `curl -s https://tavrn.org/.well-known/tavrn | jq '.domain, .api'` must print `"tavrn.org"` and
`"https://app.tavrn.org/api/v1"`.

Rules the node enforces (FEDERATION.md §1.3, §1.4): the document's `domain` must equal the queried domain; the
endpoints must be `https` (and are checked against private addresses like the domain itself); peers cache them
as long as the document (5 minutes to 1 hour), and a cached endpoint that stops answering is resolved again at
once (at most once a minute), so a move takes effect at the next failure.

**SRV record instead of the well-known file**: you need EITHER the well-known on the identity domain OR a DNS
record, never both:

```dns
_tavrn._tcp.tavrn.org. 3600 IN SRV 10 0 443 app.tavrn.org.
```

Resolution order (FEDERATION.md §1.3 has the decision table): `https://tavrn.org/.well-known/tavrn` first; when the
website has no such file (404) or there is no HTTPS server on `tavrn.org` at all, the SRV record
(`TAVRN_FEDERATION_SRV_FALLBACK`, default on): the document is fetched from `https://app.tavrn.org:443/.well-known/tavrn`
(the node serves it on its own host) and must name `tavrn.org`; only then, after a 404, the direct
`https://tavrn.org/api/v1`. Other HTTP errors (5xx, 403, …) are errors. Browsers cannot query DNS records, so web
clients ask the node they were loaded from (`GET /api/v1/federation/resolve/tavrn.org`), which runs the same order:
the connect flow, invites and add links work with an SRV-only setup too. It relies on DNS (use DNSSEC where you
can); the conformance and key-consistency checks still apply.

**Passkeys**: the relying party id is `TAVRN_WEBAUTHN_RP_ID` (default `TAVRN_DOMAIN`), the origin the public URL.
The id must be the origin's host or a parent domain of it: `tavrn.org` covers `app.tavrn.org`, so with the
default a later move to `chat.tavrn.org` keeps every passkey. A public URL on an unrelated host
(`chat.example.net` for `tavrn.org`) needs `TAVRN_WEBAUTHN_RP_ID=chat.example.net`; the node refuses to start
otherwise. Changing the relying party id later invalidates all registered passkeys (users sign in with TOTP or a
recovery code and register them again).

Everything else that builds absolute URLs (mail links, invite and application add links, the OIDC redirect URI
`<public URL>/api/v1/auth/oidc/callback`, the LiveKit signaling URL, `turn.<public host>`) uses the public URL.

### Hosted nodes under one domain

A hosting service that runs nodes as `nodename.tavrn.org` gives every node its own identity domain
(`TAVRN_DOMAIN=nodename.tavrn.org`, `TAVRN_PUBLIC_URL=https://nodename.tavrn.org`, the default) and its own
well-known on its own host. They never collide with the delegation of `tavrn.org` itself (another domain,
another document, other keys). The node needs nothing special; the hosting service must enforce, before it
creates a node name:

- **Reserved labels**: `www`, `app`, `api`, `turn` (and `turn.<label>` names for TURN over TLS), `mail`, `smtp`,
  `imap`, `mx`, `ns1`/`ns2`, `cdn`, `static`, `assets`, `status`, `docs`, `blog`, `git`, `matrix`, `identity`,
  `auth`, `login`, `sso`, `id`, `account`, `accounts`, `well-known`, `localhost` and every label starting with
  `xn--` unless it is valid IDNA.
- **Impersonation block list** (case-insensitive, also with digits for letters like `0`/`o`, `1`/`l` and with
  hyphens removed): `admin`, `administrator`, `root`, `support`, `help`, `helpdesk`, `security`, `abuse`,
  `postmaster`, `hostmaster`, `webmaster`, `noreply`, `official`, `staff`, `team`, `moderator`, `mod`, `system`,
  `tavrn`, `billing`, `payment`, `verify`, `verification`, plus the names of well-known brands and of other
  chat services. Users see the domain as part of every address, so `support.tavrn.org` would read as the
  project's own support.
- Labels follow the node domain rules (lowercase `a-z0-9-`, 1–63 characters, no leading or trailing hyphen) and
  are never reused after a node is deleted (addresses and keys of the old node stay in other nodes' caches).

## Verify

```bash
curl -s https://chat.example.org/.well-known/tavrn | jq .domain   # discovery reachable
curl -s https://chat.example.org/readyz                             # {"ready":true,"database":true,"livekit":true,"cache":null}
curl -s https://chat.example.org/healthz                            # {"status":"ok","voice":"running"}
curl -s -o /dev/null -w '%{http_code}\n' https://chat.example.org/rtc/validate   # 401
```
