# Running behind a reverse proxy

The reverse proxy guide (TLS, WebSockets, TURN over TLS, delegation of an identity domain) is part of the operator
handbook: [Reverse proxy and TLS](../docs/HANDBOOK.md#reverse-proxy-and-tls). The examples live here:
[`Caddyfile.example`](Caddyfile.example), [`nginx.conf.example`](nginx.conf.example),
[`traefik.yml.example`](traefik.yml.example), [`apache.conf.example`](apache.conf.example) and
[`haproxy.cfg.example`](haproxy.cfg.example); Nginx Proxy Manager is configured in its web interface.

- [What the proxy must do](../docs/HANDBOOK.md#what-the-proxy-must-do)
- [Examples](../docs/HANDBOOK.md#examples) (Caddy, nginx, [Nginx Proxy Manager](../docs/HANDBOOK.md#nginx-proxy-manager), Traefik, Apache, HAProxy)
- TURN: [TURN over TLS through the proxy](../docs/HANDBOOK.md#turn-over-tls-through-the-proxy),
  [TURN (optional, for strict networks)](../docs/HANDBOOK.md#turn-optional-for-strict-networks)
- Voice ports and addresses: [Voice and video](../docs/HANDBOOK.md#voice-and-video),
  [Dynamic addresses and proxies like Cloudflare](../docs/HANDBOOK.md#dynamic-addresses-and-proxies-like-cloudflare)
- Delegation: [Identity domain and node host (delegation)](../docs/HANDBOOK.md#identity-domain-and-node-host-delegation),
  [SRV record](../docs/HANDBOOK.md#srv-record-instead-of-the-well-known-file), [Passkeys](../docs/HANDBOOK.md#passkeys),
  [Hosted nodes under one domain](../docs/HANDBOOK.md#hosted-nodes-under-one-domain)
- [Verify the proxy](../docs/HANDBOOK.md#verify-the-proxy)
