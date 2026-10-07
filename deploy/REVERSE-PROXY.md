# Running behind a reverse proxy

The reverse proxy guide (TLS, WebSockets, nginx, Caddy and Nginx Proxy Manager, TURN over TLS, delegation of an
identity domain) is now part of the operator handbook: [Reverse proxy and TLS](../docs/HANDBOOK.md#reverse-proxy-and-tls).
The examples stay here: [`nginx.conf.example`](nginx.conf.example) and [`Caddyfile.example`](Caddyfile.example).

- [What the proxy must do](../docs/HANDBOOK.md#what-the-proxy-must-do)
- [Nginx Proxy Manager (Portainer)](../docs/HANDBOOK.md#nginx-proxy-manager-portainer)
- TURN: [TURN over TLS through the proxy](../docs/HANDBOOK.md#turn-over-tls-through-the-proxy),
  [TURN (optional, for strict networks)](../docs/HANDBOOK.md#turn-optional-for-strict-networks)
- Voice ports and addresses: [Voice and video](../docs/HANDBOOK.md#voice-and-video),
  [Dynamic addresses and proxies like Cloudflare](../docs/HANDBOOK.md#dynamic-addresses-and-proxies-like-cloudflare)
- Delegation: [Identity domain and node host (delegation)](../docs/HANDBOOK.md#identity-domain-and-node-host-delegation),
  [SRV record](../docs/HANDBOOK.md#srv-record-instead-of-the-well-known-file), [Passkeys](../docs/HANDBOOK.md#passkeys),
  [Hosted nodes under one domain](../docs/HANDBOOK.md#hosted-nodes-under-one-domain)
- [Verify the proxy](../docs/HANDBOOK.md#verify-the-proxy)
