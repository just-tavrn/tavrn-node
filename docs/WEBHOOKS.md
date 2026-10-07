# Posting into tavrn through a webhook

A tavrn webhook is a URL (`https://<node>/api/v1/webhooks/<id>/<secret>`) that a service such as CI or monitoring
uses to post messages into one channel. Anyone who knows the URL can post; nobody can read through it. The rules are
in `protocol/APPLICATIONS.md` §6.1 (payload, limits) and §6.1a (encrypted channels).

## Unencrypted channels

Post the JSON payload:

```sh
curl -X POST "$WEBHOOK_URL" -H 'content-type: application/json' \
  -d '{ "content": { "type": "text", "body": "Deploy **v1.2** finished" }, "username": "CI" }'
```

## End-to-end encrypted channels

The person who creates the webhook chooses who seals the messages:

- **Sealed by the service** (default): the service encrypts every message itself, so the node never sees the text.
  It needs the code below.
- **Sealed by the node**: the service posts plaintext exactly as above, over HTTPS; the node encrypts it on arrival
  and stores only the encrypted message. The node sees the text at that moment, so its operator could read it.

For a webhook sealed by the service:

1. `GET $WEBHOOK_URL/inbox-key` returns `{ "epoch": 42, "public_key": "<base64url>", "algorithm":
   "x25519-xsalsa20poly1305-sealedbox" }`: the current public key of the channel's members. It changes whenever the
   channel's membership or keys change (an "epoch"); fetch it before every post or cache it for a short while.
2. Seal the payload `{ "content": { "type": "text", "body": "…", "embeds": [ … ] }, "username": "…" }` (UTF-8 JSON;
   `username` and `embeds` are optional) with libsodium's **sealed box** (`crypto_box_seal`) to that public key.
3. `POST $WEBHOOK_URL` with `{ "sealed": "<base64url of the box>", "epoch": 42 }`. Anything else is refused with
   `400 webhook.sealed_required`; `409 webhook.pending_key` means no member has published a key yet (a member has to
   open the channel once).

base64url is RFC 4648 §5 without padding. A key from a slightly older epoch still works: members of that epoch can
read the message, and the node accepts any epoch up to the newest one.

### Node.js (`libsodium-wrappers`)

```js
import sodium from "libsodium-wrappers";

const B64 = sodium.base64_variants.URLSAFE_NO_PADDING;

export async function postSealed(webhookUrl, payload) {
  await sodium.ready;
  const key = await (await fetch(`${webhookUrl}/inbox-key`)).json();
  const box = sodium.crypto_box_seal(JSON.stringify(payload), sodium.from_base64(key.public_key, B64));
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sealed: sodium.to_base64(box, B64), epoch: key.epoch }),
  });
  if (!res.ok) throw new Error(`webhook: ${res.status} ${await res.text()}`);
}

await postSealed(process.env.WEBHOOK_URL, { content: { type: "text", body: "Deploy **v1.2** finished" }, username: "CI" });
```

### Python (`pynacl`, `requests`)

```python
import base64, json, os
import requests
from nacl.public import PublicKey, SealedBox

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def post_sealed(webhook_url: str, payload: dict) -> None:
    key = requests.get(f"{webhook_url}/inbox-key", timeout=10).json()
    box = SealedBox(PublicKey(unb64url(key["public_key"]))).encrypt(json.dumps(payload).encode())
    r = requests.post(webhook_url, json={"sealed": b64url(box), "epoch": key["epoch"]}, timeout=10)
    r.raise_for_status()

post_sealed(os.environ["WEBHOOK_URL"], {"content": {"type": "text", "body": "Backup finished"}, "username": "Backup"})
```

### Go (`golang.org/x/crypto/nacl/box`)

```go
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/crypto/nacl/box"
)

func postSealed(webhookURL string, payload any) error {
	resp, err := http.Get(webhookURL + "/inbox-key")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var key struct {
		Epoch     int64  `json:"epoch"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(key.PublicKey)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("bad inbox key")
	}
	var pk [32]byte
	copy(pk[:], raw)
	msg, _ := json.Marshal(payload)
	sealed, err := box.SealAnonymous(nil, msg, &pk, rand.Reader)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"sealed": base64.RawURLEncoding.EncodeToString(sealed), "epoch": key.Epoch})
	post, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer post.Body.Close()
	if post.StatusCode >= 300 {
		return fmt.Errorf("webhook: %s", post.Status)
	}
	return nil
}

func main() {
	payload := map[string]any{"content": map[string]any{"type": "text", "body": "Nightly build green"}}
	if err := postSealed(os.Getenv("WEBHOOK_URL"), payload); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

### What sealing protects, and what not

Only devices that are members of the channel in that epoch (and members who later receive the epoch's keys through
the channel's history setting) can open the box. The node stores it, cannot open it, and never logs payloads. Two
limits remain (`protocol/ENCRYPTION.md` §5b): a malicious node could hand the service its own public key instead of the
members' key (the service cannot tell), and in "sealed by the node" mode the node sees each text once when it arrives.
Keep the webhook URL secret like a password; it also guards the key route.
