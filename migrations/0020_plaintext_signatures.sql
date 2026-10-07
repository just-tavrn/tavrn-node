-- Device signatures on plaintext messages (FEDERATION.md §10.3): base64url(nonce(16) || Ed25519
-- signature(64)) as sent by the author's device, NULL for encrypted and unsigned messages. The node
-- stores it unchanged and does not verify it (clients do).
ALTER TABLE messages ADD COLUMN signature TEXT;
