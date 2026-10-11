# Template format

Write JSON Lines, one template per line: {"id": str, "context": str, "hint"?: {"command": str} | {"path": str}, "text": str}.
`text` is realistic tool output / file content / chat with MARKERS where values go. You never write a credential value
yourself: a filler program generates every secret and every random-looking look-alike from the marker's shape.

Markers (the brackets are U+27E6 ⟦ and U+27E7 ⟧):
- Secret to generate: ⟦S:PREFIX|ALPHABET|LENGTH⟧, e.g. ⟦S:ghp_|b62|36⟧, ⟦S:|hex|64⟧, ⟦S:AKIA|upper_digits|16⟧, ⟦S:xoxb-|digits_dash|0⟧ (see shapes).
  ALPHABET is one of: b62, hex, HEX, lower, upper, lower_digits, upper_digits, b64, b64url, b58, digits.
  LENGTH counts characters after the prefix. Also allowed: ⟦S:PREFIX|ALPHABET|LENGTH|SUFFIX⟧ for a fixed suffix.
- Special secret shapes: ⟦S:uuid⟧, ⟦S:jwt⟧ (HS256, realistic payload), ⟦S:pem-rsa⟧ (multi-line PKCS#8 RSA private key, BEGIN to END),
  ⟦S:pem-ec⟧, ⟦S:openssh⟧ (OpenSSH private key block), ⟦S:human⟧ (human-chosen password like Seasons2025! or Tr0ub4dor&3),
  ⟦S:passphrase⟧ (4-6 lowercase words joined by spaces or dashes), ⟦S:slack-webhook⟧, ⟦S:discord-webhook⟧.
- Look-alike to KEEP (must survive redaction): ⟦K:sha1⟧, ⟦K:sha256⟧, ⟦K:sha512⟧, ⟦K:md5⟧, ⟦K:uuid⟧, ⟦K:ulid⟧, ⟦K:git-short⟧ (7 hex),
  ⟦K:sri⟧ (sha512-…= integrity), ⟦K:docker-digest⟧ (sha256:…), ⟦K:ssh-pub⟧ (ssh-ed25519 AAAA… comment), ⟦K:pem-cert⟧ (certificate
  block), ⟦K:pem-pub⟧ (public key block), ⟦K:jwt-public⟧ (a JWT meant to be public, e.g. an anon/demo key), and generic random
  look-alikes with the same PREFIX|ALPHABET|LENGTH grammar: ⟦K:pk_live_|b62|24⟧ (publishable key), ⟦K:|lower_digits|26⟧ (an ID).
- Mark text you wrote yourself as a secret or keep value: ⟦S=…⟧ (e.g. a weak human password you invent, or a test password),
  ⟦K=…⟧ (e.g. a placeholder like <your-api-key>, ${STRIPE_KEY}, an error message, a key NAME, a hostname). The marker is
  replaced by its content.
- Reuse the same generated value: give it a name the first time, ⟦S#db:human⟧ or ⟦K#img:sha256⟧, then write ⟦S#db⟧ / ⟦K#img⟧
  wherever it appears again (each occurrence is labelled). Encoded occurrences: ⟦S#db|url⟧ (percent-encoded), ⟦S#db|json⟧
  (JSON-string-escaped), ⟦S#db|b64⟧ (base64 of the value; the base64 text is labelled secret), ⟦S#db|basic:alice⟧
  (base64 of "alice:" + value, as in an HTTP Basic header).
- A literal ⟦ or ⟧ is not allowed elsewhere in text.

Labels: every S marker becomes a secret (must not survive), every K marker a keep (must survive verbatim). Don't mark
credential NAMES as secrets, only values. Don't put a K marker inside an S marker or vice versa.
