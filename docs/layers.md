# Why each layer is there

Besides the values you give it, which are hidden wherever they appear, redac---n has six detectors and a decision
stage that reviews what they find. Each detector looks for a different kind of evidence, and each catches secrets
the others miss. This page shows what each one does, what only it catches, and what it costs in false redactions,
as measured by `node eval/layers.ts`.

The numbers come from the development sets (4,250 cases holding 6,424 secrets and 18,402 values that look like
secrets but aren't) and 58 M characters of ordinary text: agent trajectories and repositories with almost no
secrets, so nearly every redaction there is a mistake. The guessing model's training data comes from that same text,
so its numbers there are a little flattering. With everything on, redac---n catches 95.4% of the secrets, destroys
1.4% of the look-alikes and makes 5.2 redactions per million characters of ordinary text.

## What each layer does

In the table, "recall without it" is the full pipeline with only that layer turned off. The next two columns count
the secrets and look-alikes no other layer hides, and the last the redactions in ordinary text no other layer makes.

| layer | recall without it | secrets only it catches | look-alikes only it destroys | ordinary-text redactions only it makes |
|---|---:|---:|---:|---:|
| names | 84.1% (−11.3 points) | 788 | 20 | 1.75 per M characters |
| structure | 89.5% (−5.9) | 372 | 7 | 1.32 per M |
| random tokens | 90.0% (−5.4) | 362 | 140 | 0.62 per M |
| formats | 91.2% (−4.2) | 233 | 17 | 0.09 per M |
| where the text came from | 94.6% (−0.8) | 50 | 3 | 0.02 per M |
| encoded | 95.3% (−0.1) | 6 | 0 | 0 |

**Names** (`src/named.ts`) finds values under a credential's name, in every syntax: env files, YAML, JSON, INI,
code, flags, XML, tables, SQL rows, sentences. It's the biggest layer because most secrets in agent output have a
name next to them.

**Structure** (`src/structure.ts`) knows where secrets go in formats that have a place for them: a private key's
PEM block (judged by its contents, not its label), a URL's password, an `Authorization` header, a cookie, a
connection string, a command-line tool's password flag. These often have no name to read, or a name that public
values share: a `CERTIFICATE` block can hold a private key.

**Random tokens** (`src/unnamed.ts`; see [How it guesses](guessing.md)) is the only layer that finds a secret with
no name, format or structure around it: the key passed to `Client("…")`, a token in a neutral header, a value pasted
into chat. It's also wrong most often: 140 look-alikes, mostly random IDs and hashes, are destroyed by it alone,
which is why `guessing` is a setting.

**Formats** (`src/formats.ts`) recognizes 536 vendor token formats by their prefixes and shapes (`ghp_`, `sk-ant-`,
`xoxb-`, `AKIA…`). On its own it catches a third of the secrets, but most of those have a name next to them too, so
what only it catches is smaller. It almost never fires on ordinary text: 0.09 false redactions per million
characters.

**Where the text came from** (`src/commands.ts`, `src/secretfile.ts`) uses the hint. What `cat .env` printed is a
secret file, so every value in it is hidden; what `gh auth token` printed is a token. Few development cases come with
a hint, so it measures small here. It's the layer that hides a 7-character `SALT` nothing else would, and the one
that keeps a transcript safe when a tool prints a whole secrets file.

**Encoded** (`src/encoded.ts`) decodes base64 and hex and checks what they hold with the rest of the pipeline. The
development sets have few encoded secrets, so it measures little here. It's there because encoding hides the
evidence every other layer looks for: a base64'd `.env`, a Kubernetes Secret's data, an `xxd` dump of a key file.

## The steps around them

| step turned off | recall | look-alikes destroyed | ordinary-text redactions per M characters |
|---|---:|---:|---:|
| none (the full pipeline) | 95.4% | 1.4% | 5.2 |
| the random layer's vetoes | 96.5% | 7.8% | 73.8 |
| only its statistical vetoes | 96.4% | 3.8% | 31.8 |
| its reading of a token's context | 93.3% | 2.4% | 7.8 |
| the decision stage (`src/policy.ts`) | 95.6% | 2.9% | 5.8 |
| learning a value and hiding its repeats | 94.6% | 1.4% | 5.1 |
| hints | 94.7% | 1.3% | 5.2 |
| normalizing text first (colours, entities, line numbers, split literals) | 95.0% | 1.4% | 5.3 |

The vetoes keep the random layer usable: hashes, UUIDs, IDs, public keys and encrypted values are random too, and
without the rules that set them aside the layer would redact 14 times as much ordinary text. The decision stage
halves the look-alikes destroyed, whichever detector found them: placeholders, references, types, keys that are
public by design, version strings.

## Running it

    node eval/layers.ts [--guessing confident] [--every 10] [--no-real]

It scores every development set with each layer on its own, each layer left out and each step left out, and counts
the findings no other layer makes. The ordinary-text sample needs the external corpora (`$REDACT_CORPORA`); pass
`--no-real` without them.
