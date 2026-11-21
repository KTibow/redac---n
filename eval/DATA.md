# The data outside the repository

The repository holds the synthetic corpora (`eval/corpora/`, gzipped) and nothing else. Everything measured on
third-party text reads it from a data root on disk, `$REDACT_CORPORA` or `~/.cache/redac---n`, and that directory is a
cache: delete it whenever you like.

| what | where it lives | how it gets to the data root |
|---|---|---|
| The built sets the scripts read: real text, CredData, the converted third-party sets | a store of compressed blobs, listed with their hashes in `eval/data.lock.json` | `pnpm data pull` |
| The raw downloads those were built from: repositories, dataset shards, archives | their own hosts, listed in `eval/sources.tsv` | `node scripts/sources.ts --fetch PATH` |
| The scanners the benchmarks compare against, and the Python environment | their releases and PyPI, pinned in `scripts/tools.ts` and `eval/requirements.txt` | `node scripts/tools.ts` |

## A fresh clone

    pnpm install
    pnpm data pull          # the everyday sets: 113 MB to fetch, 1.7 GB on disk
    pnpm eval

`pnpm data status` lists every entry, its size and whether it is here. `pnpm data pull PATH…` fetches entries by
name or by directory (`pnpm data pull built/test.jsonl final2`), `pnpm data pull --all` everything. A script that needs
a file that is not here says which `pull` fetches it; `pnpm eval` and `scripts/snap.ts` skip those parts instead.

The everyday sets are what `pnpm eval`, `scripts/snap.ts` and the model's rebuild read: `built/dev.jsonl` and
CredData. `pnpm test` and `pnpm check` need none of this.

For the benchmarks against other scanners, and to retrain the model:

    node scripts/tools.ts   # five scanner binaries and a Python environment, under the data root's tools/
    python3 -I eval/baselines.py --bin ~/.cache/redac---n/tools/bin --venv ~/.cache/redac---n/tools/venv …

## The store

Each entry of `eval/data.lock.json` is a file or a directory under the data root, with the SHA-256 of its content
(for a directory, of a tar of it). The content is stored once, zstd-compressed, as a blob named by that hash, so a
blob never changes and an old commit's lock still fetches the data that commit was measured on. `pull` checks the hash
of what it downloads before putting it in place, and leaves alone a local copy that differs from the lock (one
rebuilt and not yet pushed) unless given `--force`.

There are two stores, both Hugging Face dataset repositories:

- **public** (`KTibow/redact-corpora`): read without an account or a token. Every set a script reads is here, each
  under the licence of the source it came from; the repository's card names the sources and their licences, and says
  which publish none.
- **private** (`KTibow/redact-corpora-private`): the three archives of working notes (below). `pull` reads it with
  `$HF_TOKEN` or a saved `hf auth login`; without access those entries are reported and skipped. `pnpm data status`
  marks them.

`$REDACT_STORE` replaces both with one store, which can be a directory (a copy of the blobs on a disk).

## Changing the data

Build or change a set in the data root, then:

    pnpm data push built/newset --note "What it is and what reads it"
    git add eval/data.lock.json

`push` packs the entry, uploads the blob if the store doesn't have it, and rewrites the lock. `--everyday` makes a
plain `pull` fetch it; `--private` puts it in the private store, and it stays private however it is pushed later
(`forget` it first to publish it on purpose). It needs the `zstd` and `hf` commands
(`node scripts/tools.ts python` installs `hf` into the data root's `tools/venv/bin`) and a Hugging Face login that can
write to the store. `pnpm data forget PATH` takes an entry out of the lock.

## The raw sources

`eval/sources.tsv` has a row for every repository, dataset shard and archive that was downloaded: its URL, the commit
where one was pinned, the SHA-256 of each downloaded file, the licence its host publishes for it, and the day it was
fetched. `node scripts/sources.ts PATH` prints the rows under a path, and `--fetch` downloads them into the data root:
a prior-art project to read (`priorart/betterleaks`), or the inputs of a build script.

Not everything comes back as it was. The 44 repositories behind the first real-text sets (`repos/`, `final/repos/`)
were cloned at their default branch without recording the commit, the OSV dumps change daily, and the GitHub Actions
logs are deleted by GitHub after 90 days. That is why the built sets are stored and not rebuilt: a rebuild from today's
sources gives a similar corpus, not the one the model was trained on and the numbers were measured on.

## The archives

The three entries of the private store are not read by any script. `archive/eval-out` is a copy of `eval/out/`
(reports, snapshots and scanner results, which quote third-party text and so are not committed),
`archive/built-reports` is the blind scores, scanner logs and failure lists written beside each converted set
(`eval/HELDOUT.md` has their numbers), and `archive/work` is the scripts and notes of past experiments. To redraw a
chart from the stored scanner results:

    pnpm data pull archive/eval-out
    cp ~/.cache/redac---n/archive/eval-out/baselines-*.json eval/out/
