# Regression sets

Each file here is a set of inputs a reviewer generated to probe the edges of one rule after a change to it. The
file's prefix (`r15a` ... `r15k`) names the review that wrote it; the rest names what it probes (`r15a-argv`,
`r15f-bn`, `r15g-f4_run_veto_placeholder`). They are gzipped JSON Lines, as the other corpora are, so secret scanners
(GitHub's push protection among them) do not read the fake credentials in them.

## What they are for

They are a don't-get-worse fence, not a recall benchmark. Many of their "secrets" are values the library keeps on purpose
(a rule decided that `1337x` after `password:` or a run of repeated characters reads as a placeholder, not a credential),
or are plain guesses at where a rule should stop. Some sets recall under half of their secrets, and that is the
accepted state, not a defect. Do not score them for recall and do not read their numbers as quality: only a change in
which cases leak, are lost or are slow means anything.

`eval/check.ts` reads them for that. It scores them with the dev and adversarial sets and compares each case's leaked
secrets, lost keep values and slow cases with the committed `eval/baseline.json.gz`; it exits 1 on anything new.
Run `node eval/check.ts --update` to accept a change on purpose (and say why in the commit), and look at what the
fixed entries are before you do. `scripts/snap.ts` measures the same sets (with a real-text sample on top), for diffing two
versions by hand. `eval/run.ts` and `eval/all.ts` do not use these sets.

Because the sets are tied to the rule version a review probed, a case may stop being interesting when its rule is
redesigned. Delete such a case, then run `check.ts --update`.

## Case format

One JSON object per line, the `Case` of `eval/score.ts`:

- `id`: unique within the set, usually `<set name>-<n>`.
- `text`: the input, redacted whole.
- `secrets`: values that must not survive. A secret leaks if the whole value survives or, for 12 or more characters, a
  run of at least half of it (8 characters minimum) does.
- `keep`: values that must survive verbatim. A keep the library hides is a lost entry.
- `hint` (optional, about 2% of cases): `{"command": ...}` or `{"path": ...}`, where the text came from.
- `label`: free text, what the case probes. Only for readers. (`eval/score.ts`'s `Case` also allows `known`, `kind` and
  `context`; no regress case uses them.)

`eval/corpora/templates/FORMAT.md` describes the template markers the dev sets are filled from; the regress sets are
written out as final cases and have no templates.
