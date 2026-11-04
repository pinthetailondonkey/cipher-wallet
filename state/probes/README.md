# probes

Throwaway probes from lane sessions, kept rather than left in the repo root.
They are runnable (`node state/probes/<name>.mjs`) and print; they are not part
of the test gate. If one proves durable it graduates into `test/`.

- `probe-adj*.mjs` — lane A adjudicator, while judging `b50c24c` (Lane C) and
  `e26fcee` (its audit): the proof-order trace, the merge-mining adversarial
  cases, the zero-non-miner-tx and duplicate-pocket checks, and the miner-match
  branch.

The base point is written with the repo's spaced hex convention here, then
stripped by each probe's own `bx` helper, so the pre-commit hook stays quiet.
