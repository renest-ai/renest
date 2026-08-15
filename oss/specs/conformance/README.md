# conformance · consistency fixtures

> Status: **placeholder skeleton.** The fixtures in this directory are still to
> be filled in; what exists today is the directory structure and this note.

`conformance/` is **part of the specification**, not an accessory to the test
suite. A hard lesson from early real-hardware runs: round-trip tests going green
is false comfort, because a fake environment structurally cannot reach the real
bugs. So a bad sample must be **a real nest that genuinely fails on older
code**, never a mock.

## Layout

```
conformance/
├── README.md      # this file
├── golden/        # valid sample: a miniature golden nest (a few MB of stand-in models, structurally identical to a real nest)
└── invalid/       # bad samples: at least one nest that MUST fail, for every lint error rule
```

## What is still to be delivered

- **`golden/`**: a miniature golden nest -- structurally identical to a real one,
  with stand-in models of a few megabytes -- that passes full `renest lint`
  validation, and that a generator script can rebuild deterministically (stable
  byte for byte).
- **`invalid/`**: one must-fail sample per existing `renest lint` error rule,
  such that lint goes red **and the rule identifier matches what was expected**.
  Rule ↔ bad sample ↔ the MUST statements in the specs are maintained in the same
  change: every MUST in the specs corresponds to at least one lint rule and one
  conformance bad sample.
- **`README.md`** (to be replaced): the list of samples, and which rule each one
  exercises.

## Authoritative references

Shape of the fixtures: [`../manifest.schema.json`](../manifest.schema.json).
Exit codes and validation semantics:
[`../restore-protocol.md`](../restore-protocol.md).
Worked samples: [`../examples/`](../examples/).
