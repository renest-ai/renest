# specs · the Renest open format

> **Format before implementation; the format is the source of truth.** All three
> ends (the pod agent, the service, the desktop client) and the escape hatch
> `restore.sh` are **consumers** of this specification. Any format change must
> bump the version and update this directory, `restore.sh` and `renest lint`
> together.
>
> The escape hatch depends only on `curl`, `jq`, `sha256sum`, `tar` and `uv`, and
> rebuilds a complete nest without a single line of this project's other code.
> "An outsider can implement reading and writing from the documents alone,
> without using any of our code" is this directory's acceptance criterion, not a
> slogan.

## Version index

| Component | Version | Status | Document |
|---|---|---|---|
| manifest format | 2.3 | **frozen** | [`manifest.md`](manifest.md) + [`manifest.schema.json`](manifest.schema.json) |
| exit codes / `error_class` | — | frozen baseline | [`restore-protocol.md`](restore-protocol.md) |

Every document here has a Chinese twin alongside it, named `*.cn.md`. The plain
name is the English original; the twin is a translation. Where they disagree,
the English one is authoritative.

## Reading order

1. **[`manifest.md`](manifest.md)** — the field-by-field semantics of a nest
   manifest. Shape is authoritative in `manifest.schema.json` (JSON Schema draft
   2020-12, consumed directly by CI and `renest lint`); meaning is authoritative
   in `manifest.md`. The two are maintained in the same change.
2. **[`restore-protocol.md`](restore-protocol.md)** — the **only authority** for
   the exit-code table and the `error_class` vocabulary. Pre-gate codes 0/2/3,
   the S0 pre-flight (60–66), and the five stage gates S1..S5 (10–59), each with
   its name, whether it is retryable, who may produce it, and what it means;
   plus the one-line `RESTORE_FAIL` / `RESTORE_NOTICE` contract. The
   authoritative implementation is `../src/renest/errors.py`, and the two are
   locked code by code by `../tests/consistency/test_protocol_matches_code.py`.
3. **[`examples/`](examples/)** — samples that have been through real runs: three
   `*.nest.json` files (a minimal SDXL nest, a video-generation nest, and one
   showing the honest boundary around external API calls) plus one
   `*.pack-spec.json` packing template.
   The examples deliberately stay on an older minor version: they double as
   living evidence that **an older nest still reads on a newer reader**.
   `crossver-v1.1-draft.nest.json` exists **only as a historical specimen**:
   2.0 dropped 1.x read compatibility, and its job now is to pin down that an
   old nest must be refused explicitly, reporting an unsupported version rather
   than crashing somewhere else (see `../tests/unit/test_lint.py`).
   **Do not model a new nest on it.**
4. **[`conformance/`](conformance/)** — golden (must pass) and invalid (must
   fail) fixtures; see that directory's README.

## Layout

```
specs/
├── README.md                   # this file: guide plus version index
├── manifest.md                 # manifest semantics
├── manifest.schema.json        # manifest JSON Schema (authoritative for shape)
├── restore-protocol.md         # exit codes and error_class, the one authority
├── serve-api.md                # the local HTTP surface
├── examples/                   # verified nest and pack-spec samples
└── conformance/                # golden and invalid fixtures
    ├── golden/
    └── invalid/
```

> This directory is published. It is maintained to the hygiene standard of
> "everything in here is public": no keys, no internal business information.
