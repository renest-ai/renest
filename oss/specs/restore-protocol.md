# restore-protocol · the one authority for exit codes and `error_class`

> Status: **frozen baseline**. This file is the **only authoritative document**
> for the exit-code table and the `error_class` vocabulary. Every consumer -- the
> agent, the escape hatch `restore.sh`, the orchestrator, the telemetry parser --
> must follow this table. The authoritative implementation on the code side is
> `oss/src/renest/errors.py`; the two are locked to each other code by code, in
> both directions, by `oss/tests/consistency/test_protocol_matches_code.py`: if
> either side changes and the other does not, that test goes red.
>
> Format is the source of truth: changing any code is a format change and must
> bump the version and update this file, `errors.py`, `restore.sh` and the
> linter together. A new failure class may only take the next free unit digit
> **within its own band**; taking a number from another band is a breaking
> change and goes through the version process.
>
> **How to read that sentence** (settled so the argument does not restart with
> every addition): "changing any code" means **changing the meaning of an
> existing code** -- that is breaking and goes through the version process.
> **Adding a class on the next free unit digit inside its band is the
> non-breaking path this rule explicitly permits**, and it does not bump the
> manifest format version: not one byte of the manifest schema changes, and the
> tripwire in `test_format_version_pinned.py` compares the three places the
> manifest version appears, which has nothing to do with error codes.
> What an addition still must do is **update four places** (this file,
> `errors.py`, `restore.sh`, the linter) -- locked code by code, in both
> directions, by `test_protocol_matches_code.py`.
> Precedent: 16 `OBJECT_MISSING`.

---

## 1. Numbering (tens digit = band)

- **Pre-gate codes 0 / 2 / 3**: "died before entering any stage". They belong to
  no `Sx` band.
- **In-band codes**: the tens digit is the band (S1..S5 → 1x..5x; the S0
  pre-flight → 6x); the unit digit is the `error_class` index within that band;
  **`x0` is reserved for that band's unclassified failure (`UNKNOWN`)**.
- The `error_class` string is the exit-code constant name with the `S?_` prefix
  removed (SCREAMING_SNAKE). `UNKNOWN` occupies the `x0` slot of every band, so
  it is the **(band, error_class) pair** -- not `error_class` alone -- that
  identifies an exit code.
- Naming: a new scenario is described first, then takes a free unit digit in its
  band. A plugin's translation key is `err.<error_class in lower case>`.

## 2. Who may produce what

The table is **shared in full**, but the right to produce a given code is
layered:

- The blocking and pre-flight codes **60 / 61 / 62 / 63 / 64 / 66 are produced by
  the agent only** (`renest doctor`, `renest restore`). The escape hatch has no
  graded pre-flight and produces none of them.
- The escape hatch's S0 does disk arithmetic only, and **the one S0 code it may
  exit with is 65** (insufficient space), with two precedents in real use.
- Compatibility comparisons (what the nest declares against what this machine
  reports) make the escape hatch print a one-line **notice**, `RESTORE_NOTICE`
  (§5). It occupies no exit code and the restore continues. Telemetry and
  orchestrators parsing a NOTICE line **must not count it as a failure**.

This layering is consumption discipline; it does not change the meaning of any
code, so the table below is the same table for every producer.

## 3. Pre-gate codes

| code | name | meaning |
|---|---|---|
| 0 | OK | Success: all five restore stages green, or the command completed normally |
| 2 | USAGE | Argument or usage error |
| 3 | CONFIG_OR_CREDENTIAL | Invalid configuration, a key written into a config file, or a missing credential |

Pre-gate codes carry no `stage` or `error_class` and take no part in the
(band, error_class) mapping of §4.
The single-digit pre-flight codes 6 and 7 from an old CLI draft are **abolished**
and map to nothing.
**Exit code 1 is never used**: shell convention makes 1 the generic error, so
giving it a specific meaning is guaranteed to collide with external tools'
defaults. Anything outside this table raises rather than falling back.

## 4. In-band codes (S0 pre-flight plus the five stage gates)

Code by code: band, `error_class`, whether it is retryable, who produces it, and
what it means. Retryable means the failure is worth retrying unchanged
(transient network or storage → true; deterministic failure → false).

| code | stage | error_class | retryable | producer | meaning |
|---|---|---|---|---|---|
| 60 | S0 | UNKNOWN | no | agent | Unclassified pre-flight failure |
| 61 | S0 | WARNING_UNCONFIRMED | no | agent | The health check warned and the user neither confirmed nor forced |
| 62 | S0 | PYTHON_BLOCK | no | agent | Python major version blocks the rebuild |
| 63 | S0 | CUDA_BLOCK | no | agent | CUDA major version blocks the rebuild |
| 64 | S0 | ARCH_UNSUPPORTED | no | agent | Target GPU generation is outside what this build of PyTorch was compiled for |
| 65 | S0 | DISK_INSUFFICIENT | no | agent + escape hatch | Not enough space on the target volume (the only S0 code the escape hatch may produce) |
| 66 | S0 | FINGERPRINT_MISSING | no | agent | The nest carries no fingerprint but the user asked for a forced pre-flight |
| 10 | S1 | UNKNOWN | no | agent + escape hatch | Unclassified fetch failure |
| 11 | S1 | NETWORK_INTERRUPTED | yes | agent + escape hatch | Network dropped; resumes from where it stopped |
| 12 | S1 | RANGE_THROTTLED | yes | agent + escape hatch | Ranged requests are being throttled |
| 13 | S1 | CREDENTIAL_EXPIRED | no | agent + escape hatch | Pre-signed link or manifest expired; needs re-issuing |
| 14 | S1 | STORAGE_UNAVAILABLE | yes | agent + escape hatch | Storage backend unavailable (every source down) |
| 15 | S1 | MANIFEST_UNSUPPORTED | no | agent + escape hatch | Manifest version not supported |
| 16 | S1 | OBJECT_MISSING | no | agent + escape hatch | Storage answered definitively "no such object": genuinely absent (a half-published nest), or the wrong bucket or prefix, or a key that is not allowed to see it |
| 20 | S2 | UNKNOWN | no | agent + escape hatch | Unclassified unpack/placement failure |
| 21 | S2 | PATH_CONFLICT | no | agent + escape hatch | Target path conflicts and no mode was specified |
| 22 | S2 | PERMISSION_DENIED | no | agent + escape hatch | Insufficient write permission |
| 23 | S2 | HASH_MISMATCH | no | agent + escape hatch | File verification failed (byte-level checks in lint and verify reuse this code) |
| 24 | S2 | SYMLINK_BROKEN | no | agent + escape hatch | Hard-link or symlink placement failed |
| 25 | S2 | DISK_FULL | no | agent + escape hatch | Ran out of space mid-write (pre-flight rejections use 65) |
| 26 | S2 | UNTRUSTED_SETUP | no | agent | **A nest someone else gave you** wants to run `post_install` (the only free-text shell command in a manifest) and the recipient has not named the sender. `--trust-sender "<name>"` allows it, `--no-setup` skips it. Nests you packed yourself are unaffected (the command is printed and run). **The escape hatch does not implement this code** -- blocking belongs to the agent, the escape hatch only informs |
| 30 | S3 | UNKNOWN | no | agent + escape hatch | Unclassified dependency-install failure |
| 31 | S3 | TORCH_CUDA_CONFLICT | no | agent + escape hatch | PyTorch does not match this machine's CUDA |
| 32 | S3 | NODE_REQUIREMENTS_FAILED | no | agent + escape hatch | An extension's requirements failed to install |
| 33 | S3 | NODE_VERSION_CONFLICT | no | agent + escape hatch | Extension version conflict |
| 34 | S3 | PYTHON_MISMATCH | no | agent + escape hatch | Python version mismatch |
| 35 | S3 | SYSLIB_MISSING | no | agent + escape hatch | Missing system library |
| 36 | S3 | MANAGER_INCOMPATIBLE | no | agent + escape hatch | Extension manager incompatible |
| 37 | S3 | UNTRUSTED_SOURCE | no | agent + escape hatch | The dependency lock names a download host that is not on the allowlist (the poisoning surface of a handed-off nest); `--trust-unsafe-urls` or `TRUST_UNSAFE_URLS=1` overrides explicitly |
| 38 | S3 | UPSTREAM_UNREACHABLE | yes | agent | **Upstream could not be reached** while installing dependencies: the package index or a code host is unreachable (no network, a proxy in the way, a mirror down, something removed upstream). **This is the format's honest boundary** -- models and source are inside the nest, Python dependencies are fetched at rebuild time. The error must **name the specific hosts** that could not be reached; once the network is back, re-running resumes from where it stopped. **The escape hatch does not produce this code** (it does not classify; it exits 1 uniformly). Added after a deliberate network-outage test: before that, this failure was misclassified as 31 (PyTorch/CUDA conflict), because attribution only looked for the string `torch` in the message -- and the installer's network errors naturally contain URLs like `https://pypi.org/simple/torch/` |
| 40 | S4 | UNKNOWN | no | agent + escape hatch | Unclassified start-up failure |
| 41 | S4 | NODE_IMPORT_FAILED | no | agent + escape hatch | An extension failed to import (each failing one is listed in the log) |
| 42 | S4 | NODE_NOT_REGISTERED | no | agent + escape hatch | Extension not registered |
| 43 | S4 | WORKFLOW_PATH_STALE | no | agent + escape hatch | A path referenced by the workflow no longer resolves |
| 44 | S4 | STARTUP_CRASH | no | agent + escape hatch | The application crashed on start-up (the tail of the start-up log is attached) |
| 45 | S4 | NEED_USER_DATA | no | agent | The environment rebuilt correctly, but **the user data this run needs is not present** (user data never travels in a nest). Reported separately from "it crashed" -- the environment is fine, what is missing is the user's own material |
| 46 | S4 | SYSLIB_MISSING | no | agent | The environment rebuilt correctly and the application still died, because a library owned by the operating system is not on this machine (a nest carries Python packages and code, never the OS). Names the library and, where we know it, the package that provides it -- and the image to boot instead when the nest recorded one. **Main path for a nest that runs to completion**: a fine-tuning run really does die on start. An image-gen application tolerates an extension that cannot import and starts anyway, so there a missing library usually lands on 55 rather than here -- unless it is a core dependency, which does kill start-up |
| 50 | S5 | UNKNOWN | no | agent + escape hatch | Unclassified output-verification failure |
| 51 | S5 | NODE_RUNTIME_ERROR | no | agent + escape hatch | An extension raised at run time |
| 52 | S5 | OOM_OR_SLOW | no | agent + escape hatch | Out of GPU memory, or too slow to be usable |
| 53 | S5 | ARCH_UNSUPPORTED_RUNTIME | no | agent + escape hatch | Architecture unsupported at run time (the "no kernel image" case; the run-time counterpart of 64) |
| 54 | S5 | IMAGE_MISMATCH | no | agent + escape hatch | An image was produced but similarity fell below the threshold (0.98 by default, configurable) |
| 55 | S5 | SYSLIB_MISSING | no | agent | Same cause as 46 one gate later, and the likelier of the two: the app tolerates an extension that could not import and starts anyway, so a machine short of a system library often breaks only when the recipe asks for that extension. Names the library and, when the nest recorded one, the image to boot instead |

The five stage gates mean: S1 fetch → S2 unpack and place → S3 install
dependencies → S4 start and load → S5 verify output. The S0 pre-flight runs
before all five and belongs to the agent (except 65).

### 4.9 Why a private bucket always needs a pre-signed link

13 `CREDENTIAL_EXPIRED` and 16 `OBJECT_MISSING` are frequent when a user brings
their own bucket, and the cause is structural:
**the escape hatch's dependency list contains no `openssl`, so it cannot compute
an AWS SigV4 signature and can never sign a link itself.**
Bytes in a private bucket can only be fetched through a link signed somewhere
else -- by the server for account holders, or by `renest presign` on the user's
own machine, which is where their key lives. See `specs/restore-grant.md` §4.9.

Measured note (2026-07-26, against a real S3-compatible bucket): **a request with
a missing or wrong signature comes back as HTTP 400**, not 401 or 403.
Attribution must therefore count 400 in the "key or signature is wrong" class
(see `renest.download.classify_source_failures`); otherwise it falls into
unclassified, is treated as retryable, and retries hammer a signature error that
can never succeed.

## 4.10 The two shapes of `--json` (command-line output contract)

`--json` is a **global flag accepted in both positions** -- `renest --json pack …`
and `renest pack … --json` are equivalent. The reason is mundane: the second is
what everybody types first.

The output has **two shapes, depending on the command**, and anyone writing a
script has to know which:

| Command | Shape | How to parse |
|---|---|---|
| `doctor` / `lint` / `verify` / `presign` / `list` / `export` | **One JSON document** | `… --json \| jq .` |
| `pack` / `restore` | **One JSON event per line** (NDJSON) | Parse line by line; **the last line is always the final report** |

Why they are not unified: `doctor` is a one-shot judgement, and streaming would
make a one-line `jq` awkward; `restore` is a long process and must report
progress as it goes, so it cannot be a single document. Both have reasons.
**What has no reason is leaving it unwritten** -- so it is pinned here and locked
command by command by `oss/tests/consistency/test_json_output_shapes.py`.

**The one guarantee that spans both shapes**: the **last line** of an NDJSON
stream is always the final report (carrying `ok` and `exit_code`). A script that
only wants the conclusion can take the last line without understanding any of
the intermediate event types.

## 5. The one-line contract (`RESTORE_FAIL` / `RESTORE_NOTICE`)

The failure verdict line (last line on stderr; one line, `key=value`, no
traceback -- the full log always lands in `$RESTORE_ROOT/restore.log`):

```
RESTORE_FAIL stage=S3 code=32 reason=node-requirements detail="..."
```

- `stage` ∈ {S0..S5}; `code` is the exit code from this table; the process exit
  code equals `code`.
- `reason` is a hyphenated phrase for machine classification; `detail` is human
  supplement, in double quotes.
- The agent and the escape hatch use **the same line format and the same code
  table**. The agent may report more (an NDJSON event stream, an error object),
  but must not change the meaning.

The notice line (occupies no exit code; the restore continues; compatibility
predictions are printed by the escape hatch):

```
RESTORE_NOTICE stage=S0 class=ARCH_UNSUPPORTED detail="..."
```

- `class` is a value from this table's `error_class` vocabulary (reuse it; do not
  coin new words).
- NOTICE uses the same `key=value` form as FAIL. Telemetry and orchestrators
  **must not count a NOTICE as a failure**.

## 6. The error object (consumed by NDJSON, the local job API, orchestrators and telemetry)

Structure of the `error` field in `renest --json` output and in local job status
(`type` and `ts` are added by the emitter; the implementation is
`BagFailure.to_error_object` in `errors.py`):

```json
{"type":"error","ts":"…","stage":"S3","error_class":"TORCH_CUDA_CONFLICT",
 "exit_code":31,"retryable":false,"detail":"…","human":"…","context":{"log_file":"…"}}
```

`error_class` and `exit_code` must be a matching pair from this table, and
`retryable` is decided by this table's retryable column (true when `error_class`
is one of `NETWORK_INTERRUPTED`, `RANGE_THROTTLED`, `STORAGE_UNAVAILABLE`; false
otherwise).
