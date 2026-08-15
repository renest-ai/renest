# serve-api · the local HTTP surface (the one contract the plugin ecosystem builds on)

> Status: **v1, written down** (frozen from the existing implementation;
> authoritative implementation `oss/src/renest/serve.py`, behaviour tests
> `oss/tests/unit/test_serve.py`).
> A 2026-07-23 renaming batch applied the namespace rule (tooling is `renest`,
> assets are `nest`) with a clean break and no legacy aliases: the environment
> variable became `RENEST_TOKEN_FILE`, the token path moved from `bag` to
> `renest`, `GET /bags` became `GET /nests`, and the restore parameter `bag_ref`
> became `nest_ref`. This file uses the new names throughout.
> This file is the **only authoritative document** for the `renest serve` HTTP
> surface. Every consumer -- desktop client, ComfyUI plugin, workflow tooling --
> must follow this table rather than the internal structure of the source.
> Format discipline: any change of field, path or meaning is a contract change
> and must leave a trace in this file; a breaking change must move to `/api/v2`
> and keep v1 until the deprecation window closes.

---

## 1. Scope and boundaries

- **Loopback only**: listens on `127.0.0.1:7799`. The default host is never bound
  to a routable address.
- **Job**: the local pack/restore job queue plus the local nest registry.
  `GET /nests` **never queries a bucket** -- `serve` is this machine's hand;
  facts about the cloud belong to the service API.
- **Credential rule**: no cloud credential or bucket key crosses HTTP, not even
  on loopback. Credentials are held by the host (desktop client or CLI config);
  `serve` only ever sees a reference in the job parameters (a path, a grant
  file).
- **GPL isolation**: the plugin runs inside the ComfyUI process and may only
  call across this interface. The process boundary is the protocol boundary;
  importing this package's code into the GPL side is forbidden.

## 2. Authentication: the token-file contract

- Everything except `GET /health` requires `Authorization: Bearer <token>`;
  failure is `401`.
- **Token path contract**: `~/.config/renest/serve.token`, mode 0600, overridable
  with `RENEST_TOKEN_FILE`. `serve` writes it, the bridge reads it, and it is
  re-read lazily on every request -- so rotating the token does not require
  restarting ComfyUI.
  Correction (2026-07-19, found during acceptance on real machines; the Windows
  location was confirmed by reading the library source): the implementation uses
  `platformdirs`, so **on macOS the real location is
  `~/Library/Application Support/renest/serve.token`** and **on Windows it is
  `%LOCALAPPDATA%\renest\renest\serve.token`** -- note the doubled
  `renest\renest`, because with no author set the library reuses the application
  name as the author directory. Consumers should probe in order: the environment
  variable, then `~/.config/renest/`, then the platform directory (see the
  `comfyui-renest` reference implementation). The Windows path has not been
  verified on real hardware and is marked as such.
- Token comparison is constant-time (`hmac.compare_digest`), and `/health` never
  fails because someone probed it with a bad credential.

## 3. CORS

A browser-side plugin (ComfyUI's front-end JavaScript) has to call across a port,
so:

- **The allowlist is loopback origins**: when `Origin` matches
  `^https?://(127.0.0.1|localhost)(:port)?$`, that exact origin is echoed back in
  `Access-Control-Allow-Origin` (with `Vary: Origin`); any other origin receives
  no CORS headers at all and the browser blocks it. **Never `*`** -- this
  interface carries an Authorization header.
- Pre-flight: `OPTIONS <any path>` → `204`, allowing `GET, POST, DELETE, OPTIONS`
  and the `Authorization` and `Content-Type` headers, with `Max-Age 600`.
  Pre-flight is unauthenticated, because browsers send pre-flight without
  credentials.
- Note that CORS is not a security boundary (any local process can already reach
  loopback directly); the security boundary is the bearer token. The plugin's
  JavaScript receives the token from its Python side, which reads the token file;
  the JavaScript never writes it to disk.

## 4. Endpoints (six, under `/api/v1`)

| Method / path | Auth | Meaning | Main responses |
|---|---|---|---|
| `GET /health` | none | Liveness, version, storage configuration shape | `200` health object |
| `POST /pack` | yes | Packing job. The body takes **either** `spec` **or** `workflow` (`workflow` = infer from the target alone; consumed by the plugin bridge). Optional `out` = which local folder the nest lands in (§4.1). With `{"dry_run":true}` it returns the manifest preview **synchronously** (the single source for the confirmation screen) | `202 {job_id}` / dry-run `200` / bad argument `400` / queue full `429` |
| `POST /restore` | yes | Restore job (`nest_ref` and `target` required) | as above |
| `GET /jobs/{id}` | yes | Job status: `state`, plus `progress` and `logs_tail` in the frozen event format | `200` / `404` |
| `DELETE /jobs/{id}` | yes | Cooperative cancel (queued jobs are withdrawn; a running job gets a cancel flag and the five stage gates honour it at stage boundaries) | `200 state=cancelled` / `404` |
| `GET /nests` | yes | Local registry (nests produced or received on this machine; **never queries a bucket**) | `200 {nests:[…]}` |

### 4.1 Where a nest lands, and the confirmation screen (added 2026-08-02; fields added, none changed)

Origin: a full regression against the real engine, driven in the panel's actual
request order (test `oss/tests/consistency/test_comfyui_plugin_contract.py`),
surfaced four things consumers needed that the contract did not provide. All four
are **new fields**, so the v1 compatibility promise holds.

- **`out` on `POST /pack`**: which local folder the nest lands in; the same thing
  as the CLI's `--out`. When omitted, the default is **next to the environment
  being packed**, i.e. `<environment directory>/renest-nests/`; when the target
  is obviously the ComfyUI application itself (it contains `main.py` and
  `custom_nodes/`), the level above it is used; if that is not writable it falls
  back to the user's data directory. **The old behaviour -- opening a fresh
  system temporary directory every time** (`/tmp` or `/var/folders`), where the
  nest was eventually swept away with nowhere to look for it -- is abolished.
  (`dest` is a synonym kept for compatibility. It is not used in new work,
  because it collides confusingly with the CLI's `--dest`, which chooses a cloud
  destination.)
- **`env_python` and `comfyui_dir` on `POST /pack`** (added 2026-08-03): the real
  shape of the environment is told to the engine by **the consumer running inside
  the application process**; the engine does not guess. `env_python` is the
  interpreter actually running this environment (when the environment has no
  lockfile, the dependency list is read from it live -- the desktop build of
  ComfyUI has no lockfile at all, and 135 packages were read from its interpreter
  in a real run); `comfyui_dir` is the application's own source directory, needed
  only when it is not the same place as the data directory. Both are optional and
  omitting them preserves the old behaviour. **Note**: `comfyui_dir` also decides
  which tree is searched for extensions and models, so for the desktop layout
  where program and data live apart, **do not send it yet**; packing both trees
  is separate work.
- **`warnings` added to the dry-run preview**: the verbatim list of things
  capture could not pin down (most often an extension that was unpacked in place
  and has no traceable origin, which by discipline is neither guessed at nor
  packed). Consumers **must** display it -- a confirmation screen that reports
  only good news hands the user a list that looks complete and sends them off to
  rebuild.
- **`out_dir` added to the dry-run preview**: where this packing run will put the
  nest (same default rules as above), so a person knows where their work is going
  before pressing confirm. A preview writes no bytes and creates no directory.
- **Registry entries carry identity**: every `items.nodes[]` entry carries
  `dep_role` (`host` = the application itself / `extension` = something installed
  into it / `user_code` = the user's own code) and `path`; every `items.deps[]`
  entry carries `path`. Previously these entries had only a name or only a hash,
  so a consumer either displayed question marks or counted the application itself
  among the custom extensions.
- **`path` added to every `GET /nests` entry**: where the nest sits on this
  machine. Until now the local registry could not answer the most basic question
  there is -- where is my nest?
- **Packing jobs now emit stages and progress**: `stage_start` (P1 move bytes →
  P2 write the manifest → P3 upload, only when there is an upload → P4 reconcile)
  and `progress` (the frozen five fields, with the denominator obtained by
  stat-ing everything before work starts). Previously packing emitted **no
  progress events at all**: `stage` was permanently P1 and `percent` permanently
  0, which on screen is a progress bar that never moves. Restore already emitted
  them and is unaffected.

Job events and progress fields are a **frozen contract** (six event types, five
progress fields, seven error fields); the canonical text is
`specs/restore-protocol.md` and `oss/src/renest/events.py`. The state machine is
`queued → running → succeeded | failed | cancelled | interrupted` (jobs in flight
when `serve` restarts are marked `interrupted` and may be resubmitted). The queue
limit is `MAX_QUEUE`; beyond it, `429`.

## 5. The compatibility promise (what the ecosystem is betting on)

1. Within `/api/v1`, **things are added, never changed or removed**: new
   endpoints and new optional fields at any time; changing meaning, deleting a
   field or making one required is breaking and moves to v2.
2. Error codes and the event contract follow the freezing discipline of
   `restore-protocol`; `serve` does not coin its own vocabulary.
3. Deprecation pace: after v2 ships, v1 runs alongside it for at least two
   release cycles, and `/health` reports the availability of both.
4. Drift between this file and the implementation is a bug: fix the document or
   fix the code, and never wave it away with "the implementation is the truth".

## 6. Minimum integration for a plugin author (reference)

```
TOKEN=$(cat "${RENEST_TOKEN_FILE:-$HOME/.config/renest/serve.token}")
curl -s http://127.0.0.1:7799/api/v1/health                      # liveness (no auth)
curl -s -H "Authorization: Bearer $TOKEN" \
     -X POST http://127.0.0.1:7799/api/v1/pack \
     -H 'Content-Type: application/json' \
     -d '{"dry_run": true, "spec": {…}}'                          # packing preview (synchronous)
```

Browser JavaScript works the same way (`fetch` plus a bearer header); see §3 for
CORS. The official ComfyUI node lives in its own repository under a GPL-compatible
licence and depends on this file as its only interface.
