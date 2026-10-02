# Changelog

What changed for the person using `renest`. Dates are the release date.

## 0.1.17 — 2026-10-02

### After a restore, your workflow opens from ComfyUI's Workflows sidebar

- Measured on the official starter nest: the restore succeeded and rendered, and
  ComfyUI then opened on an empty canvas. The nest only held the workflow in API
  form (what a test render runs), and the sidebar can only open the form the
  editor saves.
- The editor form now travels in the nest as an ordinary file (`files[]` kind
  `workflow`; no format change). The Renest panel sends it on its own; `pack --auto`
  reads it from the text block of the picture it picks (the picture itself still
  never goes in); with `--workflow`, add `--workflow-ui` and the same workflow
  saved with Save.
- After a restore it is in the sidebar, and What's next says
  "In ComfyUI, open Workflows (left sidebar) → <name>". `renest start` puts it
  back if it went missing. Nests without it behave as before.
- It goes through the same credential check as the recipe — a nest is handed to
  other people.

### `renest start --port PORT`

- On a machine where something already holds the recorded port — a rented box
  that ships its own ComfyUI on 8188 — `renest start` collided, and the only way
  round it was editing the restored files by hand.
- `--port` now overrides the port for this run, like `--listen` does for the
  address: the command's `--port` is rewritten, or added when the restore knew the
  app's port (ComfyUI's 8188). The printed command and the "answers on port" line
  follow it. Nothing in the restore folder is rewritten. A value that is not a
  whole number from 1 to 65535 is refused as a usage error.

### Nests saved from the Renest panel carry their workflow, and restore test-renders it

- A nest saved with "Nest this run" held every file but not the workflow itself,
  so restoring it never ran a test render. The workflow now travels in the nest
  (no format change).
- It is marked as having worked only when a finished run in that ComfyUI wrote
  this workflow into its output picture. If the canvas differs from that run only
  in whole numbers (a seed that changes after every run), restore re-runs the
  recipe of the run that really happened, and the canvas version travels too.
  With no such run, the workflow travels, restore does not test-render, and the
  pack says so.

### The restored workflow in the sidebar carries the nest's name

- Every restored workflow was listed as "renest-workflow". It now takes the name
  typed in the Renest panel, or `pack --nest-name`, cleaned the same way the
  sidebar cleans names. With neither, nothing changes.

### A nest folder on this machine restores with the command the docs give

- `renest restore --manifest <folder>/nests/<nest-id>/manifest.json --dir ./run`
  on a nest saved from the panel or by `renest pack` stopped with "Nowhere to
  download ComfyUI from"; `--blob-base file://…` then failed as a network
  interruption, retried three times. The bytes were in the folder all along.
- A manifest read from a nest folder now takes its files from the `blobs/sha256`
  folder beside it, and says so. `--blob-base` also takes a folder path or a
  `file://` address. A file missing from that folder is reported as missing,
  with its path, not as a network problem, and is not retried.

### Restoring on the machine that packed the nest no longer says it "differs"

- The comparison before the download can only read renest's own environment,
  which holds no torch, so torch and the nest's key packages read as empty, and
  the closing line said the machine differs a little.
- Once the environment is rebuilt, its own Python is asked again, and that
  answer is the one the closing line and the report use. A value that still
  cannot be read is named as unread, never counted as a difference.

### A licence nobody stated is no longer recorded as the user's

- A model whose licence could not be found was written into the nest with
  `declared_by: "user"`, though the user never said anything about it. The
  restrictive default that capture fills in now leaves `declared_by` out
  (meaning unknown). It stays restricted as before; a licence a person wrote
  or edited is still recorded as theirs.

### Smaller fixes

- `renest serve` no longer tells you to set `RENEST_TOKEN_FILE` for the panel;
  the panel has not read it since 0.1.7. The line now says where the panel
  finds the token, and names the pointer file for a token kept elsewhere.
- The restore report's lines for a skipped test render (and for a nest with no
  recipe) no longer show literal `**` marks, and a packing note uses the same dash as its neighbours.

## 0.1.16 — 2026-10-02

### `renest restore --json` now carries the boot-time health check report on the result event

- Measured on a real rented machine (batch 15, 2026-09-25): the precheck report —
  including the gpu_alloc probe that really touches the card — lived only on the
  internal report object. The machine-readable `result` event omitted it, so any
  `--json` reader saw "nothing measured" on machines that had measured plenty.
- The whole precheck report now rides the `result` event, same rule as
  `machine_libraries_missing`: a fact that only lives on the report object is
  invisible to `--json`. Machine facts only — no user files, no redaction needed.

### A plugin whose own files are pure Python no longer slips past the machine check

- Measured on a real rented machine: a plugin with no compiled file of its own
  shipped a `requirements.txt` naming opencv-python, and it was that wheel's
  `cv2` binary that asked the machine for `libxcb.so.1`. The plugin folder scan
  had nothing to read, so the rebuilt machine sailed through the check green and
  the plugin died on import anyway.
- The pack-time scan now also reads the binaries of the Python packages a
  plugin's `requirements.txt` names — installed where the working run installed
  them, walked through their own bundled libraries the same way. The restore
  side's before-download warning names these too: still a warning, never a
  refusal, exactly as before.

## 0.1.15 — 2026-09-19

The first release shaped by watching somebody outside the team use this from
nothing but a hand-off link. Everything below is either something that cost him
time, or something the tool should have said and didn't.

### After a rebuild succeeds, it now tells you what to do with it

- `restore` ends with **What's next**: where your output lands, the command that
  starts the app, where the packed workflow file is, and that the same restore
  command carries on from another machine. Every line is read off the nest —
  nothing is guessed, and anything unknown is left unsaid.
- New command **`renest start`** runs what the rebuild proved, so the start
  command does not have to be copied out of the closing lines and pasted back.
- If that start command listens on `127.0.0.1`, both the closing lines and
  `renest start` now say so — that address answers the box itself, so exposing
  the port in a rented machine's panel reaches nothing. `renest start --listen
  0.0.0.0` changes that one value. It only ever rewrites an address the recorded
  command already carries; an application that takes no such flag gets a refusal
  with the reason, never an invented flag that would break a start that works.

### The pre-flight check stops more machines before you pay to download

- It now **asks the card for memory and gives it back** — the first check that
  touches the GPU at all, rather than reading version strings about it.
- It runs a **full `nvidia-smi` query**, not the single field that a
  half-dead node can still answer. A machine whose driver has come apart is
  called out before the download, not after it.
- Both warn rather than refuse: these are new instruments, and a wrong refusal
  costs you a machine you already rented.
- When a nest does not record the image it was packed on, the verdict no longer
  tells you to "rent a machine that matches" and then name nothing to match —
  it reports what it did read, or admits the verdict cannot help you.

### Plugins that come back broken are now visible

- Nests now record, per plugin package, the **machine libraries its compiled
  files ask for** (nest format 2.12). A workflow that never touches a plugin
  never loads its binaries, so a missing system library used to be invisible
  until the plugin was first dragged into a workflow on the new machine. This is
  read off the packed bytes, so it names libraries that may never be used — it
  warns, and never refuses.
- After the app starts, the launch log is read for plugins that failed to import
  for a missing shared library, and those are reported by name.

### Fixes

- `pack` could finish successfully and still print "Pack failed" as its last line.
- `pack` no longer records a claim about upstream that contradicts what it
  recorded elsewhere about the same install.
- `capture` no longer stops with an OS error on a prompt file whose name is
  longer than the filesystem allows.
- The escape hatch's own text no longer makes a promise it cannot keep.

## Earlier releases

0.1.14 and before predate this file.
