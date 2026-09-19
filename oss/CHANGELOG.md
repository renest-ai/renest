# Changelog

What changed for the person using `renest`. Dates are the release date.

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
