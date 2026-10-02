# renest

Renest saves a ComfyUI or fine-tuning setup that already worked on a rented GPU — the model files, custom nodes, exact package versions and workflow — and brings it back on another Linux GPU machine, every file checked against its SHA-256. It promises that the files and dependencies come back verified; whether the app then runs is tested on every restore and reported, not promised.

Renest is for the moment *after* something works: a ComfyUI workflow producing the image
you wanted, or a fine-tuning run (kohya_ss, LLaMA-Factory) that finally trained. It captures
what that success depended on — models, custom nodes pinned to their commits, the
dependency lock, the workflow or training config, the system libraries the run loaded —
into a single open-format archive called a **nest**. Later, on a fresh pod, another region
or another cloud, `renest restore` checks the machine first, brings every file back and
checks it against its SHA-256, reinstalls the locked package versions, then starts the app,
runs the workflow once and tells you what passed and what didn't.

System libraries belong to the machine, not the nest. A nest records which ones the run
loaded and which image it ran on; on a machine that lacks one, the restore names it and the
command to install it.

It does not try to make unfamiliar things work. It reproduces what already did.

- Website and docs: https://renest.ai · Quick start: https://renest.ai/docs/quick-start
- ComfyUI panel: https://github.com/renest-ai/comfyui-renest
- Format spec and the standalone `restore.sh` escape hatch: Apache-2.0. The CLI itself is
  source-available, not open-source software (see `LICENSE-CLI`).

## Install

```
uv tool install --upgrade renest
renest --version
```

`--upgrade` matters if you have installed `renest` before: plain
`uv tool install renest` treats an existing install as done and leaves the old
version in place, so re-running it looks like an upgrade but is not. `--upgrade`
moves an old install to the latest and is a harmless no-op on a fresh machine.

Python 3.11 or newer. No `uv` on this machine yet?

```
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows:  powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
# only have pip?  pip install uv
```

On a proxy network, `uv` and `curl` read the proxy only from the environment,
not from the OS/system proxy settings — so `export HTTPS_PROXY=http://host:port`
(and `ALL_PROXY`) first, or the very first install step hangs with no error.

That last one is safe even inside the environment you are about to capture: `uv`
is a single binary with no dependencies of its own, so installing it moves
nothing else. That is not true of installing this package with `pip`.

**Why `uv` and not `pip`.** Two reasons, and the second one matters more than
taste. First, rebuilding an environment is what this tool does, and it does it by
calling `uv` — so does the escape hatch script inside every archive. A machine
without `uv` can install this package and still not restore anything. Second,
`pip install renest` installs into whatever environment is active, and that is
often the very environment you are about to capture; resolving our dependencies
there can move versions inside it. Protecting a setup that already works is the
whole point of this tool, so we do not ask you to touch it to install us.
`uv tool install` keeps the command in its own environment. `pip install renest`
still works if you know your environment is separate.

## Use

```
renest pack --dir /path/to/comfyui --workflow workflow.json --out ./nests
renest verify ./nests/<id>/manifest.json --dir /path/to/comfyui
renest restore --manifest ./nests/<id>/manifest.json --dir /path/on/the/new/machine
renest doctor
```

In order: capture a setup that already worked, check a rebuild end to end, rebuild it
somewhere else, and ask whether this machine can. `--dir` is always the environment root
— the folder holding `ComfyUI/` — and every path is one you name, never one we guess.

`renest --help` lists the rest (`list`, `lint`, `export`, `serve`, `presign`,
`update-rules`, `support`).

## The escape hatch

Every nest ships with `restore.sh`, a plain shell script that rebuilds the
archive using nothing but `curl`, `jq`, `sha256sum`, `uv` and `tar`. It does not
import a single line of the rest of this project, and it is Apache-2.0 along with
the format specification. If this project disappears tomorrow, your archives
still open. That is the point of it, and it is why it is licensed the way it is.

The format specification lives in `specs/` inside the wheel. Anyone can write
their own reader from it.

One command exists purely for that day: `renest presign` signs a download link
for an object in your own bucket, using keys that live on your machine. The
escape hatch deliberately depends on nothing but `curl`, `jq`, `sha256sum`, `uv`
and `tar` — it has no way to sign anything itself. So if this project is gone,
the machine holding your storage keys is the one that can still hand out links,
and that command is how.

## Versions you will see

Five separate things carry their own version, because they change at completely
different speeds:

- **the tool** — the version of `renest` itself
- **the archive format** — printed by `renest --version`; an archive records
  which one it was written with, and a newer tool reads every older one in the
  same major version
- **the environment fingerprint** — how a machine's shape is recorded
- **the retrieval grant** — how a time-limited download permission is written
- **the local API** — the endpoints under `/api/v1` that a desktop or web client
  talks to

Plus a set of compatibility facts kept on your machine as data — things like
which driver version a given CUDA release needs. Those are refreshed with
`renest update-rules` without installing a new version of the tool.

Within one major version, things are added and never changed or removed. A
breaking change moves to the next major version, and the old one keeps working
alongside it.

Note that the tool's own version number is still `0.x`, and the archive format's
is not. That is deliberate, and the difference matters: the tool's command-line
surface may still shift, but **an archive written today stays readable**. The
format promise is the one your data depends on, and it does not move with the
tool.

## Licence — three layers, and they are not the same

**Genuinely open (Apache-2.0):** the archive format specification and the escape
hatch script. These are the proof that you can open your own archives even if we
are gone. Use, modify and redistribute them freely, with no conditions from us.

**The ComfyUI plugin (GPL-3.0):** it runs inside the ComfyUI process, so it
follows that ecosystem's rules. It lives in its own repository.

**This command-line tool — source-available, and *not* open-source software:**
the code is published in full. Read it, audit it, modify it for your own use,
publish your modifications. The one thing not granted is using it, or a
derivative of it, to offer other people a hosted service that competes with ours.
The text is in `LICENSE-CLI`, which ships with this package.

It also carries a **permanent exemption**: any individual using it to pack, sign
links for, restore or verify *their own data* may do so forever, unconditionally
— this does not lapse because we shut down, because you have no account, or for
any other reason.

In one line: the format and the escape route are public, the tool's code is open
to read, and the only thing not given away is running a competing hosted service
on it.

## Links

- Source: <https://github.com/renest-ai/renest>
- ComfyUI plugin: <https://github.com/renest-ai/comfyui-renest>
- Compatibility data: <https://github.com/renest-ai/renest-rules>

The hosted service is operated by the author of this project.
