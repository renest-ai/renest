# renest

Pack up a GPU setup you already got working — an image workflow or a fine-tuning
run — and rebuild it on any other machine, every file byte for byte. Boot that machine
from the image your nest recorded, and everything the app needs comes with it.

Renest is for the moment *after* something works. You got a ComfyUI workflow
producing the image you wanted, or a fine-tuning run that finally trained. Renest
captures everything that success depended on — models, custom nodes, code, the
dependency lock, the recipe file, the environment fingerprint — into a single
open-format archive called a **nest**. Later, on any machine, any cloud, any new
pod, you rebuild it and check every file against its SHA-256. Same bytes or it
tells you which ones differ.

Shared libraries belong to the machine, not to the nest — an archive cannot carry
its operating system. That is why a nest records the image it ran on: boot the same
one and they are already there. On a machine without them the rebuild still gets
every byte back, and if the app then cannot start, Renest names the library that is
missing and where to get it rather than leaving you to read a traceback.

It does not try to make unfamiliar things work. It reproduces what already did.

## Install

```
uv tool install renest
renest --version
```

Python 3.11 or newer. No `uv` on this machine yet?

```
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows:  powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
# only have pip?  pip install uv
```

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
renest pack   /path/to/comfyui  --out ./nests      # capture a working setup
renest verify ./nests/<id>                         # check it end to end
renest restore <id> --to /path/on/the/new/machine  # rebuild it elsewhere
renest doctor                                      # will this machine do?
```

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
