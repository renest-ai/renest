# manifest v2.8 · Nest manifest specification

<!-- Version tripwire: the line "current version **x.y**" below is parsed by
     oss/tests/consistency/test_format_version_pinned.py and must agree with
     renest.restore.FORMAT_VERSION, the last entry of the schema enum, and the
     top line of the change log. This is the fifth place the version appears --
     the prose is not allowed to drift from the other four. -->

> Status: **current version 2.8** (2026-08-17). Any field change is a format
> change: bump the version and update `manifest.schema.json`, `restore.sh` and
> `renest lint` in the same change.
>
> **Readable versions**: `2.0` / `2.1` / `2.2` / `2.3` / `2.4` / `2.5` / `2.6` / `2.7` / `2.8`, plus **any future minor
> version of the same major** (a reader meeting a newer minor number warns and
> continues; it does not reject the nest -- see §2).
> **1.x is refused outright** (a one-time clean break taken while there were no
> real users yet), and must be refused with "unsupported version" rather than a
> crash somewhere else. Old fixtures are history, not a supported path.
>
> **Where each version's change log lives**: 2.0 in §10 (the format was widened
> to carry fine-tuning frameworks alongside image generation), 2.3 in §11 (purely
> relaxing and purely additive: two fields the packer cannot obtain went from
> required to optional), 2.4 in §14 and 2.5 in §15 (machine facts that differ
> from machine to machine), 2.6 in §12 (four things packing knew and threw away),
> 2.7 in §13 (`files[].kind` became an open string), 2.8 in §16 (which copy of a
> module the working run used when several packages write the same folder).
> **Every 2.x nest still reads**: no version after 2.0 tightened anything.
>
> This document is the **frozen description** of the format: written field by
> field against `manifest.schema.json` (authoritative for shape) and against
> measured evidence (the source of meaning). **Nothing is invented**: no field
> appears here that is absent from the schema, and where the schema is
> semantically vague this document records the vagueness in §9 rather than
> quietly "clarifying" it into new meaning -- that would be a change, and
> changes get a version number.
>
> Division of authority: `manifest.schema.json` defines **shape** (consumed
> directly by CI and `renest lint`); this document defines **meaning** (why a
> field exists, who consumes it, how to use it). The two are maintained in the
> same change.
> Acceptance test for "an outsider can implement this": given only this document
> and a golden nest, an engineer who has never seen our code can write a reader
> that passes `conformance/`.

Only two evidence markers are used here: `[measured]` = a conclusion produced by
running real hardware; `[schema]` = shape taken from `manifest.schema.json`.
Where something says measured, the conclusion itself is written out in the
text -- you are never asked to look it up elsewhere.

---

## 1. Top-level structure

One manifest is the complete, self-contained description of **one run that was
verified to work**. Core fields are **scenario-neutral** (the core layer never
names a specific tool); anything tool-specific lives in the `adapters.*`
namespace. `[schema]`

`additionalProperties: false` applies throughout -- the top level and every
object reject undeclared keys. **The single exception is an unknown adapter key
under `adapters`**, which since 2.0 passes through as an opaque object (§6.1).

**"Unknown field" and "unknown minor version" are two different things** (fixed
in 2.3, see the reader obligations in §2): schema validation rejects undeclared
keys, and that is `renest lint`'s job -- while **a restore path meeting a newer
minor version of the same major must proceed**, because by specification that
can only mean extra optional fields, and rejecting it turns a nest that would
have restored perfectly into a brick.

| Field | Required | Type | One line |
|---|---|---|---|
| `format_version` | ✔ | enum `2.0` … `2.8` | Format version (the schema enum is the only source of truth) |
| `id` | ✔ | string (ULID) | Nest identifier, 26-character Crockford base32 |
| `created_at` | ✔ | date-time | When it was packed |
| `name` | | string ≤120 | Human-chosen name |
| `base_image` | | object | Foundation image, pinned by digest. **Optional since 2.3** (§3) |
| `runtime` | ✔ | object | Python / CUDA / GPU runtime parameters |
| `gpu` | | object | Facts about the packing machine's graphics cards (§3.2) |
| `fingerprint` | | object | Environment fingerprint, first layer (for pre-flight checks) |
| `code_deps` | ✔ | array | Code dependencies (source archived in full); each entry must carry `role` |
| `python_lock` | ✔ | object | Deterministic dependency lock (**`lockfile` optional since 2.3**) |
| `files` | ✔ | array | Large assets (content-addressed) |
| `entrypoint` | | object | **Added in 2.0**: how the working run was started (§4.3) |
| `post_install` | | string | Global post-install command (escape hatch) |
| `adapters` | | object | Scenario adapter namespace |
| `creation` | | object | Metadata about where it was created |
| `derived_from` | | object | **Added in 2.4, reserved**: which nest this one was made from (§6.2) |
| `api_deps` | | array | External API dependencies (honest boundary) |

**Required set** (schema `required`): `format_version`, `id`, `created_at`,
`runtime`, `code_deps`, `python_lock`, `files`. Everything else is optional.
(2.3 removed `base_image` from this list -- see §3.)

### 1.1 One rule for packers: if you cannot obtain it, omit the whole block; never write placeholder text

**Since 2.3 this is a specification requirement, not an implementation
preference.** When the packer cannot determine a field, **leave the field out
entirely**; do not write `<fill in ...>` or anything like it.

Why it is in the specification: placeholder text **cannot pass this format's own
shape check** (an image digest must be `sha256:` plus 64 hex characters, and a
placeholder never matches). A full audit of previously produced nests found none
that validated -- the root cause was that this rule existed only as a verbal
convention.

The resulting division is fixed too: **the schema permits absence, and `renest
lint` reports incompleteness as a warning** (`base-image-missing`,
`lockfile-missing`), while **placeholder text is an error**
(`placeholder-left-in`). Absence is honest; a placeholder is pretending. **No
draft or completeness flag field is added** -- that would create a second source
of truth.

## 2. Identity and metadata

### `format_version` — enum `2.0` / `2.1` / `2.2` / `2.3` / `2.4` / `2.5` / `2.6` / `2.7` / `2.8` `[schema]`

**The `enum` in the schema is the only source of truth.** Everywhere else,
including this document, is a restatement. Changing the version means changing
that one place, plus the code, plus the top line of the change log, plus the
version gate in the escape hatch -- four places, each with a tripwire test.

**Version policy**: a minor bump adds optional fields or relaxes constraints; a
major bump is a breaking change and older readers must refuse. 2.0 was a major
bump because `code_deps[].role` went from absent to required.
**Additive changes still bump the minor version**: 2.0 to 2.1 added a single
optional field and still got a number -- the version answers "which revision is
this", not only "can you read it".
`fingerprint.fingerprint_version` evolves independently (§9).

#### Reader obligations (fixed in 2.3; obligations, not choices)

1. **Within one major version, an unrecognised optional field MUST be ignored
   and MUST NOT cause rejection.** Strict validation is `renest lint`'s job, not
   the restore path's.
2. **A newer minor version than you know MUST warn and proceed, not reject.**
   Landing points: `renest.restore.newer_minor_within_major`, and the `2.*`
   branch in the escape hatch.
3. **A different major version is still refused outright** -- a major bump means
   breaking changes, and guessing is just guessing.

**Why this is written as an obligation:** the 2.1 release was purely additive,
yet the escape hatch's version gate was hard-coded to `= "2.0"`, so **a nest
that could have been restored byte for byte was rejected as a brick**; a test
caught it only at merge time. That is not caution, that is losing half the
user's work.

**Readers must refuse 1.x nests** and must say "unsupported version" rather than
crash elsewhere. This is not fastidiousness: 1.x has no `role`, and guessing
`role` means guessing which part of a nest is the application and which is the
user's own code -- guess wrong and the user's training configuration is
presented to a recipient as part of the host application.

### `id` — ULID `[schema]`
`pattern ^[0-9A-HJKMNP-TV-Z]{26}$`: 26 uppercase Crockford base32 characters
(ULID shape). Blob addressing does not use it -- blobs are addressed by sha256 --
so this identifies "this act of packing" and nothing else.

### `created_at` — date-time; `name` — string ≤120 `[schema]`
`created_at` is the packing moment (ISO 8601). `name` is the user-visible name
and is optional.

## 3. Foundation: `base_image` / `runtime` / `gpu` / `fingerprint`

### `base_image` (**optional since 2.3**) `[schema]` `[measured]`

The foundation the environment sits on: a container image, pinned by the content
digest the registry computed for it. The tag (`:2.4.0` and the like) is a
human-readable hint only.

| Sub-field | Required | Notes |
|---|---|---|
| `ref` | ✔ (inside the block) | e.g. `runpod/pytorch:2.4.0-py3.11-cuda12.4` |
| `digest` | ✔ (inside the block) | `sha256:<64hex>`, resolved from the registry by image name |
| `digest_kind` | | **Added in 2.3**: which layer that digest belongs to, enum `platform` / `index` (below) |

**Why 2.3 demoted it to optional** -- a three-way contradiction that stood for
two years: the schema listed it as required with a strict format; the packer
**cannot see its own container's image name** (a boundary found by running real
hardware); and the rebuild **does not need it** (measured: nests carrying
placeholder text restored successfully anyway). The only way out was to write a
placeholder, **and a placeholder cannot pass this schema's own format check** --
an audit of previously produced nests found none that validated. The side that
had to change was "required".

**Both sub-fields remain required inside the block, with the format unchanged.**
What was relaxed is "this block may be absent entirely", not "it may appear half
filled": half a foundation misleads worse than none, because downstream will try
to pull an image name that cannot be found. If the digest cannot be resolved,
omit the whole block (§1.1).

**Two honest statements about longevity that must be made** `[2.3]`:

1. **The image bytes are not archived.** The nest records which image the run sat
   on, not the image itself. So the system layer of a rebuild -- OS, drivers,
   CUDA runtime -- **depends on the image still being available upstream**; once
   it is deleted or overwritten, this field has archaeological value only.
   Same character as the `python_lock.pinned_wheel_urls` disclosure:
   **archive what can be archived, say plainly what cannot, never pretend the
   coverage is total.**
2. **For a multi-architecture image this records the platform digest, not the
   index digest.** One tag covers different images on x86 and on ARM, with an
   index layer tying them together; each has its own fingerprint, and the two
   **look identical** (`sha256:` plus 64 hex characters), so the value alone
   cannot tell you which you have. Therefore: **record whichever layer you
   actually obtained** (`digest_kind`: `platform` = the image for one CPU
   architecture, **which is the one you want**; `index` = the layer above them),
   and **if you cannot tell, omit the field -- do not convert, do not guess**.
   Get the layer wrong and pulling by that digest fetches a different
   architecture, and that failure's error message points nowhere near the cause.

Bare-metal and container-less packing: see §9. Since 2.3 that case has an answer
-- omit the whole block.

### `runtime` (required) `[schema]`

| Sub-field | Required | Notes |
|---|---|---|
| `python_version` | ✔ | `^3\.\d+\.\d+$`, e.g. `3.11.9` |
| `cuda_version` | | e.g. `12.4` |
| `gpu_model` | | GPU at creation time (e.g. RTX 4090). **Informational, not a rebuild constraint** |
| `driver_version` | | Driver version |
| `libc_version` / `platform_tag` | | **Added in 2.4**: what decides whether a pre-built wheel installs here |
| `native_libs` | | **Added in 2.6**: which operating-system libraries the working run needed the machine to provide |
| `contested_modules` | | **Added in 2.8**: for every folder several installed packages write into, which package the working run's copy came from |

`gpu_model` is explicitly marked as not a rebuild constraint -- rebuilding on a
different card is legitimate.

**`libc_version` and `platform_tag` (2.4) -- what decides whether a pre-built
wheel installs here.** The C library version is the machine's, for example
`2.35`; the platform tag is the packing machine's Python tag, for example
`linux-aarch64`. Read together with the Python version, these are what a
pre-built wheel is matched against, so a nest packed on a newer C library can
hold wheels an older machine cannot install. **The authority is the tag, not the
C library alone** -- one machine reported 690 acceptable tags, and the C library
is only one of the things shaping that list. **Advisory only: warn, never
refuse.**

**`native_libs` (2.6)** -- `{ "method": "loaded" | "declared", "names": [...] }`.
These libraries belong to the machine's distribution, not to the nest, so they
cannot be packed; a machine missing one restores every byte correctly and still
loses whole plugins `[measured]`. Three obligations on anyone writing or reading
this field, each of them the result of a measurement that went the other way:

| Rule | Why |
|---|---|
| Names are **copied exactly as the program asked for them**, normalised in neither direction | Most entries name a file that does not exist under that name -- the driver library is asked for as `libcuda.so.1` while the file on disk carries the driver version, and one package asks for a name that already carries a minor version `[measured]` |
| **Machine-provided is decided by where the library actually loaded from at pack time**, never by looking the name up | A common compression library sits under the same name inside an installed package while the run loads the machine's copy; the name lookup got it wrong on both chip families tested `[measured]` |
| `method: "loaded"` may block a rebuild; **`method: "declared"` may only ever warn** | `declared` is the fallback used when no running application could be found, and it covers only part of what is really loaded while also listing libraries never loaded at all -- one machine was missing four of them while producing images perfectly well `[measured]` |

**`contested_modules` (2.8)** -- an array; each entry describes one top-level
module that several packages in the lock all write into:

```jsonc
{
  "module": "cv2",                        // the import name = the folder they all write
  "candidates": ["opencv-python", "opencv-contrib-python", "opencv-python-headless"],
                                          // every such package the lock installs, in lock order (2 or more)
  "winner": "opencv-python-headless",     // which one the working run's copy belonged to; one of candidates
  "winner_evidence": {
    "file": "cv2/cv2.abi3.so",            // relative to site-packages: the compiled file whose bytes decide behaviour
    "sha256": "9e29…(64 hex)",            // that file **as installed** on the packing machine
    "method": "record_hash"               // how the winner was told apart: record_hash | libs_dir
  }
}
```

**Why the format carries it `[measured]`.** The OpenCV family all unpack into
one `cv2/` folder, so whichever installs last is the one that runs -- and the
survivor decides which operating-system libraries the module needs (the two
windowed variants ask the machine for `libGL.so.1` and `libxcb.so.1`; the
headless one does not). The lock pins names and versions, **not install
order**, and the installer runs in parallel: one nest restored three times
back-to-back on one machine got a different survivor on one of the three, while
`pip list` was identical every time. So neither the lock nor the package list
can say which copy will run; only the packing machine knows which copy the
working run used, and only the installed file's bytes identify it. On the
packing machine the survivor was told apart two ways, in this order:
`record_hash` -- one candidate's own installation record lists this file with
exactly the hash on disk; `libs_dir` -- the survivor's own search path names one
candidate's bundled-libraries folder (`opencv_python.libs`, and so on). Neither
worked -> the packer writes no entry and says so in its report.

**The hash is of the file as installed on the packing machine, never of a
wheel's copy, and it is not a promise about other machines `[measured]`.** One
package version ships several builds -- one per chip architecture, and for the
OpenCV family two Linux builds of the same version on the same architecture --
and which one lands depends on the machine installing. So the same package
measured on an ARM machine and on an x86 machine gives two different
fingerprints, and a consumer on a different chip (or whose installer picked the
other Linux build) may still see a different hash **after** reinstalling the
winner. That outcome is "same package, different build": said out loud, never
refused. (What the installer does not do is rewrite the file: measured on a
uv-installed environment, the survivor's bytes equal its package's own
installation record exactly, which is what makes `record_hash` the first method.)

**Consumer rule (both restore paths, and any reader you write).** After
installing dependencies, hash `winner_evidence.file` under site-packages. Equal
to `sha256` -> nothing to do. Different -> reinstall the `winner` **alone**, at
the pin the lock gives it and without its dependencies, so it writes last; hash
again. Equal now -> say that you reinstalled it. Still different -> say so and
carry on (on another chip architecture, or with another Linux build of the same
version, the bytes legitimately differ; the winner now writes last either way). **Never refuse a nest on this field**: it is a declared-level
statement, so it may only ever warn (the same rule `native_libs.method:
"declared"` lives under). A nest without the field behaves exactly as before.

**Writer rules.** `winner` MUST be one of `candidates`; every candidate MUST be a
package the lock installs; `candidates` has at least two entries (one package
is not a contest); when the survivor cannot be identified, write **no entry**
rather than a guess. `renest lint` refuses a winner outside its candidates and,
when it can read the lock, a candidate the lock does not install.

### 3.2 `gpu` (optional) — what the packing machine's cards were `[schema]` `[measured]`

The graphics-card block. It is what separates the "every byte matches and the
kernel still will not load" class of failure from the rest. Omit the whole block
when the packing machine has no GPU tooling; the agent uses it for a blocking
pre-flight check, the escape hatch only reports it.

| Sub-field | Added | Notes |
|---|---|---|
| `captured_on` | 2.0 | The card at packing time: `name`, `sm_arch` (`^sm_[0-9]+$`), `cuda_compute` (e.g. `8.6`) |
| `torch_cuda_arch_list` | 2.0 | Which card generations this environment's PyTorch actually holds compiled code for |
| `node_native_archs` / `package_native_archs` | 2.0 | Per-binary compiled targets, for binaries an extension brought with it and for pre-built Python packages (§3.1) |
| `min_vram_gb` | 2.0 | Performance expectation only. **Nothing writes it today**; kept for nests that already carry it |
| `observed_use` | **2.4** | How much video memory a run was *seen* to use: `max_used_bytes`, `sample_interval_s`, `samples` -- all three required together |
| `shares_system_memory` | **2.4** | true = the machine has no separate video memory and draws from system memory |
| `device_count` | **2.4** | How many cards the machine had. Absent = unknown, treat as one |
| `peer_access` | **2.4** | Whether the cards can reach each other's memory directly |
| `peer_link` | **2.5** | **What carries the traffic** between them, enum `nvlink` / `pcie` |
| `total_bytes_rounded_gib` | **2.4** | Video memory per card, **rounded to whole GiB on purpose** |

**`observed_use` (2.4) -- an observed maximum, not a high-water mark.** The
application keeps no counter of its own and the sampler is a separate process, so
all it can do is ask how much memory is free every few seconds and keep the
largest use it saw. Readings that far apart can miss a short burst, so the true
peak can only be higher, never lower. **That is why the figure may never travel
alone** `[measured]`: one run reported 3523 MiB from 68 readings (meaningful),
another reported 1 MiB from 5 readings because it crashed before touching the
card at all -- and a reader given only "1 MiB" would conclude the job needs
almost no video memory. **A shortfall against this figure may only warn, never
turn a machine away**; it is a floor that is too low by design. **Absent means
not measured, not "needs none"** -- on a machine that shares its memory with the
system the usual query returns nothing, so absence is the normal case there.

**`shares_system_memory` (2.4)** -- on such a machine the reported total is the
whole system memory (one reported 121.7 GiB `[measured]`) and the per-card query
answers nothing, so a memory figure measured there is not comparable with one
from a machine that has its own card. Omitted when the reading says neither way:
a wrong flag is worse than an empty one.

**`peer_access` (2.4) and `peer_link` (2.5) -- two questions, and neither
predicts the other** `[measured]`. Card count alone misleads: a machine with two
24 GB cards reported no direct path between them in either direction, so those
two are not one 48 GB pool and a recipe that splits a model across them fails
while the count looks right. And it must be measured, never inferred -- two
machines with their cards merely on the host bus and no bridge fitted answered
**opposite** ways. 2.5 exists because *whether* they can reach each other hid the
difference that matters: of four machines measured in one night, two pairs both
answered "yes" while one had a dedicated link (12 links per card, 25 GB/s each)
and the other only shared the host bus. For the question people actually ask --
can these two cards act as one bigger card -- those are not the same answer.
`peer_link` is read from the driver tool's topology map (a marker like `NV4`
between two cards means a dedicated link; `PHB` / `NODE` / `SYS` mean the host
bus or worse), and **absent is not `pcie`**.

**`total_bytes_rounded_gib` (2.4) -- rounded on purpose** `[measured]`: two
machines carrying the same card model reported totals about 7 MB apart, because
the amount reserved differs by host. Compared byte for byte, two identical cards
look different. Round first, compare after.

### `fingerprint` (optional) `[schema]`

Environment fingerprint, first layer: used to estimate success **before**
restoring, carrying **only scenario-neutral, functionally reproducible fields**.
Its job is the prior question "can this be installed at all", which does not
overlap with the recipe fields describing what to install (`code_deps`,
`python_lock`). Collected once, after packing completes and the application has
started cleanly.

| Sub-field | Required | Notes |
|---|---|---|
| `fingerprint_version` | ✔ | const `"1"`; evolves independently of `format_version` |
| `python.version` | ✔ | e.g. `3.11.9` |
| `torch.version` / `torch.cuda_version` | | The most common cause of extension conflicts in practice |
| `os.name` / `os.version` | | Operating system |
| `os.machine` | | **Added in 2.3**: CPU architecture of the packing machine (below) |
| `critical_packages` | | key = package name, value = version |

**`os.machine` (2.3)** -- Python's `platform.machine()` output; values look like
`x86_64` (most cloud hosts) or `aarch64` (ARM).

**Why it exists**: ARM GPU instances are now sold on the major clouds. Across
architectures, the wheel URLs pinned in the lockfile and the recorded container
image are **all void on the other chip**, and the resulting failure **points
nowhere near the real cause** -- the user sees a package that will not install or
a library that will not load, and does not think "this machine's chip is not the
same kind as the original".

**Crossing chip families is a certain failure, not a risk** `[measured]`:
Python dependency binaries are **built per chip family, one build per family**,
so a nest packed on an x86 machine **simply will not install** on an ARM one.
The correct strength for a consumer of this field is therefore a **hard stop**,
not "a note you may click past".

**This version only records the fact; the hard stop belongs to the pre-flight
check and is not built yet.** The record takes no part in deciding success or
failure, and at present **neither direction is blocked**. If it cannot be
probed, omit the field (§1.1).

**Boundary of this block**: it **does not record the host application's commit**
(`code_deps[].commit` already pins it, and recording it twice creates two
sources of truth), and key names that profile the subject matter are
**forbidden**. Consumption discipline: `restore.sh` **reports fingerprints, it
never blocks**; graded blocking lives in the agent (see `restore-protocol` §2).
Field overlap between `runtime` and `fingerprint` is discussed in §9.

## 4. The recipe: `code_deps` / `python_lock`

### `code_deps` (required, array) `[schema]`

Code dependencies: the application itself, the extensions installed into it, and
the user's own scripts and configuration. **Source is archived in full, so a
rebuild does not depend on upstream surviving.** Each entry:

| Sub-field | Required | Notes |
|---|---|---|
| `name` | ✔ | Dependency name |
| `role` | ✔ | **Required since 2.0**, enum `host` / `extension` / `user_code` |
| `repo_url` | | uri. **Optional since 2.0** |
| `commit` | | `^[a-f0-9]{40}$`, full 40 characters. **Optional since 2.0** |
| `archive` | ✔ | Blob of the source tarball (§7) |
| `install_path` | ✔ | Install path relative to the environment root |
| `post_install` | | Post-install command specific to this dependency (escape hatch; use sparingly) |
| `upstream_match` | | **Added in 2.2**: whether this code matches the upstream it claims |
| `license` | | **Added in 2.2**: licence of this code (shape in §8) |
| `exclude` | | **Added in 2.6**: array of strings; what packing deliberately left out of this archive |

#### `code_deps[].exclude` (2.6) — telling a complete source tree from a trimmed one

The pack spec has always had this field; the manifest threw it away. So a
recipient -- including yourself six months later -- **could not tell whether the
code in a nest was complete or had been cut down**: same repository, same commit,
one directory missing, and nothing in the manifest looks wrong. It carries both
what the pack spec asked to leave out and **what packing decided to drop by
itself** (compiled `.so` files it expects to be rebuilt, and `build/`), because
the recipient's question is about the archive, not about who chose.

**This is disclosure, not an instruction.** A reader unpacks the archive as it
is; nothing here is replayed. Entries mean what they mean in the pack spec:
anchored to the archive root, so `models` removes only the top-level `models/`.
That anchoring is not a detail -- matching a bare name at every depth once
stripped source directories too, and the nest verified green by hash and died on
start-up `[measured]`. Ordinary junk (`.git`, `__pycache__`) is removed
automatically and is not listed.

#### `code_deps[].upstream_match` (2.2) — catching "popular extension plus three lines"

| Sub-field | Required | Notes |
|---|---|---|
| `state` | ✔ | enum `clean` (matches upstream) / `modified` / `no_upstream` (in no repository at all) |
| `changed_files` | | integer ≥0; how many uncommitted changes when `state=modified` |

**This is the one line of disclosure that catches "take a popular extension and
add three lines"** -- the most typical poisoning technique there is.
**The logic existed already; the result was being thrown away**: the code that
computes this had always run, but the answer only reached a hint shown to the
packer, never the manifest, so **the recipient never saw it**.

`no_upstream` is **an honest value, not a failure**: a fine-tuning user's config
and launch scripts legitimately live in no repository.
**When upstream identity cannot be established, omit the whole block rather than
guess** -- there is a specific trap here: a directory with no repository metadata
of its own resolves to an enclosing repository, attributing the host's identity
to an extension, and **wrong provenance is more dangerous than none**.

`renest lint` adds three semantic checks the schema cannot express: claiming
"modified" without saying how many changes → warning; claiming `clean` or
`no_upstream` while also reporting a change count → error; claiming "in no
repository" while also giving a repository URL → error.

#### `code_deps[].license` (2.2) — closing a structural gap

**Before this, models carried licence fields and code carried none.** The host
application uses a copyleft licence of the "use me and you must open yours too"
kind; extensions vary widely, and some forbid commercial use while others are
stricter still. **Handing a nest to someone else redistributes all of that
source.**

On the copyleft side we happen to comply (the full source travels with the nest,
which is exactly what the licence asks for) -- **but that was luck, not design**;
before 2.2 nothing could stop or even flag a non-commercial extension being
passed to a commercial user. The shape is identical to `files[].license`, §8.

**Why `role` is required, and why these three neutral words:**
- `host` = the application that gets run; `extension` = something installed into
  the host (a ComfyUI custom node is one); `user_code` = the user's own scripts
  and configuration.
- **It is not called `custom_node`** -- that is a ComfyUI term, and the core
  layer never names a specific tool.
- Making it required (rather than optional) is what let consumers **delete** the
  heuristic that inferred the role from whether `install_path` contained
  `/custom_nodes/`. That heuristic was the one place the server hard-coded
  ComfyUI's directory layout, it sat directly on the user-visible recipe view,
  and for a fine-tuning nest (which has no such directory) it declared
  everything to be the host, sweeping the user's own training config in with it.
- Only the window before there are real users can afford a newly required field.

**Why `repo_url` and `commit` became optional** `[measured]`: a fine-tuning
user's dataset config and launch scripts are **usually in no repository at all**.
The escape hatch **never clones** -- it fetches the tarball by `archive.sha256`
and unpacks it, using `commit` only for a log line -- so making these optional
does not weaken the rule that the escape hatch depends on nothing of ours.

**Recipes, not outputs**: the source archive contains source only. Models travel
as separately content-addressed `files[]` entries and are **never mixed into the
source tarball** (otherwise the same bytes are stored twice).

### `python_lock` (required; `lockfile` **optional since 2.3**) `[schema]`

A deterministic dependency lock produced by `uv`, the Python resolver and
installer this project standardises on.

| Sub-field | Required | Type | Notes |
|---|---|---|---|
| `tool` | ✔ | const `"uv"` | Always uv |
| `lockfile` | | blob | The lockfile itself (§7). **Optional since 2.3** |
| `lockfile_path` | | relpath | **Added in 2.6**: where that lockfile sat in the environment |
| `pinned_wheel_urls` | | integer ≥0 | **How many packages are pinned to a direct wheel URL** (a count, not a list) |
| `wheels_archived` | | boolean (default false) | true = the wheels are archived too (resists link rot, costs size) |
| `hosts` | | array of string | **Added in 2.2**: which hosts installing dependencies will contact |

**Why `lockfile` became optional, and the packing discipline that goes with it**
`[2.3]`: some environments have no lockfile at all (the desktop build of ComfyUI
produces one such). The schema used to demand one, so the packer had to either
fail or fabricate. From 2.3, in order:

| Case | Situation | What to do |
|---|---|---|
| ① | A lockfile exists | Archive it as-is |
| ② | No lockfile, but **the interpreter that runs this environment can be found** | **Ask it for the installed package list** (reading a fact, not guessing); archive that and state the source in the report |
| ③ | Not even the interpreter can be found | **Leave the field empty and warn.** Do not invent |

A nest with this empty **cannot rebuild its Python environment**. That is its own
honest labelling, not a defect: `renest lint` warns `lockfile-missing`, and the
restore path says so at the first step.

> **The two legs are deliberately strict to different degrees**: the agent
> (`renest restore`) refuses a nest with no lockfile and explains why; the escape
> hatch **degrades and continues** on the same input (skips dependency install,
> carries everything else). This is not an oversight -- the escape hatch's job is
> "get the bytes back no matter what", the agent's job is "either give you a
> working environment or say clearly why it cannot".

**`hosts` (2.2)** -- which hosts a rebuild will contact when installing
dependencies. Host names only, never full URLs: a host name already answers "who
will my machine talk to", while full URLs would blow up the disclosure surface.
Why it exists: those addresses are buried **inside** the lockfile, invisible on
the disclosure surface, and an unfamiliar host name is the plainest possible
signal. It pairs with the hard allowlist of trusted sources -- **disclosure is
the advance notice for that hard stop, not a substitute for it**: disclosing
without blocking is a disclaimer, blocking without disclosing leaves someone
facing an unexplained failure in front of the machine.

**`lockfile_path` (2.6)** -- where the lockfile sat in the environment, relative
to the environment root. Until 2.6 the manifest did not carry it, so both restore
paths landed the lock at `requirements.lock` in the environment root by fixed
convention, and both said so in a source comment. **The fine-tuning frameworks
keep theirs in a sub-directory**, so packing them moved the file somewhere the
framework does not look. **Absent = the old fixed landing spot**, which is what
every 2.0-2.5 nest gets. Written only when the lock really was a file in the
environment: under case ② above the list was read out of the interpreter and
there is no original path, so the field stays out rather than naming one that
never existed.

**`pinned_wheel_urls` is an honest counter**: packages carrying a local version
segment (for example `torch==2.4.1+cu124`) exist only on a vendor's private
index and not on PyPI, so packing must pin them to a direct wheel URL or the
rebuild dies during dependency installation `[measured]`. It also tells
downstream that this lock's reproducibility depends on that wheel host staying
up. **Note**: the actual URLs and their hashes **live inside the `lockfile`
blob**; the top level exposes only a count -- which is where the escape hatch's
"no uv available" fallback problem comes from (§9).

### 4.3 `entrypoint` (optional) `[schema]`

**Added in 2.0.** Moves "how the working run was started" out of the restore
path's hard-coding and into the nest. Both shapes were exercised on real runs:
training is `oneshot` (criterion = exit code), an image-generation server is
`service` (criterion = an HTTP probe).

| Sub-field | Required | Notes |
|---|---|---|
| `kind` | ✔ | enum `oneshot` (runs and exits) / `service` (long-running) |
| `argv` | ✔ | An **array** of strings, not one command line -- this avoids shell quoting problems and lets `redactions` address elements by index |
| `cwd` | | Working directory relative to the environment root; no absolute paths, no `~`, no `..` |
| `env` | | **Allowlisted object**, below |
| `success.exit_code` | | Success criterion for `kind=oneshot` |
| `success.expect_artifact` | | **Added in 2.1**: the artefact that should appear, relative to the environment root |
| `ready_probe` | | Readiness and smoke criteria for `kind=service`: `http_get` / `smoke_get` / `timeout_s` |
| `redactions` | | Array of redaction records, below |

**`env` accepts allowlisted keys only, and explicitly refuses `PATH` and
`HOME`.** The permitted keys are `VIRTUAL_ENV`, `CUDA_VERSION`,
`LD_LIBRARY_PATH`, `HF_HOME`, `HF_HUB_CACHE`, `FORCE_TORCHRUN`; anything else is
rejected by the schema. The first three come from measured run contexts; the two
model-cache variables correspond to the two home-directory roots added in this
version; the last has upstream documentation behind it but was never exercised
on real hardware, so it is permitted without being given any required meaning.
`PATH` and `HOME` are host-specific and the rebuild computes its own -- and
**the environment is the most common hiding place for secrets**, so accepting
the whole environment would pack credentials along with it.

**The four path-shaped keys have their values constrained too** (2026-07-26):
the values of `VIRTUAL_ENV`, `LD_LIBRARY_PATH`, `HF_HOME` and `HF_HUB_CACHE`
must be **relative paths inside the rebuild directory** -- no absolute paths, no
`~`, no `..`. For `LD_LIBRARY_PATH` **every colon-separated segment** must
satisfy this, and an **empty segment** (`a::b`, or a leading or trailing colon)
means "the current directory" and is rejected likewise.

> **Why pin this down now, when nothing reads the field yet** -- precisely
> because nothing reads it yet. The format permits these keys while their values
> are arbitrary strings; the day someone wires it up and really exports them,
> `LD_LIBRARY_PATH` becomes a **library hijacking** entry point (point it at a
> shared object inside the nest and it loads ahead of the system one) -- and by
> then the format is frozen and old nests exist, so **adding the constraint
> would be a breaking change**. This is exactly what "format before
> implementation" is for: **constraints must be fixed before a field is
> consumed**, and right now it costs nothing.

**Hard requirement on future consumers**: before exporting any of these values,
validate them again under the same rules as the file write gate
(`renest.roots.bad_entrypoint_env`) and **join them beneath the rebuild root**
rather than exporting them as-is -- the schema guards against a nest being
written wrong, the consumer guards against someone else's nest.

**`success.expect_artifact` (2.1) -- an exit code is not enough.**
Real hardware produced a false pass: a training script that could not find its
data logged `ERROR No data found` and **still exited with code 0**, so "exit code
0 means it worked" reported success while nothing had been trained. Hence this
field: **once declared, the artefact must exist for the run to count**, even with
the right exit code. The value is a path relative to the environment root (no
absolute paths, no `~`, no `..`), and the criterion is still declared by the
nest -- **the restore path never guesses at the framework**.

This does not conflict with "outputs never travel": what is recorded is **where
the artefact should appear**. The artefact itself, like user data, is **never
packed**.

**`redactions`: the record of redaction lives in the core layer, the knowledge
of what to redact lives in the adapter layer.** No general-purpose redaction
language is invented -- only someone who understands a given framework knows
which parameter is an output path. Each entry: `locator` (✔), `role` (✔, enum
`output_dir` / `output_name` / `log_dir` / `dataset`), `placeholder`, `note`.

`locator` **must support both forms**, because neither covers the other:
`{argv_index: 7}` (one framework's redaction points sit at command-line indices)
and `{file, key}` (that same framework hides its dataset path **inside a key** of
a config file, for example `datasets[0].subsets[0].image_dir`). Every value of
`role` comes from real runs: output-directory, output-name and logging arguments
point at outputs, while a dataset argument -- or a key inside the config file it
references -- points at the user's dataset.

**Timing of capture** `[measured]`: right after dependencies are installed the
model cache **is empty**; right after the base model is downloaded it holds only
the base model; **the tokenizer appears only after training has run**. So packing
at either of those two earlier moments misses the tokenizer, and the rebuilt
environment cannot run offline. This agrees naturally with the rule that we only
reproduce what already worked -- **capture must happen after a successful run;
that is a technical necessity, not conservatism.**

## 5. Assets: `files`

Large assets (models, LoRAs, VAEs, input material and so on), **always
content-addressed**. An array; each entry:

| Sub-field | Required | Notes |
|---|---|---|
| `path` | ✔ | Landing path, **relative to the root named by `root`** |
| `root` | | **Added in 2.0**, enum `env` (default) / `hf_hub` / `hf_home` (§5.1) |
| `blob` | ✔ | Content-addressed blob (sha256 + size, §7) |
| `license` | ✔ | Licence annotation (§8) |
| `origin_url` | | Original source; the only lead a recipient has when `serving_scope=gated` |
| `sources` | | Ordered list of alternative sources (below) |
| `kind` | | **Open string since 2.7** (lower case, digits, underscores, 64 chars max -- no list of permitted values). Only `clip` / `vae` / `tokenizer` / `input_asset` carry behaviour; see below |
| `serialization` | | **Added in 2.2**: whether loading this file executes code, enum `safetensors` / `pickle` / `other` |
| `declared_base_model` | | **Added in 2.4**: what this file's own header says about the model it was trained on (below) |

**`serialization` (2.2) -- whether loading this file executes code.**
The `pickle` family (`.ckpt`, `.pt`) is a Python serialisation format that
**executes on load**, the classic route for a poisoned model. `safetensors` is
data only and has no such property.

**Note this is a different axis from `kind`**: `kind` describes **purpose**
(base model / fine-tune / decoder), this describes **format**. The same
fine-tune can be either. It is determined by reading the file header at pack
time, at no cost; **if it cannot be determined, omit the field** (the honest
omission rule of §1.1). When everything is clean it is a **positive signal** and
should be shown: "all 40 models are pure-data format".

**`declared_base_model` (2.4) -- a transcription, not a judgement.**
The trainer writes these values into the file when it saves it; packing copies
them across and names where they came from. Sub-fields: `sha256` (the base
model's digest exactly as the header states it, lower case),
`family` (the base-model family as the header names it, e.g. `flux1` or `sd_v1`,
free text on purpose -- it is the trainer's word, not ours), and `stated_by`
(enum `safetensors_header`, **required whenever anything else here is present**:
a transcribed claim without its source cannot be told apart from a conclusion of
our own, and only one of those is allowed here).

Why it earns a place `[measured]`: a fine-tune recorded its base model's
**whole-file sha256**, and it matched the digest of the file actually fed to the
trainer, character for character; two fine-tunes by different authors recorded
the same base-model digest, and asking a public index by that digest returned the
expected model. So "which base model does this asset want" can be answered **by
bytes** -- without guessing, and without recommending anything.

**`sha256` here is the whole-file digest and nothing else.** Five digests
circulate in this ecosystem under the same name: the whole file; its first 10
characters; a 64 KiB window one mebibyte in, truncated to 8 characters (32 bits,
where collisions are a real risk); and two variants that skip the file header and
cover only tensor bytes. **Only the first is comparable with the addresses used
everywhere else in this manifest.** Lower case always -- one public index answers
in upper case while trainers write lower, and a plain string comparison then
fails. **Absent means the header said nothing, or was not read; it does not mean
the asset has no base model.**

**`kind` (open string since 2.7) -- what kind of asset this is.**

**Only four values mean anything to a program:**

- `clip`, `vae`, `tokenizer` -- a **shared part**. One text encoder or VAE sits
  inside dozens of unrelated models, so a content-hash hit on such a file
  identifies merely *some bundle containing it*, and that bundle's base model
  says nothing about this file. Licence adjudication therefore refuses to let a
  shared part's record speak for a base model (§8).
- `input_asset` -- the user's own material: listed, never packed.

**Every other value is a label for people to read.** It is shown in listings and
counted in summaries; nothing branches on it.

**Consumer obligation: a value you do not recognise is an ordinary asset.**
Never refuse a nest over it, never guess what it means, and display it exactly as
written -- not blank, not "unknown". A reader that keys behaviour off any value
other than the four above is reading a label as an instruction.

**Why the closed list went away (2.7).** One enumerated list was chasing an open
ecosystem, and every family it missed cost a whole version bump -- the eight-step
checklist, two byte-identical copies of the escape hatch, a human on a real
machine. On 2026-08-12, while building a deliberately messy test nest, three real
assets had no honest slot: the models of a top-five image-generation extension,
quantised weights, and video-model weights; the last two could only be filed as
`checkpoint`, which is not what they are.

**The shape rule is not a disguised list.** Lower case, digits and underscores,
64 characters at most: it keeps the value a machine token rather than a sentence,
so nobody has to decide whether `IPAdapter` and `ipadapter` are the same thing.
Every value legal before 2.7 satisfies it, so **no older nest is affected**.

Values in common use, none of them special: `checkpoint`, `lora`, `controlnet`,
`embedding`, `upscaler`, `tokenizer` (merges/vocab/tokenizer files),
`model_config` (config and generation-config files), `runtime_config` (the
launcher's configuration), `other`, and `license_text` (2.2). Language-model
weights reuse `checkpoint`; licence and readme files fall under `other`.

### 5.1 `files[].root` — landing roots and the home-directory allowlist

The original `path` implied "an asset is a file under the environment root",
which always held for image generation and broke for fine-tuning: a base model
lives in the model cache hub `[measured]`, a tokenizer lives there too **and is
only downloaded once a run has actually happened**, and the launcher's config
lives in the model-cache home and is required for training.

| `root` | How the root resolves | Permitted `path` (enforced by schema pattern) |
|---|---|---|
| `env` (default when absent) | The rebuild target directory | Unchanged |
| `hf_hub` | `$HF_HUB_CACHE` → `$HF_HOME/hub` → `~/.cache/huggingface/hub` | `^models--[^/]+/(refs/[^/]+\|snapshots/[0-9a-f]{40}/.+)$` |
| `hf_home` | `$HF_HOME` → `~/.cache/huggingface` | `^accelerate/[^/]+\.yaml$` |

**Why the allowlist is a schema pattern rather than an exclusion list on the
packing side** `[measured]`: training writes **the user's dataset** into the
model cache's `datasets/` directory, and datasets must never be packed. The two
ways of getting this wrong are **not symmetric**: a missing allowlist entry means
a rebuild is short one file and **the user notices**; a missing denylist entry
means **the user's dataset is uploaded and nobody notices**. Written as a
pattern, `datasets/…` **cannot be expressed in a manifest at all**.

**Rule R1 (enforced by `renest lint`)**: if any `root:"hf_hub"` entry lands under
`models--X/snapshots/…`, an entry for the same `models--X`'s `refs/<branch>`
**must** also exist. Measured on two independent paths: without that 40-byte
file, loading the model by repository name fails offline with "We couldn't
connect to huggingface.co" -- **a completely misleading error** that makes users
think their network is down and leaves them unable to diagnose it. So it has to
be enforced at packing time rather than left to whoever remembers.

**How files land (a hard constraint, not to be changed)** `[measured]`: files
land as **real files** under `snapshots/<commit>/`, **with their original names
and extensions; no symlinks are created and no `blobs/` tree is rebuilt**. The
reason was measured: one training framework resolves symlinks with
`os.path.realpath()` and then decides a file's type **by extension alone**, while
the cache's blob files **have no extension** → it calls `torch.load()` on a
safetensors file → `_pickle.UnpicklingError: invalid load key`, **an error that
points nowhere near the cause**. "Resolve the link, then judge by extension" is
a common pattern, not unique to that framework. Deduplication may therefore use
hard links or real copies, and **never symlinks**.

**Always compute hashes yourself** `[measured]`: the model cache's `blobs/`
directory is a **mixed namespace** -- large files are named by sha256, small ones
by a git object id (measured counter-example: a licence file whose blob name and
actual sha256 are completely different values). "The name happens to equal the
sha256" is usable as a **verification shortcut**, never as the only source: get
it wrong and verification **passes** (the value computed and the value stored are
the same wrong value) until the rebuild lands somewhere else and breaks.

**Traversal protection and the allowlist are two different things**: the pattern
is an allowlist and does not provide traversal protection. The `.+` at the tail
of the `hf_hub` pattern **will happily swallow `..`**. Rejection of absolute
paths, `~` and `..` lives at the write gate (`restore.sh`, `restore.py`,
`renest lint`) and **applies to every root**.

### `files[].sources` (optional, array) `[schema]`

An ordered list of alternative sources, nearest or fastest first. The agent races
them and verifies by sha256, so whichever wins is equally correct.
**The escape hatch does not read this field** (it uses the authoritative source
only). Reserved in the format; present or absent, it does not affect a rebuild.

| Sub-field | Required | Notes |
|---|---|---|
| `url` | ✔ | Source URL |
| `kind` | ✔ | enum `authoritative` (a source we guarantee exists and do not outsource) / `mirror` / `provider_cache` / `torrent` / `magnet`; the last four are optional accelerators verified by hash |
| `note` | | ≤200 |

> **The frozen shape is simpler than an early proposal**: only `url/kind/note`,
> with no priority, geography or chunk hashes. Those belong to a proposal that
> is not part of this format. See §9.

## 6. Scenario and boundary: `adapters` / `api_deps` / `post_install` / `creation`

### 6.1 `adapters` (optional) `[schema]`

The scenario adapter namespace; everything tool-specific outside the core fields
lives here.

**Opened up under control since 2.0**: known adapters (`comfyui`, `kohya`,
`llamafactory`) each **validate strictly**; unknown keys are permitted but
treated as **opaque objects** (required to be an object, contents unchecked).
Supporting a fourth framework therefore needs no version bump, while stray data
still cannot reach the core fields.

`adapters.comfyui`:
- `workflow` (**required if `comfyui` is present**): blob of the workflow JSON
  from the run that worked.
- `workflow_path` (**added in 2.6**): where that file sat, relative to the
  environment root. See below.
- `workflow_name`: string.
- `verified_run`: evidence for the "it worked" judgement -- `queue_completed_at`
  (date-time), `duration_seconds` (number), `output_samples` (array of blobs).
  **`output_samples` is never written** (2026-08-11 ruling) and the field is kept
  only for nests that already carry it: storing a sample would mean holding the
  user's own artwork and handing it on with the nest, and comparing against it
  would mean looking at what they drew. So the run check after a rebuild answers
  "this environment still produces something", never "it produces the same
  picture". **Absent is the normal case, not missing information.**

**`workflow_path` (2.6) -- three obligations, not suggestions.** Packing read the
path, hashed the bytes and then threw the path away, so restore had nowhere to
put the file back and parked it in a staging folder. That breaks the ordinary
journey "restore, change one thing, pack again" at the first step: the recipe is
not where the app looks for it. A reader must

1. put the bytes back at this path;
2. **keep the user's copy if something different is already there** -- leave ours
   in staging and say so in one line, never overwrite;
3. when the field is absent (every nest older than 2.6) **leave it in staging and
   say so -- never invent a path**.

Putting a file down is **not** starting the application: the ruling that keeps
the escape hatch out of the business of launching apps does not touch this, and a
nest whose recipe cannot be recovered is not a complete nest.

`adapters.kohya` / `adapters.llamafactory` (added in 2.0, identical shape):
- `config_files`: array of strings pointing at `files[].path`, marking which
  entries are **recipe files**. **No new concept is created** -- a recipe file is
  an ordinary `files[]` entry, so content addressing, verification and
  deduplication all come for free, and the adapter only names them. The two
  frameworks carry their recipe in completely different places (one entirely on
  the command line, the other entirely in a YAML file), so both carriers must be
  expressible.
- `verified_run`: `completed_at` / `duration_seconds` / `exit_code`. For
  fine-tuning the standard criterion is an exit code of zero, demonstrated on
  real runs of both frameworks.

### `api_deps` (optional, array) `[schema]`

Dependencies on external API services -- the part that cannot be archived.
**An honest-boundary field: the byte-for-byte reproduction promise does not cover
this list.** After a rebuild, whether these nodes work depends on the service
provider surviving and on the user supplying their own key.
Each entry: `node_name` (✔), `service` (✔), `endpoint_hint` (never a key),
`note` (≤300).

### `post_install` (optional, top-level string) `[schema]`

Global post-install command: system-level operations outside the image, written
by hand, for the escape hatch to run.

### `creation` (optional) `[schema]`

Metadata about where the nest was created: `cloud`, `region`,
`upload_bandwidth_mbps`, `agent_version`.

### 6.2 `derived_from` (optional, added in 2.4) — reserved `[schema]`

Which nest this one was made from, when splitting or merging nests produced it.
Two sub-fields, **both required once the block is present** (`nest_id`, in the
same form as this nest's own `id`, and `version`): a parent without a version
cannot be resolved to bytes.

**Reserved: the packer of this version never writes it**, because the feature
that would is not built. It is here so that the first implementation does not
have to bump the format again.

Two reading rules that matter more than the shape:
**absent means "not derived from anything", never "unknown"** -- read it the
other way and every ordinary nest looks as though it has lost its parentage; and
**it is a dead snapshot**, naming one specific version of the parent and not
following the parent's later versions. Anything that resolves it to "whatever the
parent is now" is a different product, and a surprising one: the point of a nest
is that it does not move.

### 5.2 Landing form: always a real file or a hard link, **never a symlink for deduplication** `[2.3]` `[measured]`

**This is a hard constraint and is not to be "optimised".** Deduplication may use
**hard links** (one set of bytes, several real names) or plain copies, **but
never symlinks** (a pointer to somewhere else).

**The evidence is a real failure on real hardware**: a training framework first
resolves a symlink to the real file behind it, then decides **by extension** what
kind of file it is -- and the content-addressed copy it points at **has no
extension**, so it read a pure-data model through the code-executing path and
reported something like `invalid load key`, **pointing nowhere near the cause**.
"Resolve, then judge by extension" is a common pattern, not one framework's
quirk.

**Corollary on the packing side**: if the **code directory being packed is itself
a symlink**, the tarball stores the link rather than the tree -- a 5 KB extension
packs to a few hundred bytes, **verifies byte for byte**, and unpacks to nothing.
The restore path must catch this.

**Exit code 24 (`SYMLINK_BROKEN`), conditions stated** `[2.3]`: when an archive
**verifies byte for byte but unpacks to zero members**, the restore path must
fail with code 24 and say plainly that the problem is not on this machine, that
retrying will not help, and that whoever packed it must replace the link with a
real directory and pack again. Landing point: the unpack step of
`renest.restore` raises `SYMLINK_BROKEN` when extraction yields zero members.

> Before 2.3 this code was **registered in the specification with no code
> anywhere producing it** -- an error code that exists only on paper is worse
> than none, because it makes people believe the case is handled.

### 5.3 One set of bytes referenced by several paths: legal, fetch once and land many `[2.3]`

The same sha256 appearing in several `files[]` entries under different paths is
**a legal shape, not an error** -- content addressing makes it inevitable: two
differently named files with identical contents are the same block of content.

**A restore path should deduplicate by content: fetch once, land in every
place.**

> **This is a "should", not a "must", and today's implementations do not do it**
> -- stated plainly so nobody assumes otherwise. Both legs currently **download
> repeatedly**: a model referenced N times is fetched N times. A 20 GB model
> referenced twice costs twice the time and twice the traffic.
> **This version writes the "should" into the specification; the implementation
> follows later.**

**Landing during deduplication is governed by §5.2**: the second and subsequent
places use hard links or real copies, **never symlinks**.

### 5.4 Reserved path: `.renest/escape/restore.sh` — the escape hatch travels with the nest `[2.3]`

`.renest/escape/restore.sh` is a **reserved path**. The packer places the
recovery script -- the one that unpacks a nest without any of our code -- there
as **an ordinary `files[]` entry** (`root:"env"`, `kind:"other"`), so its content
hash and size are recorded by the existing machinery. **No top-level field is
added for it**; version information lives in the script's own header comment.

**Why the convention exists.** The **entire reason** that script exists is "even
if this company is gone, your work comes back". Yet it **was not in the nest** --
a user would have to return to our repository and dig out the version from back
then, **which requires us to still be around**, contradicting the script's own
promise.

**The cost is close to zero**: tens of kilobytes, content-addressed, so one
version is stored once no matter how many people use it.

**The cost on the other side, which must be stated up front**: the copy inside a
nest is **frozen**, so later fixes never reach older nests. The honest framing
has two layers --

> **The copy in your nest is the floor**: at any time, even if we are gone, it
> gets your work back.
> **Our current version is better**: it has been fixed, and it reads several
> generations of older formats.
> **When you can reach us, use the current one.**

**The safety note (omitting it would open a poisoning route):**

> **A nest you packed yourself**: the script inside is the version from back
> then. Use it.
> **A nest someone gave you**: use your own copy. If you really want to use
> theirs, **check the content hash first** -- it is recorded in that same
> `files[]` entry, so checking is free.

## 7. `$defs.blob` — content-addressed file pointer

Every large file, archive, lockfile, workflow and sample uses the same blob
pointer:

| Sub-field | Required | Notes |
|---|---|---|
| `sha256` | ✔ | `^[a-f0-9]{64}$`, lower-case hex |
| `size_bytes` | ✔ | integer ≥0 |

Physical location is `<bucket>/blobs/sha256/<first two hex characters>/<full
hash>`. sha256 is a first-class decision -- it interoperates with the model-hosting
ecosystem, and it is not swapped for anything faster. Content addressing plus a
hard-link layout means the packing side lays out the blob tree first and then
uploads, and hard links on an overlay filesystem do not double the space
`[measured]`. The restore path verifies every byte of every blob.

### 7.1 Publication order is part of the specification

**A `manifest.json` appearing in the bucket means that nest is complete and
fetchable.** This is a **specification-level promise**, not one implementation's
internal detail -- both the agent and the escape hatch start from the manifest,
and on reading it they assume every blob it lists can be fetched.

Any implementation that publishes to a bucket (`renest pack --dest s3`,
`--dest hosted`, or a manual sync) **must** therefore:

1. **Write `blobs/` first, `nests/` second.** Only once every blob is in place is
   `nests/<id>/manifest.json` written.
2. **If any blob fails, write no manifest at all.** The worst state a bucket can
   be in is "bytes without a manifest" -- an **unreadable** intermediate state, so
   a rebuilder never starts and never sees half a nest. Writing the manifest
   first would create "a manifest without bytes", a **readable half-nest** whose
   rebuilder walks into a series of 404s.
3. **If it breaks, just run it again.** Blobs are content-addressed, so a re-run
   is naturally idempotent: objects already present with the same name and size
   are skipped, only the missing ones are sent, and the manifest is written last.
   **No manual cleanup is needed.**
4. **Abort failed multipart uploads** (`DELETE ?uploadId=…`). Uploaded parts do
   not appear in object listings but keep costing money until a lifecycle rule
   removes them -- not aborting leaves the user an invisible bill.

Users syncing by hand should follow the same order: finish `blobs/`, confirm,
then send `nests/`.

## 8. `$defs.license` — licence annotation

Drives the rules for sharing and for serving bytes. **Two orthogonal switches:**

| Sub-field | Required | Notes |
|---|---|---|
| `shareable` | ✔ | boolean. Governs **hand-off**: false = removed automatically on sharing, and the recipient gets self-service instructions |
| `serving_scope` | ✔ | enum `private` / `open` / `gated`. Governs **supply**: may these bytes be served across users from the deduplication pool |
| `spdx` | | e.g. `Apache-2.0`; empty for custom licences |
| `tag` | | Coarse class: `permissive` / `capped` / `rail` / `restricted` / `unknown` |
| `note` | | ≤500 |
| `declared_by` | | **Added in 2.2**: whether this licence was **looked up** or **stated by the user**, enum `detected` / `user` |
| `gated_form` | | **Added in 2.2**: the two shapes of "gated", enum `none` / `auto` / `manual` |
| `attribution` | | **Added in 2.2**: attribution requirements, `author` (≤200) + `url` |
| `text` | | **Added in 2.2**: where this asset's licence text is (blob, §7) |

**`declared_by` (2.2) -- who said so.**
Before 2.2 every licence in a nest was a claim the packer wrote into the input
spec, **never verified**, copied verbatim into the manifest as though it were an
adjudicated result. Without this field, a completed adjudication **cannot be told
apart from a transcription**. Absent = unknown (as in older nests). In a dispute
it answers "who said so". `renest lint` adds a check: claiming `detected` while
naming neither a licence nor a source → warning (that is an empty claim).

**`gated_form` (2.2) -- the two shapes of gated; do not collapse them into one
word.** `auto` = click to accept and download, a few seconds; `manual` = request
access from the author, **possibly days**. For a recipient those are **completely
different waiting expectations**. Confirmed by checking real model repositories
(2026-07-29): all three values occur in one batch of popular models.
`renest lint` adds a check: a gated form declared while `serving_scope` is not
`gated` → error (the two contradict each other).

**`attribution` (2.2) -- without it, the "use it however you like, just credit
me" class of licence can never be enabled.** Some licences permit any purpose
including commercial redistribution, **on the single condition of attribution**.
Recording it is not enough -- the recipient's side must actually display it.

**`text` (2.2) -- the licence text travels with the bytes.**
One family of licences requires the usage restrictions to be **delivered together
with** the asset, and the most direct, least error-prone way is to let the text
travel with the bytes rather than mention it in terms of service.

**Approach: carry the standard text, do not scrape it from the source.** Three
cases were measured, and the third rules out fetching from the repository: the
text is in the repository and was downloaded locally (fetchable); it is in the
repository but is not included when the model is downloaded; and **the repository
has no licence file at all** (measured on a widely used vision model: none of its
13 files was one). There are only a handful of licences on the list and one
canonical text each, so the tool ships them.

It points at an ordinary `files[]` entry with `kind=license_text` -- content
addressing, deduplication and verification all free, and one copy of each licence
text stored no matter how many nests reference it. `renest lint` adds a check:
if the bytes `text` points at **are not in this nest** → error (that is not
carrying it, and carrying it is the requirement).

The three levels of `serving_scope` are decided at capture time, fixed when the
nest is sealed, and executed as written by the restore path with no on-the-spot
discretion:
- `private` = the sharer's own asset (self-trained weights, workflows, own
  material), served directly to authorised recipients;
- `open` = the licence itself permits redistribution (Apache-2.0, MIT,
  redistributable OpenRAIL), so the cross-user pool may serve it as an
  accelerator;
- `gated` = a restricted licence (non-commercial model weights, assets whose
  terms forbid re-hosting), where a copy serves only its owner's rebuild, bytes
  are never served across users, and downstream receives `origin_url` plus the
  sha256 and fetches it with their own credentials.

**Deny by default**: when no licence can be determined, the value is `gated`.
**Constraint**: `gated` implies `shareable` must be false (the schema does not
enforce this implication conditionally -- see §9).

## 9. Known ambiguities — what already has an answer, and what is still open

> Discipline: this section records semantic vagueness and design tension found
> while freezing the format. **It is not resolved inline in the body** -- that
> would be a change, and changes get a version number.
> **2.3 rewrote this section**: four of the original seven entries had been
> resolved by later versions while still being listed as ambiguous, and a list
> that presents solved problems as unsolved makes readers re-think things that
> have already been thought through. **Resolved entries now say which version
> resolved them and where it landed.**

### 9.1 Already answered (kept so readers know the question was asked)

- **✅ The meaning of "ignore unknown fields"** -- **fixed in 2.3, see the reader
  obligations in §2**: within one major version an unrecognised optional field
  **must be ignored and must not cause rejection**, and a newer minor version
  **warns and proceeds**. Strict validation belongs to `renest lint`, not to the
  restore path. Landing points: `renest.restore.newer_minor_within_major` and
  the escape hatch's `2.*` branch.
- **✅ `base_image` on bare metal** -- **resolved in 2.3**: the whole block became
  optional, and bare-metal or container-less packing **omits it** rather than
  filling in something false. See §3.
- **✅ The meaning of symlink deduplication** -- **fixed in 2.3**: never use
  symlinks, and the conditions that produce exit code 24 are now written down.
  See §5.2.
- **✅ One content, several paths** -- **2.3 states what should happen** (fetch
  once, land many) **and states honestly that the implementation has not caught
  up**. See §5.3.

### 9.2 Still ambiguous or still owed

- **a. Two independent version numbers**: `format_version` and
  `fingerprint.fingerprint_version` evolve separately and their relationship is
  not written down; consumers must read each on its own.
- **b. `pinned_wheel_urls` is only a count, the real URLs are inside the
  lockfile**: if the escape hatch takes its "no uv available" fallback it needs a
  dependency list with hashes, but the top level exposes only a count while the
  URLs and digests are buried in the lockfile. Whether to add a compatible export
  is undecided.
- **c. `runtime` and `fingerprint` overlap**: Python and CUDA versions are
  recorded in both. The division of meaning is clear (runtime = rebuild
  constraint, fingerprint = pre-flight), but the same fact exists in two places
  with no schema-level consistency check.
- **d. `sources` is simpler than an early proposal**: today `{url, kind, note}`,
  with no priority, geography or chunk hashes. Extending it later requires a
  migration story.
- **f. `gated` implies `shareable=false` is not enforced by the schema**: the
  implication is written in the licence block's description, with no conditional
  constraint checking it; today it rests on the packer and on `renest lint`.
- **h. Remaining defects in draft nests (not covered by 2.3)**: a draft nest
  inferred from an existing environment may still fail validation for two reasons
  beyond the placeholder text that 2.3 fixed -- (1) with no interpreter found,
  `runtime.python_version` is missing, and that field remains required because
  **a rebuild genuinely needs it**; (2) a model whose licence cannot be
  determined defaults to gated, and gated requires an origin URL. Neither is a
  format problem.

### 3.1 `gpu.package_native_archs` (optional, added in 2.0) `[measured]`

The GPU targets of **each pre-compiled extension** among the Python
dependencies. Same idea and same honesty rule as `gpu.node_native_archs` (if
probing yields nothing, nothing is recorded), applied to packages installed by
pip. Each entry: `package` (✔), `path` (✔, relative to `site-packages`),
`sm_list` (✔).

**The shape was decided after measuring, not written from a description.**
Measured 2026-07-26 on an RTX 3060 across three GPU libraries; the raw probe
output for 29 shared objects is on file. The measurements changed three design
decisions directly:

| What was measured | Effect on the field |
|---|---|
| Different binaries **inside one package** carry different targets (one library's seven probeable binaries had **three** different target sets) | **Record per binary; do not aggregate per package** |
| **18 of 29 binaries could not be probed** (62.1%): pure-CPU libraries, non-NVIDIA variants, C++ glue | **"Probe fails → omit honestly" is a required branch, not an optional one** |
| One attention library's main binary targeted sm_60/70/75/80/90 and **omitted sm_86** -- which was the packing machine's own GPU; conversely a quantisation library shipped targets **wider** than PyTorch's list | **Reading `torch_cuda_arch_list` alone is wrong, and wrong in both directions** -- a pre-flight check must intersect, not trust PyTorch |

**One more note for consumers**: a package may ship **one binary per CUDA
version** (one library shipped seven), selecting at runtime. So you cannot
naively intersect every entry of a package -- intersect **the ones that would
actually be loaded**. This field only records the shape faithfully; consuming it
belongs to the cross-generation migration work, not to this version.

## 10. What 2.0 changed (2026-07-26)

Reconnaissance first, format second -- fields were not designed by guessing: six
real runs (26.1 minutes, $0.034) plus four zero-cost local experiments. The
drafting principle was **evidence only, invent nothing**: any field that could
not be traced back to a measurement was not written.

| # | Change | Breaking | Evidence |
|---|---|---|---|
| ① | `files[].root` plus schema-pattern allowlists for two home-directory roots (§5.1) | No (absent = old meaning) | Real fine-tuning runs |
| ② | `files[].kind` gains `tokenizer` / `model_config` / `runtime_config` (§5) | No | Real fine-tuning runs |
| ③ | Top-level `entrypoint` (§4.3) | No (optional) | Real fine-tuning runs |
| ④ | `code_deps[].role` becomes **required**; `repo_url` / `commit` become optional (§4) | **Yes** | Real fine-tuning runs |
| ⑤ | `adapters` opens under control, adding `kohya` / `llamafactory` (§6.1) | No | Real fine-tuning runs |
| ⑥ | `gpu.package_native_archs` (§3.1) | No (optional) | Real hardware measurement, samples on file |

**Why 2.0 and not 1.4**: ④ is a breaking change, which by definition is a major
bump; together with ① and ③ this is no longer a small compatible patch. The
story is also clean: the format was widened to carry fine-tuning.

**Why 1.3 read compatibility was dropped**: there were no real users yet, which
is exactly the window for a clean break. Only a required `role` allows the
server's `/custom_nodes/` path sniffing to be **deleted immediately**; keeping
compatibility would mean carrying that sniffing forever.

### Explicitly not done

| Not done | Why |
|---|---|
| User datasets are not collected -- neither under the environment root nor in the model cache's `datasets/**` | Measured: training writes them there, and they must never be packed |
| Training outputs are not collected -- output directories, adapter weights, checkpoints, trainer state, TensorBoard events | Measured as the difference between two real runs |
| The whole model cache is not collected -- `blobs/`, `.locks/`, `trees/`, `.no_exist/`, `xet/`, `CACHEDIR.TAG` | Measured: the blob tree is unnecessary under the chosen landing scheme, and offline loading still succeeds without the negative-cache directory |
| Arbitrary absolute home paths are not supported -- only two controlled roots, each with a pattern | The asymmetric-cost argument in §5.1 |
| No conda support -- `python_lock.tool` stays `const: "uv"` | Reconnaissance found the fine-tuning frameworks all use pip and virtualenvs; the escape hatch's dependency list does not grow |
| No general-purpose redaction language | §4.3: knowledge of what to redact belongs to the adapter layer |
| No compatibility judgements, no curation, nothing that never ran | The product's standing limits, not relaxed for a new scenario |

### Ideas held back for lack of evidence

Keeping to "invent nothing", the following were **not** given fields: multi-GPU
and distributed training (only single-card runs were measured); pre-compiled
wheel coverage for several GPU libraries (not measured in that round); system
library probing (never triggered); Windows and hosts without symlink support
(documented upstream, not measured by us); multi-step entrypoints (for example
"configure, then train" -- the evidence did not settle whether that belongs in
`entrypoint` or in `post_install`).

### Two conclusions related to 2.0 that are **not** format changes

Two CUDA problems surfaced by real runs needed **rules, not fields**, so they
live in `data/doctor-rules.json` and travel through the existing update channel:
(1) if the lockfile contains several vendor packages belonging to different CUDA
major versions, warn at packing time; (2) before rebuilding, compare the CUDA
major version this machine's driver supports against the one the lock requires.
Both messages must make clear that **the user's graphics card is not the
problem** -- across five real failures, not one error message pointed at the real
cause.

## 11. What 2.3 changed (2026-08-08)

**In one line: purely relaxing and purely additive. Nothing was tightened, and
every 2.0 / 2.1 / 2.2 nest still reads.**
(That claim ships with a test that can falsify it:
`oss/tests/consistency/test_old_nests_still_read.py` exercises older nests
through all three legs -- shape check, product restore path, escape hatch.)

| # | Change | Breaking | Why |
|---|---|---|---|
| ① | `base_image` becomes optional (§3) | No (relaxing) | The packer cannot obtain it and the rebuild does not need it, while "required and unobtainable" forced placeholder text that fails this format's own shape check |
| ② | `python_lock.lockfile` becomes optional (§4) | No (relaxing) | Some environments have no lockfile at all; the companion is the three-case packing discipline (use the lock, else ask the interpreter, else leave empty and warn) |
| ③ | `fingerprint.os.machine` added (§3) | No (additive) | ARM GPU instances exist on the major clouds, and cross-architecture failures **point nowhere near the cause** |
| ④ | `base_image.digest_kind` added (§3) | No (additive) | Multi-architecture images have two identical-looking digest layers; without saying which, downstream pulls the wrong architecture |
| ⑤ | `gpu.torch_cuda_arch_list` wording changes from "will fail" to "will probably fail" | No (wording) | We do not probe intermediate code; where it is present the driver can compile on the spot and the machine **may work**. An overstated pre-flight makes people abandon a usable machine |
| ⑥ | Reader obligations written down (§2) | No (existing behaviour, made explicit) | The 2.1 release was purely additive and the escape hatch still rejected nests as bricks -- an obligation that is not in the specification does not count |
| ⑦ | Packing rule: omit rather than write placeholder text (§1.1) | No (discipline) | An audit of previously produced nests found **none that validated**; the root cause was that this rule existed only as a verbal convention |
| ⑧ | Reserved path `.renest/escape/restore.sh`, the escape hatch travels with the nest (§5.4) | No (additive) | A script that is not in the nest means the user must come back to our repository two years later, **which requires us to still exist** |
| ⑨ | Symlink semantics plus the conditions for exit code 24 (§5.2) | No (made explicit) | That error code had been registered on paper with no code producing it |
| ⑩ | One content, several paths: states "fetch once, land many" and states honestly that the implementation lags (§5.3) | No (made explicit) | Today it downloads repeatedly: a model referenced N times is fetched N times |
| ⑪ | The nine fields added in 2.1 and 2.2 whose meaning was never written up (§4, §4.3, §5, §8) | No (documentation) | The fields were in the schema while the authoritative prose lagged, leaving outsiders unable to read them |

### Explicitly not done (2.3)

| Not done | Why |
|---|---|
| No field recording intermediate-code targets | Never measured, so the shape is not fixed -- wait until real hardware provides a sample (invent nothing) |
| No draft or completeness flag | With two fields demoted, draft nests are legitimate by construction; `renest lint` expresses incompleteness as a warning, and **no second source of truth is created** |
| No top-level object for the in-nest escape hatch | It is an ordinary file entry; version information lives in the script's header comment |
| No relaxation of `entrypoint.env`'s key allowlist or path constraints | That is the defence against library hijacking, and it does not move |
| No relaxation of the three `files[].root` allowlists, and no new `kind` value | The in-nest escape hatch uses the existing `other` |

### Exceptions left open before freezing (they arrive later as compatible minor versions; older readers ignore rather than reject)

System-level dependency probing and system library versions; expressing multi-GPU
and multi-step training; per-extension load and verification status; layering of
private content blocks; node identity in an official registry; intermediate-code
target fields.
**What they have in common: each needs a paid measurement round before its shape
can be fixed.** Once the reader obligations of §2 are in force, their later
arrival will be ignored by older readers rather than rejected.

---

## 12. What 2.6 changed (2026-08-12)

**Purely additive, all four fields optional, so every 2.0-2.5 nest still reads.**
Nothing was tightened and nothing was removed.

The four have one thing in common: **packing already knew each of these and threw
it away.** The trigger was moving a nest by hand and finding the recipe was not
where the pack spec said it lived; the sweep that followed went through every
field in the format, one by one, against the code that writes it and the four
places that read it.

| # | Field | Breaks compatibility? | Why |
|---|---|---|---|
| ① | `adapters.comfyui.workflow_path` (§6.1) | No (additive) | Packing hashed the recipe and dropped its path, so restore parked it in a staging folder. "Restore, change one thing, pack again" breaks at the first step |
| ② | `python_lock.lockfile_path` (§4) | No (additive) | Both restore paths landed the lock at a fixed spot in the environment root **and said so in a source comment**; the fine-tuning frameworks keep theirs in a sub-directory |
| ③ | `code_deps[].exclude` (§4) | No (additive) | Without it a recipient cannot tell a complete source tree from a trimmed one -- same repository, same commit, one directory missing, manifest looks healthy |
| ④ | `runtime.native_libs` (§3) | No (additive) | Operating-system libraries cannot travel in a nest. A machine missing one restores every byte, starts, answers -- and silently loses whole plugins `[measured]` |

**Why four at once.** The expensive part of a version bump is not the field: it
is the eight-step checklist, keeping both copies of the escape hatch
byte-identical, and a human running the whole thing on a real machine afterwards.
Splitting these would have paid that twice.

### Also corrected in 2.6 (wording, not shape)

`adapters.comfyui.verified_run.output_samples` was still described here as "the
baseline for pixel-level comparison after a rebuild". That stopped being true on
2026-08-11, when storing samples was ruled out for good; the schema was corrected
then and this document was not. The prose now matches (§6.1).

### Explicitly not done (2.6)

| Not done | Why |
|---|---|
| No `workflow_path` for the fine-tuning adapters | They never had the problem: their recipe files are ordinary `files[]` entries and already carry their real paths |
| Nothing removed, although a sweep found fields nothing writes and nothing reads | "Nobody reads it" and "it should go" are different statements. A reserved field is *supposed* to have no readers, and two of these say so in their own description |
| No version number recorded alongside a native library name | Names are recorded exactly as asked for, and most of them differ from the file on disk precisely by version `[measured]`; adding a version would mean inventing one |
| No refusal on a `declared` library list | It covers only part of what is really loaded and lists libraries never loaded at all; one machine was missing four of them while producing images perfectly well `[measured]` |

## 13. What 2.7 changed (2026-08-12)

**One change, and it only relaxes**: `files[].kind` stops being a closed enum of
thirteen categories and becomes an open string with a shape rule. Every value
that was legal before is still legal, so every 2.0-2.6 nest reads unchanged and
nothing anywhere had to be re-packed.

| # | Change | Breaks compatibility? | Why |
|---|---|---|---|
| ① | `files[].kind`: enum removed, replaced by `pattern` + `maxLength` (§5) | No (purely relaxing; every old value still valid) | An enumerated list cannot keep up with an open ecosystem, and each miss cost a full version bump |

**What forced it.** Building a deliberately messy test nest on 2026-08-12 turned
up three assets with no honest slot in the list: the models of a top-five
image-generation extension, quantised weights, and video-model weights. The last
two could only be filed as `checkpoint` -- which is not what they are, and a
category that is wrong is worse than one that is unfamiliar.

**What the field is actually for.** Exactly one rule keys off it: `clip` / `vae`
/ `tokenizer` mark a **shared part**, whose licence record must not speak for a
base model. `input_asset` marks the user's own material. That is the whole of its
machine meaning; everything else it carries is a label for people. Marking four
values was never a reason to enumerate all of them.

**The one thing the relaxation costs, and what replaces it.** The old enum
refused `text_encoder` (a search-folder name) where `clip` belonged -- a mistake
that once cost a paid cloud run to discover. An open string cannot refuse it. So
the linter now *says* it instead: warning `kind-is-a-folder-name`, raised only
for folder names whose asset really is a shared part, and printed by `renest
pack` before the machine starts costing money. **A warning, never a refusal** --
refusing an unfamiliar category is the behaviour this version exists to remove.

### Explicitly not done (2.7)

| Not done | Why |
|---|---|
| No new enum values for IPAdapter / quantised / video weights | Adding values one at a time is precisely the practice this version ends |
| No change to `code_deps[].role` (`host` / `extension`) | That list is genuinely closed and genuinely sufficient: it names our own two positions, not the world's asset families |
| No change to the licence rules themselves | The shared-part rule is untouched; this version only had to make sure relaxing `kind` did not weaken it |
| No case folding, no synonym table, no normalisation | Deciding that `ipadapter` and `IPAdapter` are the same thing is us deciding what things are. The shape rule makes the question not arise |

## 14. What 2.4 changed (2026-08-11)

**Purely additive, every field optional, so every 2.0-2.3 nest still reads.**
(Sections 14 and 15 come after 12 and 13 in this document only because they were
written up later; the versions themselves are in order.)

The fields were not picked from a list of what seemed likely to matter. Four
machines were asked what they could report, and **only what actually differed
between them was kept**; anything whose meaning was still unclear was left out.

| # | Field | Breaks compatibility? | Why |
|---|---|---|---|
| ① | `gpu.observed_use` -- with `sample_interval_s` and `samples` beside it (§3.2) | No (additive) | The figure alone misleads: one run reported 1 MiB from 5 readings because it crashed before touching the card |
| ② | `gpu.shares_system_memory` (§3.2) | No (additive) | On such a machine a memory figure is not comparable with one from a machine that has its own card |
| ③ | `gpu.device_count` and `gpu.peer_access` (§3.2) | No (additive) | Two cards are not automatically one bigger card, and the count alone says nothing |
| ④ | `gpu.total_bytes_rounded_gib` (§3.2) | No (additive) | Two machines with the same card model differ by megabytes; rounded first, they compare equal |
| ⑤ | `runtime.libc_version` and `runtime.platform_tag` (§3) | No (additive) | These are what a pre-built wheel is matched against; without them a nest can hold wheels the target machine cannot install |
| ⑥ | `files[].declared_base_model` (§5) | No (additive) | "Which base model does this asset want" becomes answerable by bytes, transcribed from the file's own header rather than judged by us |
| ⑦ | `derived_from` -- **reserved**, nothing writes it (§6.2) | No (additive) | Put in now so the first implementation of splitting and merging nests does not have to bump the format again |

### Explicitly not done (2.4)

| Not done | Why |
|---|---|
| No requirement figure derived from `observed_use` | It is an observed maximum sampled from outside, so the true peak can only be higher. Turning a floor into a requirement would turn machines away wrongly |
| Nothing that judges whether an asset and a base model belong together | `declared_base_model` is a transcription with its source named; adjudicating the match is curation, which this tool does not do |
| No normalisation of the base-model family name | It is the trainer's word, not ours |

## 15. What 2.5 changed (2026-08-11)

**One optional field, plus two wording corrections; purely additive, so every
2.0-2.4 nest still reads.**

| # | Change | Breaks compatibility? | Why |
|---|---|---|---|
| ① | `gpu.peer_link`, enum `nvlink` / `pcie` (§3.2) | No (additive) | Recording only *whether* the cards can reach each other hid the difference that matters |

**What forced it** `[measured]`: of four machines measured in one night, two
pairs of cards both answered "yes" to whether they could reach each other -- one
over a dedicated link (12 links per card, 25 GB/s each), the other over the host
bus alone. For the question people actually ask, "can these two cards act as one
bigger card", those are not the same answer.

**Why a whole version for one field.** The rule on this page is that an optional
addition still gets a number (2.0 to 2.1 did). Editing 2.4 in place would leave
one version number describing two different formats.

---

## 16. What 2.8 changed (2026-08-17)

**One optional field, purely additive**: `runtime.contested_modules` (§3).
Every 2.0-2.7 nest reads unchanged; a nest without the field behaves exactly as
before on both restore paths.

| # | Change | Breaks compatibility? | Why |
|---|---|---|---|
| ① | `runtime.contested_modules[]` -- for each folder several packages in the lock write into, which package the working run's copy came from, identified by the installed file's fingerprint | No (additive, optional) | Same lock, same machine, back-to-back installs -> a different survivor on one of three tries, `pip list` identical every time. Only the packing machine knows which copy worked, and only the installed bytes name it `[measured]` |

**What forced it `[measured]`.** A real user environment carried
`opencv-python-headless` and `opencv-python` side by side; the windowed one had
won only because it was installed four hours later, seven extensions imported
`cv2` through it, and on a cloud machine without `libGL.so.1` all seven would
die with an error that names the library and not the cause. The environment
was alive by luck of install order -- and a lock cannot pin luck.

**Two steps, and why the first was not enough.** Step one (a tool change in the
same release, no format change): after installing, name what the survivor needs
that this machine lacks -- it turned a silent failure into a warning. Step two (this version): make the survivor the one that worked. A
warning alone cannot do that, because the packing machine itself may install a
different survivor next time; there is no stable "original" to check against
unless the nest pins it.

### Explicitly not done (2.8)

| Not done | Why |
|---|---|
| Not a general "install order" record | Order is not what a lock can promise and not what decides the outcome; the surviving bytes are. Recording the file is smaller and exact |
| No refusal on a mismatch | The statement is declared-level (read off installed files, not off the working run), and declared-level statements may only warn -- the same line `native_libs` draws |
| The list of contested families is not in the format | Which packages collide is world knowledge that changes without the format changing; it ships with the tool's rules today (`cv2` first) and can move to the signed rules bundle without a version bump |
| No per-file list, one file per module | The compiled module is what decides behaviour; the rest of the folder follows it |
