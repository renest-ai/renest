# Changelog

What changed for the person using `renest`. Dates are the release date.

## 0.1.21 — 2026-10-09

### `pack --dest hosted` now says that it reports progress, and what
Uploading to your drive has always sent upload progress and facts about this machine
(GPU, driver, free disk space) back to your drive, unless you add `--no-report`. Restore
told you so; pack did not say a word. Pack now prints the same short note as restore when
the upload starts, before anything is reported, and the full field-by-field list with
`--verbose`. With `--no-report`, or when you are not uploading to your drive, it prints
nothing, because nothing is sent.

### The reporting note says exactly what it covers
The note used to say file names and anything about your models "never go back". That is
true of the progress report, and the note now says so. A nest stored on your drive is
stored there whole, with its file names and the prompts inside its workflows, and the
note now says that too. It also no longer reads as if the cloud you run on is always
reported: it is only when an environment variable on the machine names it. Both notes,
pack and restore, now also say that you can delete these reports under Settings → Run
reports on your drive, and that deleting your account deletes them too.

### When this machine's GPU will not start, restore says so
On a rented machine whose GPU could not be started, restore used to download every file,
install every dependency, and then report only "The app would not start", followed by
advice to run the same command again on the same machine. When the app or the test render
fails because CUDA could not initialise (for example "CUDA unknown error", "no
CUDA-capable device is detected", or NVML failing), restore now says that the GPU on this
machine could not be started, that your files and dependencies were checked and are in
place, and that the usual fix is to rent a different machine and run the same command
again. A card with no kernels for the packed build, or a driver too old for it, keeps its
own message.

The machine check before anything downloads now also asks the GPU driver directly
whether it can start CUDA, without needing PyTorch (`nvidia-smi` can look normal on a
machine in this state). If the driver answers "unknown error" or finds no GPU, and the
nest needs a GPU, restore stops there with exit code 63; `--force` goes ahead anyway.
Other answers only warn, and a machine where the driver cannot be asked is reported as
unknown, never as a pass. `renest doctor` shows the same line but never stops on it.

### A package installed in editable mode from outside the environment now travels
If your environment had a local package installed with `pip install -e /some/other/folder`,
pack used to only mention it, and both restore paths then refused the `file://` source and
stopped. Pack now carries that folder in the nest and points the dependency list at it, so
it is put back and installed on the new machine. renest's own development install and
folders over 100 MiB are not carried; those are still named.

### Programs a custom node calls, such as ffmpeg, are installed on restore
A node that runs `ffmpeg` or `ffprobe` as a separate program used to fail after a restore
with "file not found", and pack said nothing. Pack now names such programs, and restore
installs the missing ones the same way it installs git or a C compiler: it asks first,
`--yes` skips the question, and without permission it prints the command to run.

The standalone `restore.sh` now names them too: after it puts the code back, if a node runs
`ffmpeg` or `ffprobe` and this machine has no `ffmpeg`, it prints one line naming the node,
the program and the command that installs it. It never installs anything and never stops.

### A dependency installed from a folder on the packing machine is named as such
When a nest's dependency list installs a package from a folder on the machine it was packed
on (an editable or local-path install the nest does not carry), both `renest restore` and
`restore.sh` used to call it "servers nobody recognises", suggest trusting a host, and in
`restore.sh` print an empty `RENEST_TRUSTED_HOSTS=` line. No host setting can fetch a folder
that is not there. Both now say what it is, say whether that folder is on this machine, and
give the real fixes: pack again with the newest renest, which carries such folders, or
install that package from a published source on the packing machine and pack again. Restore
still stops before installing anything, as before.

### Code a custom node compiled in its own folder is kept
Compiled files built inside a node's folder (for example by `setup.py build_ext`) used to be
left out of the nest whenever the folder had a `setup.py` or `requirements.txt`, but nothing
rebuilt them on the new machine, so the node failed to load. They are now left out only when
the node has a step that rebuilds them on restore; otherwise they travel as they are, and the
GPU generations they were built for are recorded and checked before a restore.

### Pack names data files a node reads from outside its folder, and files it keeps in your home cache
If a node reads a file from elsewhere in the environment, pack now names it and gives the
exact `--add` line to include it. It does not add it on its own, because only you know
whether the node needs that file. If a node keeps files it downloaded in a cache under your
home folder, pack now says that these files do not travel with the nest and will be
downloaded again on the new machine.

### The warning about hand edits says what really happens
Pack warned that uncommitted edits in a node or ComfyUI folder "will be lost" because a
restore pulls a clean copy from git. That was wrong: restore puts back the exact folder you
packed, edits included. The warning now says the edits travel with the nest.

### Models a custom node downloads into its own folder get their own licence check
Some custom nodes download the models they need into their own folder the first time
they run (comfyui_controlnet_aux keeps them under `ckpts/`). `renest pack` used to store
those models inside the node's code archive, under the node's own licence, so a nest you
handed to someone carried them as if the node's licence covered them -- including
models whose licence forbids commercial use. Every model file inside a code folder
(`.safetensors`, `.ckpt`, `.pt`, `.pth`, `.bin`, `.onnx`, `.gguf`, `.sft`) is now taken
out of the archive and stored as a file of its own, with its own licence check. Any we
cannot confirm are restricted: your own restores still get them, a hand-off does not.
A restore puts each one back at the same path. A model file reached through a link to
another folder is now stored as the real file instead of a link that is dead after a
restore.

## 0.1.20 — 2026-10-07

### Your Hugging Face token only goes to Hugging Face
When a nest you were handed lists a download address for a restricted file, `renest`
fetches it with your Hugging Face token so gated models work. That token used to go to
whatever address the nest named, so a nest built to do so could collect it. A restricted
file's download address now only receives your Hugging Face token if it is on
huggingface.co (or hf.co) over https; any other address is fetched without it.

### Model weights saved as `.pth` now travel in the nest
SAM, upscaler and face-restoration models are often `.pth` files. `pack` used to treat
every `.pth` as program code and leave it out, so a workflow that loaded one could not
run after a restore. A `.pth` is now treated as code only inside a Python package folder
(`site-packages`, a virtual environment, `bin`), which is the only place Python runs one.

### Restore installs the tools it needs instead of only naming them
When a nest needs git, a C compiler or git-lfs and the machine has none, `renest restore`
now installs them itself (it asks first; `--yes` / `-y` answers for you). Without the
rights to install, it prints the exact command to run and the command to carry on.
Before, a missing git only showed up as "Installing dependencies failed", with the
real reason buried in the evidence log.

### `renest start` installs a missing C compiler and starts the app again
When the app started by `renest start` fails because a C compiler (or git, or git-lfs)
is missing -- triton's "Failed to find C compiler" the first time a model runs is the
usual case -- `renest start` now installs it the same way a restore does (it asks
first; `--yes` / `-y` answers for you) and then starts the app again. ComfyUI keeps
running when one picture fails, so this happens without waiting for it to exit. Without
the rights to install, it prints the exact command and leaves the app running.

### `renest pack` downloads Git LFS files a node folder is missing
A custom node cloned without its Git LFS files holds small placeholder files instead of
the real ones. `renest pack` used to refuse the whole nest over them, even when every
one was an example picture or video, and said the code would be missing, which was
not true. Now it offers to run `git lfs pull` in that folder (it asks first; `--yes` /
`-y` answers for you; it installs git-lfs first when that is missing and it has the
rights). When the files cannot be downloaded, placeholders for pictures, videos and
documents are left out of the nest, in one line that names them. Placeholders that
could be code or model weights still stop the pack, with the reason and the exact
command to run.

### Clearer wording for packages that are compiled on the restore machine
The note about a package pinned to a source archive used to read "ujson come(s) as
source code and is built on this machine". It now reads "ujson is pinned to a source
archive, so it is compiled on this machine" (and "... are pinned to source archives,
so they are ..." for several).

### The test render after a restore sends the workflow the way ComfyUI's editor does
After a restore, `renest` re-runs the workflow that worked to prove the environment
still produces something. On several community workflows that re-run failed although
the restored environment was fine. Three causes, all fixed:
- Some custom nodes write `NaN` into the recipe; the re-run refused to send it
  ("Out of range float values are not JSON compliant", exit 50). It is now sent as written.
- A list setting such as an empty LoRA list was sent bare, so ComfyUI took it for a
  broken link, skipped every node that saves a picture, and reported success with
  nothing written. Lists are now wrapped exactly as the editor wraps them.
- Nodes that read their settings from the editor's copy of the workflow (KJNodes'
  WidgetToString) stopped with "'NoneType' object is not subscriptable". When the
  nest carries that copy, it now goes along with the re-run, as it does from the editor.

### Nest names in other scripts stay readable in ComfyUI's Workflows list
A nest named in Chinese (or any non-Latin script) no longer loses those characters in
the sidebar workflow name. Slashes and characters that are unsafe in file names are
still removed.

### Packing on our template image records which image it was
`pack --auto`, `pack --workflow` and the ComfyUI panel now write the nest's image line
when the machine runs the Renest template image (it names its own version). Before, only
a hand-written pack-spec could carry it, so a restore that hit a missing system library
could not say which image to boot from. On any other image the line is still left out:
a container cannot see its own image name, and we do not guess.

### Restricted models get a download address whenever one can be proven
A restricted model never travels to someone you hand a nest to; they fetch it from its
source. `renest pack` now records that source by itself when it can be proven: the
Hugging Face model cache, the known-file list, or an address your ComfyUI workflow gives
for the file that Hugging Face confirms serves exactly these bytes. When there is none,
the pack output names each such file and the line to add one by hand — the new
`--download-url PATH=URL` flag.

### No more "restricted by default" for models the known-file list clears
`pack --auto` no longer keeps saying a model's licence is unknown after the known-file
list has cleared it as shareable.


### The machine check mentions CPU instructions the packing machine had and this one lacks
`renest pack` now records which instruction-set extensions (AVX2, AVX-512, AMX and
similar) the packing machine's CPU supports (nest format 2.13). Before a rebuild, if
this machine's CPU lacks some of them, the machine check adds a note: most software
runs fine without them, but a few prebuilt libraries assume them and can stop at
start-up with "Illegal instruction" -- so if the app does not start, a machine whose
CPU supports them is one thing to check. It is a note only: nothing is stopped and no
exit code changes. Nests packed before this record nothing and get no note.

### Packages installed from git or a direct download address travel inside the nest
A package installed from a git repository (like `sam-2 @ git+https://github.com/...`) or
from a direct download address (a GitHub release wheel, for example) now has the wheel
that was installed in your environment stored inside the nest, with its original source
kept beside it. A restore installs that wheel when it fits the machine's Python version
and platform, so it no longer needs git, a compiler or that website to be up, and the
step that installs missing git or a compiler skips such packages. When the wheel does
not fit, the restore installs from the original source and says why. If the wheel cannot
be obtained at pack time, packing still succeeds and says so in one line. Packages from
PyPI and the official PyTorch download site are not stored. Nests made this way are
format 2.13; older versions of Renest still restore them, from the original source.

### Wheel-pinning messages no longer point at a switch that does nothing
When pinning a vendor-only package (like `torch==2.4.1+cu124`) failed at pack time, or
its pinned wheel had vanished at restore time, the message suggested turning on
`wheels_archived` to store the wheel files inside the nest. That switch was never built —
it only recorded a flag, and it is now retired. The messages now say plainly that wheels
installed from a package index are not stored in the nest and a restore downloads them
again, and offer steps that work today: make the
index reachable and run `renest pack` again, or install the needed build by hand in the
restored environment.

### `renest pack` carries the models your run used, whichever node loaded them

- A model named anywhere in the workflow now travels when that file is in your
  models folder: inside a node's nested settings (rgthree's Power Lora Loader rows),
  in a list, or as a `<lora:name:weight>` tag in the prompt text. These used to be
  left out without a word. A LoRA row switched off in the node is named, not packed.
- IPAdapter's unified loaders (`IPAdapterUnifiedLoader`, `…FaceID`, `…Community`)
  take a preset name, not a file name. `pack` now asks the IPAdapter node pack itself
  which files that preset means, by running your ComfyUI's own Python (found in
  `.venv`, or given with `--env-python`) in a separate process, and packs them. When
  it can't ask, it names the files those loaders read from instead.
- New `--add PATH` (repeatable; a folder adds everything in it) packs a model on top
  of the ones the workflow names, checked and restored like any other. When `pack`
  finds a model this run may have used but could not confirm, it names the file and
  prints the full command with `--add` filled in, ready to paste.
- Every model file left behind is now named, whatever its size (smaller ones in one
  line, all of them in `--json` under `unreferenced_model_files`), not only those over
  128 MB.

## 0.1.19 — 2026-10-07

### `renest watch` works again
`renest watch -- <your training command>` crashed the moment it started
(`TypeError: unhashable type: 'list'`) in 0.1.15 through 0.1.18, so the first step of
packing a fine-tuning run could not be taken. It now runs your command and records what it
loaded, as documented.

## 0.1.18 — 2026-10-05

### `renest start` and the restore summary print the address to paste on RunPod and vast

- On RunPod, clicking ComfyUI's link on the provider's console page is refused by
  ComfyUI (HTTP 403); an address pasted into a new tab is not. `renest start` and
  the restore's closing lines now print that address on its own line —
  `https://<pod>-<port>.proxy.runpod.net` on RunPod, `http://<ip>:<port>` on vast
  when that port is mapped. Only when the command listens on every interface;
  anything we can't work out is not guessed.
- After the address, `renest start` now also says to expose the port as an HTTP
  port in your provider's panel, the same sentence the restore summary uses —
  RunPod's proxy only answers on ports opened that way.

### The official starter nests' models are recognised as redistributable

- The bundled known-files table now lists the 8 model files of the three official
  starter nests (FLUX.2 Klein 4B, Wan 2.2 TI2V 5B, Z-Image-Turbo), checked byte for
  byte against their Apache-2.0 upstream releases. They no longer come out
  restricted because a stranger re-uploaded the same bytes under a stricter label.

### Known files packed with `pack --auto` are no longer always restricted

- When nobody had said anything about a file's licence, the placeholder that
  `renest` fills in ("restricted by default") was treated as a claim and outvoted
  the lookup, so a file we recognise as redistributable still ended up restricted --
  stricter than writing no licence at all. The placeholder now stands aside when the
  lookup has an answer, and the entry is recorded as looked up.
- Nothing gets looser where someone said otherwise: a licence you wrote or edited by
  hand still wins when it is stricter, a file the lookup can't place stays
  restricted, and a record that forbids passing it on still restricts it.

### ComfyUI's own nodes are no longer reported as possibly missing a node pack

- Packing the FLUX.2, Wan 2.2 and Z-Image starters warned about 14 nodes that
  ship with ComfyUI (`KSamplerSelect`, `CFGGuider`, `SaveVideo`,
  `ModelSamplingAuraFlow` and more): our hand-kept list of built-ins was behind.
- Packing now reads the names of ComfyUI's own nodes from the ComfyUI program it
  packs — both the old and the new way nodes are declared, from the program
  folder on the desktop build — without running any of it. If that can't be read,
  the old list still applies. A node that really comes from a node pack is still
  reported.

### Pack warnings now say something you can actually do

- A model with an unknown licence: instead of "add the licence and origin_url"
  (which neither the panel nor `--auto` lets you do), it says what restricted means
  for a hand-off and, for a file you made yourself, to pack again with
  `--mine PATH`.
- A node we can't place: the advice now reads right whether you pack from the
  Renest panel or from a terminal.
- A big model your workflow doesn't load: load it in your workflow, run it once and
  pack again — no more pack-spec instructions.
- `pack --auto` on a setup that has never run: no more "fill workflow_path in by
  hand"; it says to run your workflow once in ComfyUI and pack again.
- A start script left outside the nest: only a script that mentions Python or
  `main.py` is named now, not every `.sh`/`.bat` beside the environment, and the
  advice is to move it into the application folder.
- "We can't tell which container image this ran on" is said once per pack, not
  twice.

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
