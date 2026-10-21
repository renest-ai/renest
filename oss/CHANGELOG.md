# Changelog

What changed for the person using `renest`. Dates are the release date.

## 0.1.28 — 2026-10-22

### `renest login` keeps waiting through a slow network
While `renest login` waits for you to approve the sign-in in your browser, it keeps checking
with Renest. Until now one dropped or slow reply ended it, often while you were approving, and
you had to start again with a new code. Now a timeout or a busy reply means it tries again a
little later, until the code itself runs out, and it tells you the network is slow. If it does
run out while the network is still down, it says the network was the problem. In the rare case
where you approved but the reply carrying the key was lost on the way, it says so and names the
key to revoke in Settings > Access before you sign in again.

## 0.1.27 — 2026-10-20

### A slow network no longer cancels a save or take-back you already approved
While the ComfyUI panel waits for you to approve a save or a take-back in your browser, it
keeps checking with your Renest drive. Until now, one dropped or slow reply ended the whole
thing, even after you had approved, and you had to start again and approve again. Now a
timeout or a busy reply just means it tries again a little later, until the approval itself
runs out; the panel says the network is slow and that it is still waiting. Listing your nests
and getting a nest's files for a take-back also try again a few times before giving up. When
it does give up, it says the network was the problem, not that nobody approved.

## 0.1.26 — 2026-10-20

### Take a nest back into the ComfyUI you are using
From the ComfyUI panel (comfyui-renest 0.1.13 or later) you can now browse the nests on your
Renest drive and take one back into the ComfyUI that is running. Each file is checked byte
for byte against the nest. Files that are already here and the same are skipped. When a file
of yours has the same name but different contents, yours stays where it is and the one from
the nest is put beside it in `.renest/kept/`. Nothing is installed: the panel lists what the
nest recorded about its environment (custom nodes, packages, GPU) next to what this machine
has now, and says plainly which ones are the same, changed, or missing. A file your drive
cannot hand out is listed with the address it originally came from. You approve each take-back
once, in your browser, signed in to the account that signed this machine in.

### Saving from the panel cleans up after itself
After your drive has checked a nest you saved from the panel, the copy Renest made beside
ComfyUI while packing is removed, so deleting the originals from your ComfyUI folder really
frees the space. Renest never deletes anything inside your ComfyUI folder; the panel lists the
files you could remove and leaves the choice to you. If the drive does not take the nest, the
copy is removed straight away; if the drive is still checking when the panel stops waiting,
the copy stays until a later take-back sees the check finished.

### Restoring a nest someone handed to you refuses files that would run as code
`renest restore` (and the escape hatch) now refuses any file in a nest that would land where
it gets run rather than read: program code and native libraries, browser scripts, files that
tell pip, uv or ComfyUI-Manager what to install, ComfyUI and ComfyUI-Manager settings, hidden
folders such as `.git`, and names Windows would quietly rewrite. Models, LoRAs, images,
workflows and training configs are not affected. This matters most for nests handed to you by
someone else; earlier versions let some of these files through, so update before restoring
one.

### Nest format 2.15
Nests saved from the panel record which ComfyUI environment they came from, so your drive can
group the workflows saved from one environment together. Earlier versions of `renest` still
restore a 2.15 nest: they say it carries a field they don't know and go ahead without it.


## 0.1.25 — 2026-10-17

### When your drive can't take a nest, the panel says why and what to do next
Saving from the ComfyUI panel used to end on "Job failed" when the Renest drive refused the
upload. Now the panel shows the drive's own explanation with a link to fix it ("See plans",
or "Make room or upgrade" when your storage is full) and offers to keep the nest on the
machine instead. A plan that can't store nests of your own is now told so before you are
asked to approve anything. Any other failure now carries its real reason too.

### "Save on this machine only" in the ComfyUI panel
After the preview, the panel offers two ways: save to your Renest drive (approved once per upload in
your browser) or save on this machine only. The
second is free, needs no account and uploads nothing; the panel says where the nest is and
that it is gone when the machine is.
This needs comfyui-renest 0.1.11 or later.

## 0.1.24 — 2026-10-17

### Save from the ComfyUI panel straight to your Renest drive, approved in your browser
New `renest login`: run it once in the machine's terminal, open the link it prints in a
browser where you are signed in, check the code, approve. What the machine keeps can only
*ask* for an upload. Each time you save from the ComfyUI panel, the panel shows a code and a
link; you approve that one upload in your browser, and only the account that signed the
machine in can approve it. The permission covers that one upload and is switched off when it
ends, fails or is cancelled. Cancelling while it waits withdraws the request.
`renest login` leaves an access token the machine already has alone; `--replace` swaps it.
This needs comfyui-renest 0.1.10 or later.

### A nest no longer carries the last nest inside it
When the folder you pack holds your nodes and models but not ComfyUI's own `main.py` (the
desktop app's layout, or ComfyUI started with `--base-directory`), nests land in a
`renest-nests` folder inside it. The next pack read that folder too, so every nest carried
the previous one and grew by its size. `renest-nests` is now never packed.

## 0.1.23 — 2026-10-11

### Restoring a nest someone handed you: every file that does not travel is named first
A nest handed to you leaves out the files whose licence does not let the sender pass them
on. `renest restore` used to say only how many there were, download everything else, and
then stop on the first missing one, naming that one alone. Fix it, run again, and it
stopped on the next.
Now the restore opens with all of them: path, size, and the address the nest records for
each. They come in two groups: "We will fetch these for you from their original source"
and "You need to provide these", with the reason next to each one. Nothing is shortened
to "and N more". `--check-only` and `--plan` print the same list and move no bytes.
(`--check-only` used to download the public ones.)

### Restore fetches publicly downloadable files from their original source for you
When the nest records where a withheld file came from and that address is public,
`renest restore` downloads it at the start of the download stage, before any of the
nest's own files, and checks it against the sha256 in the nest. Different bytes are a
failure for that file and are never kept. An address that turns out to be a web page is
reported as that, not as changed bytes.
Your Hugging Face token is used only when the file is on Hugging Face and needs your
account, and is sent only to huggingface.co. A file on any other host that asks for a
sign-in is listed under "You need to provide these"; no token is sent there.
On a nest someone handed you, an address on a host renest does not recognise is not
contacted at all until you name the sender (`--trust-sender "<name>"`), the same rule as
for unrecognised dependency sources. Add your own hosts with `RENEST_TRUSTED_HOSTS`.

### Restore stops before downloading when a withheld file cannot be had, and names them all
If any file that does not travel is neither fetchable nor already in place, the restore
stops before the nest's files and code are downloaded. One message names every such file
with its size, full sha256, recorded address, why it could not be fetched, and the exact
path to put it at. Put the files there and run the same command again: a file in place
whose bytes match is kept and the rest carries on. The exit code (16) and error class
(`OBJECT_MISSING`) are unchanged. `restore-report.json` lists each file under `gated`
with `size_bytes`, `sha256` and `put_it_at`.
A restricted file your own storage can serve (`--blob-base`, or a link in your own
restore code) is no longer listed as "does not travel".

### `restore.sh` names the files that do not travel, and keeps one you put in place
`restore.sh` now lists every such file before it downloads anything, with size, sha256,
recorded address and where to put it. It only tells: it does not fetch them and does not
stop there. It moves everything else, then stops once with the whole list (same
`BLOBMAP-MISS` code as before) instead of on the first one.
A file you had already put in place with the right bytes used to stop the script, because
it asked for a download link before looking at the disk. It now looks first and keeps it.

### `renest restore --plan` and the real run agree on what is already on this disk
`--plan` counted any file whose bytes matched as "already on this disk"; the run itself
only skipped files its own record listed, so a plan could say "0 to fetch" and the run
then downloaded everything again. Both now use one test: a file of the right size is read
and checked, and matching bytes are kept. `--no-resume` still downloads everything again,
and the plan now says so.

### The restore report says "written into home" for what it wrote into your home folder
`restore-report.json` had `home_files`, which read as "the home-cache files this restore
brought back" and looked like a miss when it was empty. It only ever listed files written
into your real home folder. It is now `written_into_home`, next to a new
`home_cache_files_in_restore_folder` count. `home_files` is still written, with the same
content, for anything that reads it.

### A missing system library named only by packages gets its install command up front
When a nest was packed while its app was not running, its system libraries are read off
the installed packages. If this machine lacks some of them, `renest restore` now prints
the one `apt-get` command that brings them, before the models are downloaded. It used to
appear only when the app failed to start, after the whole download. Nothing is installed
for you from that list and the run does not stop: some of those libraries are never used.

### `renest pack` records where each file came from
When you hand a nest to someone, files whose licence does not let you pass them on do not
travel; the recipient gets their checksum and, if the nest has one, the address to fetch
them from. Most nests had none, so the recipient was left to find the files alone.
`renest pack` now writes that address (`origin_url`, an existing field) for every file it
can derive one for, restricted or not:

- a file in a Hugging Face model cache, including the cache kept under the home folder:
  the repository, the exact revision and the file;
- a file in our known-files table: its pinned address;
- a file Civitai knows by its sha256: the download address Civitai gives for that exact
  file (the model version's page when it lists no such file).

An address you give yourself (`--download-url`, or `origin_url` in a pack-spec) still comes
first. **An address that carries a login, a key or a signature is never recorded**, whoever
supplied it: a presigned storage link or a Civitai link ending in `?token=…` is left out
and named in a warning, because a nest is handed to other people.

### Files in a Hugging Face cache are judged by the repository they belong to
A file from the Hugging Face cache under the home folder was looked up by its checksum
only, so most of them (configs, tokenizer files, the `refs/main` pointer) matched nothing
and were restricted. They now get the licence of their repository, read at the revision
the cache holds. This covers every kind of entry, including `refs/…` pointers and the
`.no_exist` markers. The known-files table is still asked first.

### A file can be marked "not passed on", whatever its repository says
The known-files table can now hold a row that keeps a file back, with the reason. The
first one is the CLIPSeg weights (`CIDAS/clipseg-rd64-refined`, `model.safetensors`): the
Hugging Face repository is tagged apache-2.0, but that tag was set by the person who
converted the model, and the author states that no licence is specified for the weights.
`renest pack` says so on that file, and records where the recipient can fetch it.

### Data files a custom node publishes in its own repository stay with its code
Since 0.1.21, anything in a custom node's folder that looked like a model or data file was
taken out of the node's code archive and looked up on its own, and restricted when nothing
vouched for it. That also caught files the node's author publishes as part of the node
(a popular preprocessor pack carries several), which then did not travel with a
hand-off. A file now stays in the code archive, under the node's licence, when the node's
own git repository tracks it and it is unchanged from the published commit the nest
names. Everything else is handled as before: a weight the node downloaded while running,
a tracked file you edited, a file committed only on your machine, and every such file in
a node installed without git.

### Two more ComfyUI loader nodes are recognised
`ConditioningLoader` (`models/embeddings`) and `SAM3DBody_Loader` (`models/detection`):
the file a workflow loads through them is now packed.

### `pack --dest hosted`: "uploaded, not confirmed yet" no longer reads as a failed pack
After the upload, `renest pack` waits for the server to check the nest. When that took
longer than the wait, the run printed "This is not a failure" and then closed on
"✗ Pack failed", exit code 20. Three changes:

- It waits longer for small nests: at least 10 minutes (was 2), still 30 seconds per GB
  above that and 30 minutes at most. While it waits it says so every 30 seconds, and that
  every byte is already stored, so stopping there loses nothing.
- If the server still has not answered, the last line is now
  `◷ Uploaded, not confirmed yet: nest … is on your Renest drive and the server is still
  checking it. Do not pack or upload it again. See the result:  renest list <nest id>`.
- `--json` says it at the top level: `"outcome": "uploaded_verification_pending"`,
  `"uploaded": true`, `"verified": null`, and `hosted.check_command`. The same word is in
  `failure.context.outcome`.

What did not change: `ok` is `false` and the exit code is 20 in that case, because the
server has not confirmed the nest and renest does not call anything stored and verified
before it has. A script should test `outcome` and run `hosted.check_command`, not pack
again.


## 0.1.22 — 2026-10-11

**Restoring with `restore.sh`:** a nest packed with 0.1.22 needs the `restore.sh` from 0.1.22 or later.
Older copies stop at the new place this format keeps model caches. The copy inside each nest
(`.renest/escape/restore.sh`) always matches the nest, so use that one.

### `renest restore` no longer asks you to install a library it has just installed
When the machine lacked a system library the working run used, `renest restore` offered to
install it, installed it, and then closed the same run with "this machine is missing 1
library file(s)" and the `apt-get install` command for it. The report said the same
(`machine_libraries_missing`, `environment_warning`). Running that command only got
"already the newest version". Restore now looks at the machine again after it installs
anything, so the closing lines, `restore-report.json` and the `--json` result describe the
machine as it is: what was installed is no longer named, and what is still missing (an
install you declined, one that failed, or a library renest knows no package for) is named
as before, with the command. `restore.sh` is unchanged: it never installs anything.

### Nest format 2.14: model caches some nodes keep under the home folder now travel
Popular nodes download real weights into caches under the home folder rather than into
`models/`: Hugging Face's cache (CLIPSeg, grounding-dino), rembg (`~/.rembg`),
transparent-background (`~/.transparent-background`) and insightface (`~/.insightface`).
No nest carried them, so a new machine downloaded them again, or failed when the source
was gone or wanted a login. `renest pack` now carries the files the working run used from
those four caches (and only those four; a cache is never copied whole): files the running
ComfyUI holds open, or that appeared while the run went. Each goes through the same
checksum, credential scan and licence lookup as any model; Hugging Face's access token is
never carried.

On restore they land **inside the restore folder**, under `.renest/home/`, and the app is
started with `HF_HUB_CACHE`, `REMBG_HOME` and `TRANSPARENT_BACKGROUND_FILE_PATH` pointing
there (`renest start` does this by itself; the closing lines print them for a hand-built
start command). insightface has no such setting, so its files are also copied into
`~/.insightface`: every file is named first, a nest someone handed you stops and asks
(`--trust-sender` or `--yes` answers), and a file already there with different bytes is
never overwritten. `restore.sh` prints the `export` lines, and copies the insightface files
only after you type `yes` or set `RENEST_ACCEPT_HOME_WRITES=1`. A nest that lists anything
else under the home folder (`~/.bashrc`, `~/.ssh/...`) is refused by `renest restore`;
`restore.sh` warns that it is dangerous and goes ahead only on an explicit yes, and even
then puts the file inside the restore folder, never in your home folder.

Hugging Face also keeps empty markers for the files a model repository does not have
(`.no_exist/<revision>/`, for example `processor_config.json` on CLIPSeg). They now travel
with the revision they belong to, so the restored cache does not ask huggingface.co about
those files again. Only empty files are carried from there. An empty file holds no
content, so it is never treated as restricted and pack does not ask for a download
address for it; restore writes it without downloading anything.

### The test render runs offline when the nest carries Hugging Face files
Restoring a nest with Hugging Face model files rendered the same picture without
downloading anything, but every load still asked huggingface.co for metadata. The app
that `renest restore` starts for its test render now runs with `HF_HUB_OFFLINE=1` when the
nest carries Hugging Face files, so a passing render shows the nest brought everything
the run reads. If you set `HF_HUB_OFFLINE` yourself, your value is used. If the render
stops because a file did not travel with the nest, the restore says so and tells you to
run it again with `HF_HUB_OFFLINE=0`. `renest start` does not turn the network off: a node
may fetch a new model later, and Hugging Face reads from the cache by itself when the
network is down.

### `pack --json` no longer lists carried files as not packed
When pack carried files the working run fetched for itself (or files you named with
`--add`), the printed warnings stopped naming them, but `capture_report.gaps` in `--json`
still said "… is NOT packed … pack again with --add" for each one. The gap lines are now
written again from what is actually left behind, in both places.

### What a nest does not carry is now written into it, and said again on restore
The list `renest pack` ends with (files the run fetched but did not need, data files a
node names outside the nest, a node's settings under `~/.config`, caches, packages whose
GPU build targets were not read) is now part of the nest as `capture_gaps` (format 2.14).
`renest restore` and `restore.sh` print it near the start, one line each. The closing words
say "Restored, but not complete" only for an entry marked as needed by the run; the exit
code never changes. `--json` readers get it in the result. For packages whose GPU build
targets were never read, the card check now says "unknown — not read at pack time" instead
of counting them as covered.

### Pack carries the files the working run fetched for itself
Some nodes download their own models the first time they run: a face-swap node put 13
files under `ComfyUI/models/`, a captioning node put 18 files (3.1 GB) there. `renest pack`
used to only name them and give you `--add` lines to paste. Now, when ComfyUI is still
running, pack works out when that ComfyUI started and when the picture the nest records
was written, and carries every file that appeared in between in a folder ComfyUI loads
models from (`models/` and `extra_model_paths.yaml` folders; temporary folders never
count, and a model copied in by hand with its old date kept does not match). A new file in a
folder ComfyUI loads by name (`checkpoints/`, `loras/`, `diffusion_models/`, ...) is carried
only when ComfyUI is holding it: the recipe names what it loads from those, and anything else
there is a download for later, so it is named instead. Each carried
file is listed with its size, and goes through the same checksum and licence lookup as any
other model: a file nobody vouches for is restricted, so it is never handed to someone
else. When ComfyUI is holding one weight file open and another one appeared beside it
(the same weights saved twice), the one it is not using is left out and named. When pack
cannot tell, it carries them all and says so. With no picture to measure against (a
`--workflow` that never ran here, or ComfyUI restarted since), nothing is carried on a
guess: the files are named, with the `--add` command, as before.

Pack also ends with a short list of what the nest does not carry: those files, data files
a node names that sit outside the nest, settings a node keeps under `~/.config`, the cache
a node fills under `~/.cache`, and packages whose GPU build targets were not read in time.
`--json` gives the same list as `capture_gaps`.

### A model in a folder a node named itself no longer makes an invalid nest
A model packed from a folder under `models/` that ComfyUI does not know (a node's own
`LLM/` or `facerestore-models/`) had that folder name copied into the nest as its type,
capitals and dashes included, and `renest lint` rejected the nest. The type is now written
in lower case with `_` for anything else.

### The card check now hears about small compiled extensions, not just the big libraries
When packing, `renest` reads which GPU generations each installed compiled package was
built for, so the check before a restore can warn when a card is not covered. That reading
has a time limit, and it used to spend it on PyTorch and the NVIDIA runtime libraries,
hundreds of MB each. Packages that sort alphabetically after `nvidia` (SageAttention, for
one) were never read. Those are the extensions most likely to be built for one card only.
Separately built extensions are now read first, PyTorch and the NVIDIA libraries last, four
at a time. If the limit still runs out, `renest pack` names the packages it did not get to
instead of leaving them out silently.

### restore.sh warns before unpacking a code archive whose links point outside it
`renest restore` already refused a code archive holding a link whose target is an
absolute path or leads out of the folder being unpacked. The standalone `restore.sh`
unpacked the same archive and kept the link without a word. It now lists each code archive
before unpacking it and, if it finds such a link, says plainly what the risk is and asks you
to confirm: type `yes` at the terminal, or set `RENEST_ACCEPT_ARCHIVE_LINKS=1` beforehand.
With your confirmation it unpacks the archive as it is; without it, it stops before
unpacking and says how to go ahead. Links that stay inside the folder unpack as before.

### A handed-off nest says its custom nodes are the sender's code
When someone hands you a nest that carries custom nodes, the "Handed to you by …" line now
adds: "Custom nodes in this nest are the sender's code and run on this machine when the
app starts." Setup commands and unrecognised download sources still stop and ask, as
before.

### Restore names files the app fetched for itself while it ran
Some nodes fetch their own model files the first time they run (a face-swap node fetched
8 files, about 0.88 GB). On an online machine the restore's test render still worked and
the restore said nothing, so a nest that was short of those files looked complete.
Restore now lists, per folder, the files that appeared under the restore folder while the
app started and ran and that the nest does not carry, with their sizes; says the app most
likely fetched them from the network, so a machine without internet access would most
likely fail there; and gives the `--add` flags to carry them next time. It is information
only: the result and the exit code do not change. `--json` readers get the same in
`fetched_while_running`. Renders, previews, settings and caches the app writes for itself
(`output/`, `temp/`, `user/`, `__pycache__`) are not counted.

### The card check sees packages built from source and stored in the nest
A package installed from a git repository is stored in the nest as its built wheel. What
its compiled files were built for was not recorded, so the check before a restore said
every compiled extension could run on a card it was never built for (SageAttention built
on an RTX 4090 for sm_89 only, restored to an sm_86 card). Pack now reads the stored
wheel itself and records its build targets with the other packages', and the check names
such a package on a card it does not cover. As for any other package, it is a warning,
never a refusal.

### CUDA libraries the Python packages carry are no longer machine requirements
Packed on a CUDA "devel" image, a run can load a CUDA library (for example
`libcublasLt.so.12`) from the image's CUDA toolkit while the environment's NVIDIA Python
packages carry the same library. Pack recorded it as a system library the restore machine
had to install (`libcublas-12-8`), a package only NVIDIA's own package source has, so a
restore on an image with the usual Ubuntu sources stopped before downloading anything.
Pack now leaves such a library off the machine list and says why. Separately, when
restore tries to install a package and the machine's package sources do not have it, it
no longer tells you to run that same install again: it says the package is not in this
machine's sources, and gives the two ways on (`--force` to go ahead, which works if the
nest's Python packages provide the library, or the image the nest was packed on).

### A damaged code archive fails with a plain sentence
When a code folder's archive held a link to a file the archive does not contain, restore
stopped with only `KeyError: linkname '...' not found`. It now names the folder, says the
archive is damaged, and that re-running will not help: whoever packed it needs to pack it
again.

### Symlinks that point outside the environment no longer break the restore
A code folder holding a symlink to somewhere outside the environment (an absolute path,
or a relative one that leads out of it) used to pack the link as it was. The link
carried this machine's path, often a home folder with your user name, and restore
refused to unpack it, so the whole restore stopped while packing had said the link would
only come back dead. Such links are now left out of the code archive and not followed;
pack names each one, and the manifest lists it under that folder's `exclude`. Links that
stay inside the environment travel as before.

### Packing your own folder from outside the environment shows how much goes in
When a package installed editable from a folder outside the environment is carried into
the nest, pack (and `--dry-run`) now says how many files and how many bytes of that
folder go in. Sizes in the dry run no longer count what a symlink points at, since only
the link would travel.

### A credential in a `.env` file is reported once, not contradicted
When a `.env` (or another file with a credential-like name) held something shaped like a
token, pack stopped and named it, but also printed "We did not find a credential in it"
about the same file. That second line is gone for files the scan stopped on.

### When ffmpeg could not be installed, the last words say so
If a custom node runs ffmpeg and restore could not install it (no root and sudo asks for
a password, no package manager it can drive, you said no, or the install failed), the
restore still finishes, but its closing line used to be a plain "✅ Done". It now starts
"Restored, but not complete", names ffmpeg, the node that runs it and the command to
install it. `--json` readers get the same in `machine_programs_missing` on the result
event. A failed install at that point no longer says the files "have not been downloaded
yet": they have. The escape hatch `restore.sh` repeats its ffmpeg notice after "Your
setup is back" as well.

### Models inside a node's folder are recognised by what they are, not by their name
Since 0.1.21, a model file that a custom node keeps in its own folder leaves the node's code
archive and gets its own licence check, so a hand-off does not pass it on under the node's
licence. That only caught the usual model file endings (`.safetensors`, `.pth`, `.ckpt` and
a few more). A model saved as `.pkl`, `.npy`, `.h5`, `.zip`, or with no extension at all,
still went inside the code archive. Pack now looks at the file's contents: pickles, zip and
other archives, NumPy, HDF5, GGUF, safetensors and TFLite files from 64 KiB up, and any other
non-text file of 1 MiB or more that is not a program, image, font, audio, video or PDF, are
stored as files of their own. Whatever we cannot confirm may be passed on stays restricted:
your own restores get it, a hand-off does not. This is about passing files on only, not about
how you or anyone else may use them. The same applies to folders installed from outside the
environment (`local-packages/`), to files you name with `--add` (a model put in the input
folder is no longer treated as your own input material), and to a second copy of a file the
nest already lists, which now leaves the code archive under the listed copy's licence. Icons,
fonts, web files, text and small data files stay with the code.

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
