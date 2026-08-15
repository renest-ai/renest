# Local asset library layout, v2

> The desktop client's local library. Converts to and from the on-drive format
> without loss.
> v2 (2026-07-23) renamed the nest directory level to `nests/`, in step with the
> on-drive format. Structure unchanged; a rename only.

    MyRenestLibrary/
    ├── nests/<nest-id>/manifest.json    # structurally identical to nests/ on the drive
    ├── blobs/sha256/<first 2 chars>/<hash>   # content-addressed, identical to blobs/ on the drive
    ├── workspace/                        # loose material, not yet packed
    │   ├── workflows/   workflow drafts
    │   ├── inputs/      reference and input images
    │   └── prompts/     prompt library
    └── outputs/<nest-id>/                # finished work, filed under the nest it came from

Rule: the `nests` and `blobs` levels are structurally identical to the cloud
drive, so uploading and downloading are plain copies -- no format conversion and
no sync engine.
