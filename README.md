# R2 runners — exact source-file handoff for game development

**Primary goal: give ChatGPT/development agents the exact Cloudflare R2 files they need to decode, test, and integrate real game assets.** This repository is an isolated GitHub Actions data-transfer and validation workspace, **not** a metadata-only audit service.

## Non-negotiable source-file contract

1. **Fetch the actual requested data.** Use the public `https://r2.houseofkublai.com/` origin and explicit R2 object keys or authenticated source-archive indexes. Select the precise files a task needs: original PAK/FF/IWD objects, or byte-for-byte original cooked UE package payloads extracted from verified PAK spans. Do not fabricate equivalent files or use guessed source layouts.
2. **Keep exact bytes and original names/paths.** Validate source sizes and hashes (SHA-256 for complete R2 objects; retail PAK index/entry SHA-1 where available). Do not transcode, downsample, replace, or silently omit requested assets. A decompressed package payload is a distinct verified source file; do not mislabel it as a complete PAK.
3. **No artificial file-size ceilings.** The downloader streams files regardless of their original length. Do not impose a 10 MiB, 200 MiB, 850 MiB, 10 GiB, or other application-defined maximum that prevents obtaining the exact needed source. Retain expected-size and SHA verification as *integrity checks*, not download ceilings. GitHub-hosted runner disk, Actions artifact, and network constraints remain external platform limits that must be reported explicitly rather than mistaken for complete delivery.
4. **Deliver files, not merely reports.** Upload the complete selected source files to downloadable **GitHub Actions artifacts**, retaining directory structure. Publish checksums, inventory, parser output, and failure diagnostics *in addition to*, not *instead of*, the exact binary files. There must be no 10 MiB threshold that silently suppresses game data.
5. **Do not delete source files before the upload.** Never run a cleanup step that erases original files before `actions/upload-artifact` can publish them. Even if a parser later fails, upload the successfully acquired files using `if: always()`; mark incomplete transfers clearly. An unsuccessful run is **not** proof that all source files were delivered.
6. **Make the handoff machine-consumable.** Artifact names identify the game, scope, and workflow run. Every output has a source key or retail package identity and verification record so an agent can retrieve the artifact, unpack the original files, and work from actual bytes locally.
7. **Separate public and private code.** `Rust-test` is private; do not check it out into this public repository's runners. Public standalone research decoders (e.g. `Fortnite-reverse`) may run against source data in this isolated workbench. The exact files are the output of this workbench and are not committed to Git history.

### Important storage and access facts

- GitHub-hosted runners are **ephemeral**. Keeping files in `$RUNNER_TEMP` without uploading them does **not** preserve them after a job finishes. Actions artifacts persist only for the repository's configured retention period (typically up to 90 days, subject to GitHub settings); they are not permanent R2 mirrors.
- GitHub Actions artifact size, storage, bandwidth, and retention limits still apply. For a large source set, **split it into smaller game-/map-/asset-family-specific artifacts or keep a pinned original object in R2** and publish a verified exact-source retrieval manifest. Never describe metadata alone as a complete file handoff.
- **This repository is public.** Artifacts from public workflow runs may be accessible to others with GitHub access to the run. Do not place secrets, credentials, personal data, or any files you are not authorized to publish in its artifacts. For restricted assets, use private storage or a private runner repository instead.

## Fortnite 5.41: actual Athena assets for the Rust-test importer

The [Fortnite 5.41 R2 source lab](.github/workflows/fortnite541-retail-lab.yml) selects `poi`, `terrain`, `foliage`, `sky`, or `all`.

It uses the pinned public `Fortnite-reverse` parser to retrieve genuine retail-cooked packages and source-verify their PAK entries. For example, `poi` targets real REC, Warehouses, and Pueblo streamed building UWorlds and their nested source assets rather than an invented stand-in mesh. Each selected family publishes:
- **An exact-source-files artifact:** original `.umap`, `.uexp`, `.uasset`, `.ubulk` payload files, where actually recovered, preserving `FortniteGame/Content/...` paths.
- **A separate validation/report artifact:** source inventory, checksums, actor/mesh/material diagnostics, and any errors.

### Athena POI exact dependency chain (21 October 2026)

The `poi` workflow is no longer a list of known UWorlds only. It performs the following source-backed dependency closure on the same runner:

1. The pinned **public** UE4 parser retrieves original REC, Warehouses, Pueblo, and nested 3x3/5x5/7x12 UWorld `.umap/.uexp` payloads with per-file authenticated PAK SHA-1.
2. `scripts/fortnite541_dependency_handoff.py` reads the actual original actor class frontier. It fetches their distinct cooked architectural Blueprint `.uasset/.uexp` packages, along with directly referenced static meshes.
3. `scripts/fortnite541_blueprint_mesh_closure.py` parses original UE4 FObjectImport/FName/Outer tables in those exact Blueprint bytes, resolves their **source-owned** UStaticMesh package identities, and fetches those original mesh source files. It does not infer mesh identities from prefab names.
4. `scripts/fortnite541_material_dependency_closure.py` follows original mesh MaterialInterface, original material parent and Texture2D UObject imports to recover actual renderer-facing source assets. Source-missing, ambiguous, encrypted and incompatible records are reported, never replaced.
5. Every actual file is preserved at its original `FortniteGame/Content/...` path and published as an **exact-source** GitHub Actions artifact; the JSON source validation reports are companion artifacts.

[Verified real-source UWorld → Blueprint → UStaticMesh run](https://github.com/lizardpeter/r2-runners/actions/runs/39638599890): 683 actual source files delivered; 151 architectural Blueprint class packages and 160 original mesh package identities recovered from retail indexes, with zero unresolved entries in both class and mesh passes. [Further authenticated UStaticMesh → material → Texture2D dependency run](https://github.com/lizardpeter/r2-runners/actions/runs/39639235544) preserved **1,070 exact original files** (253,329,014 payload bytes) including 101 authentic `.ubulk` records. The material/texture discovery added **143 distinct original source object identities** over three bounded dependency hops (31 + 101 + 11), and all three stages reported zero unresolved requests. This proves the requested **three-hop source-file recovery**, not comprehensive shader execution, full dependency closure beyond those hops or the private Vulkan scene's visual parity.

The private `Rust-test` importer and universal renderer remain in the private repository, never checked out on these public GitHub runners.

This is source-file delivery for real importer implementation; no public-runner result by itself proves that the private Windows Vulkan `Rust-test` game renders correctly. Investigate missing files from the explicit inventory, not by replacing them with approximations.

## Download a specific public R2 object intact

The [direct R2 download](.github/workflows/r2-download.yml) supports manual `object_key` input. The tool writes the **entire original file**, its original key-relative path, and a SHA-256 verification JSON into a downloadable artifact. The older "files larger than 10 MiB are report-only" behavior was intentionally removed.

Example:

```bash
python3 scripts/r2_download.py \
  --base-url https://r2.houseofkublai.com \
  --key Downloads/HOK_Gamerpics/512_HK_Holder.png \
  --output-dir /tmp/r2-test \
  --expected-size 164176
```

For whole-bucket discovery, use an explicit manifest or the connected Cloudflare account to enumerate exact object keys: a public object URL does **not** imply the bucket has a public directory listing. Prefer bounded, task-specific source sets over mirroring unrelated files.

## Retrieving a completed run

Find the matching workflow run under [Actions](https://github.com/lizardpeter/r2-runners/actions), open its **Artifacts**, and select the `*-exact-source-*` artifact. A development agent with GitHub access can use the Actions artifact API or GitHub connector to list and download these ZIP artifacts. The ZIP is transport packaging; files inside remain unchanged and should be checked against the report's hashes.

**Success means the exact requested files are actually available for subsequent local decoding**, not simply that a download command or source-count audit executed.
