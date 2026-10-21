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

## CS2 original Source 2 VMAT / VTEX handoff

The [CS2 exact-source workflow](.github/workflows/cs2-material-source-handoff.yml)
downloads the current anonymous Steam depot \`730/2347770\` VPK directory index,
resolves source-authored texture paths, downloads only the physical VPK segments
needed, and saves each ORIGINAL compiled \`.vtex_c\` byte stream after checking
the index entry's CRC32. Original bytes, original resource names, a SHA-256
manifest and any unindexed paths are published. Files are not recreated from
screenshots or given synthetic substitutions.

**Verified October 21, 2026:** [run 39646857633](https://github.com/lizardpeter/r2-runners/actions/runs/39646857633)
passed and delivered all three original compiled VTEX resources missing from
the 275-VMAT Dust2 material corpus:

- \`materials/default/default_ao_tga_559f1ac6.vtex_c\`
- \`materials/default/default_normal_tga_7be61377.vtex_c\`
- \`materials/de_dust/hr_dust/hr_dust_trim_overlay_psd_92cba63e.vtex_c\`

The archived files retain the \`cs2-base-resources/materials/...\` path.
Extract that directory **beside the existing original Workshop
\`3620630831_dir.vpk\`**, or into the corresponding existing CS2 source
overlay root read by the Rust-test importer. Keep the Workshop VPKs untouched.
An agent may fetch and unpack the artifacts into its own analysis environment
using the GitHub artifact handoff.

A separate original-source audit of all 18 existing compact corpus archives
plus these three recovered files accounted for **275 original VMATs and 729
original VTEX files**. All 275 original VMAT KV3 documents (268 v5, five v4,
two v3) were independently decoded. All 729 VTEX files have valid payload and
mip extents, including the 3D Perlin-noise volume whose depth halves at each
mip (**4,712 source mip levels total**). These checks prove metadata/byte
decoding and dependency closure in THIS corpus, not original VCS shader
execution or visual parity for arbitrary CS2 maps.

## Fortnite 5.41: actual Athena assets for the Rust-test importer

### New full original Athena source and renderer-dependency workflows — October 21, 2026

**Original Athena root-world bootstrap fixed:** [run 39645112512](https://github.com/lizardpeter/r2-runners/actions/runs/39645112512) verified all nine actual original root-level UWorld packages from the main 5.41 PAK, including `Athena_Terrain`, `Athena_POI_Foundations`, `Athena_Streaming_Grid`, and `Athena_LocationVolumes`. The former environment family filtering missed root `Athena_POI_Foundations`, making the newly recovered high-detail building assets unplaceable without an older source cache. The new `root` source family fetches these exact original source files, including their .uexp and available .ubulk companions, with retail PAK entry SHA-1 verification.

**Exact original location identities:** The 67 original `FortPoiVolume` UObjects in `Athena_LocationVolumes` serialize a typed `GameplayTagContainer LocationTags`; these include **21 distinct named POI gameplay tags** (Tilted Towers, Retail Row, Paradise Palms, Lazy Links, Pleasant Park, etc.) and biome/landmark tags. Do **not** take map labels from actor filenames: the original `FortPoiVolume_AnarchyAcres` actor actually carries `Athena.Location.POI.LazyLinks`. The native Rust importer now decodes these source tags as a strict typed UObject property rather than a guessed string mapping. [Merged private PR #560](https://github.com/lizardpeter/Rust-test/pull/560).

**Expanded ALL-POI world dependency closure:** [workflow `fortnite541-all-poi-closure.yml`](.github/workflows/fortnite541-all-poi-closure.yml) fetches all original root, 41 POI and 179 nested building UWorlds together on one runner, follows actual cooked UObject `FPackageImport` edges into original Blueprints, static meshes, material instances and source texture packages, and preserves *the complete original bytes* of each authenticated asset in the same artifact. The bounded dependency depth and any unvisited source frontier are explicitly disclosed. This is a data bridge, not proof that every material section renders. The original local-Pak bootstrap also includes the foundation and location packages automatically. [Merged private PR #562](https://github.com/lizardpeter/Rust-test/pull/562).

The [full Athena world/environment source workflow](.github/workflows/fortnite541-world-environment.yml) partitions authentic source entries across two GitHub Actions runners per asset family; [run 39641166847](https://github.com/lizardpeter/r2-runners/actions/runs/39641166847) passed all fourteen shards. Its source-proven original payloads cover **41 POI UWorlds, 37 streamed UWorlds, 179 building UWorlds, 7 background/landscape UWorlds, 262 terrain-related packages, 1,163 vegetation-related packages and 80 sky/cloud/fog/weather-related packages**. The seven source families include 264 parsed original map headers; tree/grass/foliage source recovery alone preserved **2,553 exact cooked source files (517,211,715 original bytes)**. Each file's original directory structure, authenticated retail PAK entry SHA-1, and SHA-256 artifact inventory are retained. Asset-family selections are based on exact **authenticated PAK indexed paths**, never guessed individual asset filenames or a metadata-only handoff.

The separate [original lighting/material/shader source workflow](.github/workflows/fortnite541-materials-shaders.yml) partitions original **light, material, and shader archive** file sources across four shards. It preserves all original binary files. Its source parser [`scripts/fortnite541_shader_index_decode.py`](scripts/fortnite541_shader_index_decode.py) runs a **complete** 37-byte UE4 FShaderCode library index walk and verifies every Zlib-compressed shader's actual uncompressed length, exact table offsets, original record hash uniqueness, shader stage, and structural DXBC chunk bounds. [Shader run 39643365398](https://github.com/lizardpeter/r2-runners/actions/runs/39643365398) passed both original SM5 and both original SM4 libraries: **176,214 source shader records structurally decoded**, including **96,496 FortniteGame SM5 records**. This is not the same as executable Vulkan translation or UE4 uniform-resource binding.

The original source hashes for the four accepted shader archives are:

| Exact original `FortniteGame/Content/` asset | Payload bytes | Retail entry SHA-1 |
| --- | ---: | --- |
| `ShaderArchive-FortniteGame-PCD3D_SM5.ushaderbytecode` | 138,986,223 | `937132b7eddced473e1826a66f78be57bf6b1ef3` |
| `ShaderArchive-Global-PCD3D_SM5.ushaderbytecode` | 2,256,607 | `2a37a2159116d4030e59747d53c1c3b1f6d2fe79` |
| `ShaderArchive-FortniteGame-PCD3D_SM4.ushaderbytecode` | 106,773,481 | `35edcfdf3475c405d7f8a65fb40ed462cd7d2184` |
| `ShaderArchive-Global-PCD3D_SM4.ushaderbytecode` | 837,988 | `f1d09aef1274f9e89255940e014bdd4a73fa7124` |

**Full original material source completed:** [the verified materials/shaders runner 39643365398](https://github.com/lizardpeter/r2-runners/actions/runs/39643365398) reports **7,851 original material-related packages**, **15,946 verified original cooked source files**, **1,609,899,690 original payload bytes**, and **zero unresolved source files** across its four material shards. The original lighting shard family also completed source recovery for **36 light-related source packages** (72 files). The material set is selected from authentic PAK-indexed paths and does not by itself prove every material's original shader-map / runtime binding is executable.

**Actual Rust-test integration:** [source-native world/actor registry PR #557](https://github.com/lizardpeter/Rust-test/pull/557) and [standalone authenticated SM5 original shader execution PR #559](https://github.com/lizardpeter/Rust-test/pull/559) were merged. The private importer may now load a verified original full shader archive from the loose source directory even without the original 4.8GB game PAK. Original material shader selection and actual per-material compile success still depend on source UE4 shader-map/material/texture binding contracts; exact sky, lighting, fog, world-scale foliage instancing, and POI rendered parity are not established from asset retrieval alone.

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


## BO1 real-client packed material texture verification

[BO1 real client first-two texture alias replay](.github/workflows/bo1-second-alias-validation.yml)
is an actual binary validation task, not a report generator. It retrieves the
complete original BO1 **Nuketown and Firing Range client FastFiles** from an
existing exact-source workflow artifact, verifies their original SHA-256,
decompresses their authentic T5 source zones and replays the first two original
GfxWorld material texture allocations.

The independent [successful real-original-byte run #39650670394](https://github.com/lizardpeter/r2-runners/actions/runs/39650670394)
verified **205 packed texture-slot references** to the genuine first/second
original material image-pointer fields (Nuketown 43+35; Firing Range 10+117).
The source `.ff` bytes are retrieved and processed locally by the runner.
No JSON summaries are substituted for source files.

The default transfer artifact comes from run `39637661371` and will eventually
expire under GitHub's artifact retention policy. To rerun later, use a fresh
full-client binary-transfer run and provide its ID to the manual workflow
dispatcher. The Rust-test importer is generic; the names and offsets in this
validation test are source-specific regression fixtures, not importer rules.


## BO1 exact original client image and shader/material source verification

- [Complete BO1 original-client texture workflow](.github/workflows/bo1-client-material-textures.yml):
  **passed** [run #39675418914](https://github.com/lizardpeter/r2-runners/actions/runs/39675418914).
  It really downloads and authenticates the full 11.16GB original client ZIP,
  scans **all 57 original IWD archives**, and transfers both original map
  FastFiles plus **162 full original IWI files**, not just JSON. Every one of
  the 162 direct named image identities from Nuketown and Firing Range was
  found **uniquely**; no missing original direct texture images.
- [Complete original IWI mip validation](.github/workflows/bo1-iwi-source-validation.yml):
  **passed** [run #39677620614](https://github.com/lizardpeter/r2-runners/actions/runs/39677620614).
  Independently validates every transferred IWI SHA-256, format, dimensions
  and exact top-level compressed mip span: **162/162 pass** (24 BC1 and
  138 BC3 images).
- [Original material virtual address and sampler name verification](.github/workflows/bo1-second-alias-validation.yml):
  **passed** [run #39677047129](https://github.com/lizardpeter/r2-runners/actions/runs/39677047129).
  Verifies 205 original first/second-material packed image slot references
  and independently recovers 2,590/2,600 source material sampler names from
  BO1's exact case-folded `R_HashString`, authenticated source semantic and
  Shader Model 3 HLSL sampler declaration strings. Ten nonstandard source
  binding names remain unresolved.

The original source images and FastFiles are persisted as actual GitHub
Actions transfer artifacts; the JSON files are companion integrity evidence,
not replacements for original game assets. Original generated/composite
image names are distinct from literal IWD images and require engine image
composition / zone loader replay. The remaining packed image aliases also
require further T5 virtual allocation reconstruction.
