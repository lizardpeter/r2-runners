# Source Coverage Observatory v1

Cloudflare Worker deployed at https://source-coverage-observatory.hokroute.workers.dev/ (Cloudflare deployment confirmed 2026-10-27; GitHub-hosted Ubuntu runner independently fetched the live site and API, parsed its JSON and checked browser JavaScript syntax (run 40536577723)).

## Status and scope

This is a read-only, R2-native **source-file listing and explorer**, not a semantic parser or full decoded-byte audit. It lists actual objects from the existing `houseofkublai` R2 bucket and **does not fetch, expose, download, or publish original game bytes**.

The October 27, 2026 verified object-list snapshot enumerated these eight prefixes: `bo1/` (133 files), `bo2/` (1,287), `bo3/` (76), `destiny/` (2,156), `ghosts/` (7,539), `h1/` (7), `Fortnite/` (352), `super-mario-galaxy/` (2,426). **13,976 source objects total**, excluding zero-byte folder placeholder keys. Duplicate games/editions and files inside archive containers are not deduplicated or counted here.

## API

- `GET /`: no-build browser dashboard.
- `GET /api/games`: schema and dated prefix counts.
- `GET /api/files?game=bo2&limit=400&cursor=...`: pagination over *live* R2 objects with source key, byte size, extension, etag, and upload date where provided. Excludes folder placeholders. Each returned row explicitly marks structure / byte ranges / semantics as `not-evaluated`. A supplied cursor applies only to the requested game.

The initial three-file authenticated T6 proof pipeline also exposes:
- `GET /api/t6/index`: proven original/expanded SHA-256 and directory counts for `common_mp.ff` (6,082 XAssets), `common_patch_mp.ff` (3,533), and `patch_mp.ff` (1,764). Source/expanded SHA-256 fingerprints match independently pinned research fixtures. Runner success: https://github.com/lizardpeter/r2-runners/actions/runs/40536019206.
- `GET /api/t6/report?key=bo2%2Fzone%2Fall%2Fcommon_mp.ff`: verified expanded byte ranges, per-entry ordinal/type/pointer information, explicit unknown body span and an `asset_bodies: not-evaluated` flag.
- `GET /api/t6/headers`: complete 571-object original R2 HTTP range survey. 215 client-zone files under `bo2/zone/all` and `bo2/zone/english` start `TAff0100`; the other 356 FastFiles are dedicated-server package files under `bo2/exes` starting `TAsvu100`. Merely recognizing those eight bytes is not a dedicated-server decoder. Survey run: https://github.com/lizardpeter/r2-runners/actions/runs/40537166256. The 571-file survey is separately verified from the live hosted website by run 40537578076.

A byte range read establishes only the first 64 original source bytes, not the file's full SHA-256 or interior. A full-file decoder runs on a separate verified job. Production Rust-test importer closure remains untested by these public-runner reports.

All results are metadata only. ETags are **not** treated as SHA-256 proofs, file extensions **not** treated as magic-byte verified file types, and compression **not** treated as understood field semantics.

## Future evidence contract

Future source parsers and authenticated runners should output a versioned evidence manifest with:
- corpus game/build, exact R2 key, observed object size and **verified SHA-256**;
- physical bytes in the outer original file, separate from decompressed/transformed virtual address spaces;
- typed containers, nested file/asset ordinal paths, spans, overlaps and holes;
- range ownership classification: semantic field, structurally parsed, padding, opaque-preserved, unknown;
- proof stage P0–P8 with exact reference to relevant test/corpus and an explicit source provenance record;
- unresolved references and blocker IDs;
- aggregate totals scoped to the audited corpus, never across unevaluated prefixes.

A green structural walk does not promote `semantics` above `not-evaluated`. Decompressing a blob does not establish knowledge of the blob's semantic byte layout.

## Deployment

`worker.mjs` is a complete Worker script, with an R2 bucket binding `SOURCES` -> `houseofkublai`, `main_module: worker.mjs`, and `compatibility_date: 2026-10-27`. It was published through the connected Cloudflare API as `source-coverage-observatory` and enabled on the existing `hokroute.workers.dev` account subdomain, without changes to any existing game production deployments.

Any larger inventory or exact retail parsing should use the established `r2-runners` source-handoff workflows and hash-verify source objects. Private Rust-test code must not be checked out on public r2-runners. This site itself needs **no local PC commands**.

## October 27, 2026: whole-corpus T6 source audit

**All 1,287 BO2 R2 objects have been listed and an original-source 0–63 byte
range signature has been validated** (shorter files use their full length).
This includes, but is not limited to, **571 FastFiles, 23 IPAKs, 116 audio
banks (66 SABS/50 SABL), 366 WAD files, and 154 CAB files**.
`GET /api/t6/source-headers` provides every original R2 key, physical
byte length, extension, exact observed first eight bytes, signature group,
and byte-range proof status. This is **not** a complete original SHA-256
or structural parser proof for the non-FF files.

The original **215 signed T6 PC client FastFiles** all authenticated by
original R2 source SHA-256 and expanded/decrypted with the pinned public
decoder. All **215 XAsset directories** passed the strict parser:
**120,385 directory entries**. The 215-source report at
`GET /api/t6/client-corpus` records exact source hashes, expanded SHA-256s,
type counts, raw directory end offsets, unknown spans and all successes or
failures. Original historical fixture hashes were independently checked
for three shared MP zones. This is not proof of semantic body closure.

The original **356 unsigned T6 server FastFiles** from an archived server
bundle (60 PC v147, 103 PS3 v146, 107 Xbox 360 v146, 86 Wii U v148) all
passed strict unsigned raw-DEFLATE XChunk expansion. All **356 XAsset
directories** parsed structurally: **256,811 directory entries**.
These originals are separately SHA-256 hashed during the runner audit,
with explicit trailing source bytes/padding and expanded address-space
metadata. **Version 146 alone does not identify PS3 vs Xbox 360.**
The per-file results are served at `GET /api/t6/server-corpus`.

`GET /api/t6/types` aggregates these **377,196 XAsset DIRECTORY
entries** across all 571 archives: 43 observed out of 60 registered type
IDs. 17 type IDs lack top-level entries in this scope; no conclusion about
nested usage, absence in other builds, asset uniqueness, or full serialized
semantics can be drawn. Counts may overlap across source zones, versions
and DLC patches.

Production Rust-test importer coverage, embedded sound and texture semantics,
WAD/CAB internals, runtime rendering, and lossless byte-span owner closure
**are not measured** by this metadata-first observatory. A successful full
FastFile decrypt/expand plus type directory census does not mean that the
remaining encoded asset-body bytes are understood. Every source state is
reported separately with source corpus/proof provenance.

Relevant remote-source runner proofs:
- Client source SHA/decrypt/215 directories:
  https://github.com/lizardpeter/r2-runners/actions/runs/40540875368
- Unsigned PC/PS3/WiiU smoke:
  https://github.com/lizardpeter/r2-runners/actions/runs/40541515916
- Full original server source decode:
  https://github.com/lizardpeter/r2-runners/actions/runs/40542137393
- 571-entry type index:
  https://github.com/lizardpeter/r2-runners/actions/runs/40542799682
- Live original client/server/type website API:
  https://github.com/lizardpeter/r2-runners/actions/runs/40543183541
- Entire 1,287-object source header survey:
  https://github.com/lizardpeter/r2-runners/actions/runs/40543593008

