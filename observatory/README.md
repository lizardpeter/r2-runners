# Source Coverage Observatory v1

Cloudflare Worker deployed at https://source-coverage-observatory.hokroute.workers.dev/ (Cloudflare API deployment and workers.dev subdomain both confirmed 2026-10-27; public DNS availability was not independently verified by this assistant's restricted runtime).

## Status and scope

This is a read-only, R2-native **source-file listing and explorer**, not a semantic parser or full decoded-byte audit. It lists actual objects from the existing `houseofkublai` R2 bucket and **does not fetch, expose, download, or publish original game bytes**.

The October 27, 2026 verified object-list snapshot enumerated these eight prefixes: `bo1/` (133 files), `bo2/` (1,287), `bo3/` (76), `destiny/` (2,156), `ghosts/` (7,539), `h1/` (7), `Fortnite/` (352), `super-mario-galaxy/` (2,426). **13,976 source objects total**, excluding zero-byte folder placeholder keys. Duplicate games/editions and files inside archive containers are not deduplicated or counted here.

## API

- `GET /`: no-build browser dashboard.
- `GET /api/games`: schema and dated prefix counts.
- `GET /api/files?game=bo2&limit=400&cursor=...`: pagination over *live* R2 objects with source key, byte size, extension, etag, and upload date where provided. Excludes folder placeholders. Each returned row explicitly marks structure / byte ranges / semantics as `not-evaluated`. A supplied cursor applies only to the requested game.

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
