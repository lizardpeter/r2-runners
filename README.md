# R2 runners

A clean GitHub Actions workbench for downloading **public** Cloudflare R2 objects without putting download machinery or original binary assets in the game-engine repositories.

## First test

The workflow [R2 public download test](.github/workflows/r2-download.yml) checks an actual object from the existing `houseofkublai` bucket:

```text
https://r2.houseofkublai.com/Downloads/HOK_Gamerpics/512_HK_Holder.png
```

On a push that changes the downloader/workflow, GitHub Actions fetches the object, streams it to the runner disk, verifies the expected **164176-byte** length and PNG signature, calculates its SHA-256 digest, and uploads a JSON verification report and (for small objects) the actual downloaded file as a workflow artifact.

For any other public object, run the workflow manually using its `object_key` input. The public host is fixed by the workflow, so there are no API tokens or secrets. The tool will reject traversal-like object keys.

## Locally on a network-enabled machine

```bash
python3 scripts/r2_download.py \
  --base-url https://r2.houseofkublai.com \
  --key Downloads/HOK_Gamerpics/512_HK_Holder.png \
  --output-dir /tmp/r2-test \
  --expected-size 164176
```

The source bytes are written only to the runner's temporary workspace, **not committed to Git**. For objects larger than 10 MiB, the Actions artifact contains the report only to avoid expensive and unnecessary redistribution.

This is a **download proof-of-concept**, not yet a whole-bucket synchronizer: publicly readable R2 object URLs do not automatically offer a public bucket listing. Later workflows can consume a manifest of object keys obtained from the connected Cloudflare account and execute game-specific parsers on the same runner.

## Black Ops 1 source workflows

The verified BO1 PC server files are under `bo1/exes/Call of Duty - Black Ops PC Server/` in `houseofkublai`. An authenticated Cloudflare R2 inventory of **78 original FastFiles/IWDs** is in [`manifests/bo1-server.json`](manifests/bo1-server.json).

- [BO1 original-source validation](.github/workflows/bo1-real-source.yml) downloads real `mp_nuked.ff`, `mp_firingrange.ff`, `common_mp.ff`, `patch_mp.ff` and 42 `iw_*.iwd` files into temporary runner storage. It decompresses BO1 FastFiles, parses original XAssetList records and structurally recognizes both ZIP IWDs and the original T5 `IWD2` 12-byte record tables. The only uploaded artifact is a JSON evidence report; no original game bytes are published.
- [BO1 complete-game ZIP64 probe](.github/workflows/bo1-full-game.yml) targets the separate **11,161,080,622-byte** `downloads/games/pluto_t5_full_game.zip`. It attempts bounded HTTP ranges to read original members directly from the full ZIP. If R2 does not serve partial responses, it performs a guarded full download into temporary runner storage only if there is enough free disk, then selects FastFiles and image packages by original archive paths. This workflow is the preferred way to inspect client textures absent from the server installation.

The original server IWD names are **not** evidence of ordinary image ZIPs: `iw_00.iwd` is a ZIP with zero IWI image members, and `iw_01.iwd` through `iw_41.iwd` use `IWD2` record tables. Source T5 game shader/texture ownership still must be verified in `Rust-test`. A successful source probe does not establish working in-game rendering.
