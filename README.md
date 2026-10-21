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
