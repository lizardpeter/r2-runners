#!/usr/bin/env python3
"""Capture a bounded original IW5 ZIP prefix as a CI artifact for local analysis.

Large R2 ZIP currently responds 200 rather than 206 to Range GETs.
A normal streaming GET can still read a small prefix and close the connection.
Never attempt to download the entire 18.4 GB source into runner storage.
"""
from pathlib import Path
from urllib.request import Request, urlopen
import hashlib, json, argparse

URL = "https://r2.houseofkublai.com/downloads/games/pluto_iw5_full_game.zip"
SIZE_LIMIT = 4*1024*1024

def capture(out: Path):
    out.mkdir(parents=True,exist_ok=True)
    path=out/"iw5_zip_first_4m.bin"
    h=hashlib.sha256()
    left=SIZE_LIMIT
    with urlopen(Request(URL,headers={"Accept-Encoding":"identity","User-Agent":"r2-runners-iw5/1.0"}),timeout=120) as response:
        if response.status not in (200,206):
            raise RuntimeError(f"Unexpected GET response {response.status}")
        total=int(response.headers.get("Content-Length","0"))
        with path.open("wb") as f:
            while left:
                chunk=response.read(min(left,1024*1024))
                if not chunk:break
                f.write(chunk);h.update(chunk);left-=len(chunk)
    if left:
        raise RuntimeError("IW5 R2 source truncated before first four MiB")
    report={"source_url":URL,"reported_source_length":total,
            "captured_prefix_bytes":SIZE_LIMIT,
            "prefix_sha256":h.hexdigest(),
            "first_64_hex":path.read_bytes()[:64].hex(),
            "note":"Raw original 4MiB ZIP prefix for local parser development; NOT a full-game archive."}
    (out/"iw5_prefix_metadata.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",type=Path,required=True)
    capture(p.parse_args().output_dir)
