#!/usr/bin/env python3
"""Recover ORIGINAL IW5 source .ff bytes, not a JSON-only metadata report.

R2's public custom hostname does not advertise usable HTTP byte ranges for
the owner's 18.4 GB ZIP. Read one normal HTTP response through stream_unzip,
select a verified ZIP member suffix, and preserve the entire .ff byte stream
as a GitHub artifact. Files are not decoded or re-encoded; the private
Rust-test IW5 importer handles original source decoding.
"""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen
from stream_unzip import stream_unzip

URL="https://r2.houseofkublai.com/downloads/games/pluto_iw5_full_game.zip"
ARCHIVE_SIZE=18424199780
ALLOWED_SUFFIXES={
    "zone/dlc/mp_aground_ss.ff",
    "zone/dlc/mp_courtyard_ss.ff",
    "zone/english/mp_dome.ff",
    "zone/english/mp_hardhat.ff",
}
MAX_ZONE_BYTES=512*1024*1024
MAX_TOTAL_BYTES=850*1024*1024

def buffered_http(http, report):
    while True:
        data=http.read(1024*1024)
        if not data:
            break
        report["downloaded_outer_bytes"]+=len(data)
        yield data

def extract(dst, max_files):
    dst.mkdir(parents=True,exist_ok=True)
    report={
        "original_archive":URL,
        "downloaded_outer_bytes":0,
        "source_ff_files":[],
        "source_ff_member_names":[],
        "errors":[],
    }
    selected=0
    total=0
    headers={"User-Agent":"IW5-original-ff-source-extractor/1.0",
             "Accept-Encoding":"identity"}
    with urlopen(Request(URL,headers=headers),timeout=300) as response:
        length=int(response.headers.get("Content-Length","0"))
        if length!=ARCHIVE_SIZE:
            raise ValueError(f"original R2 archive size changed: {length}")
        try:
            for raw_name, size, chunks in stream_unzip(buffered_http(response,report)):
                name=raw_name.decode("utf-8","replace").replace("\\","/")
                if name.startswith("/") or ".." in name.split("/"):
                    raise ValueError("unsafe source archive member")
                normalized=name.lower().removeprefix("pluto_iw5_full_game/")
                if not normalized.endswith(".ff"):
                    for _ in chunks:
                        pass
                    continue
                report["source_ff_member_names"].append(normalized)
                if normalized not in ALLOWED_SUFFIXES or selected>=max_files:
                    for _ in chunks:
                        pass
                    continue
                if size is not None and size>MAX_ZONE_BYTES:
                    report["errors"].append(f"original source zone too large: {name}")
                    for _ in chunks:
                        pass
                    continue
                output_name=Path(normalized).name
                path=dst/output_name
                sha=hashlib.sha256()
                n=0
                with path.open("wb") as target:
                    for block in chunks:
                        n+=len(block)
                        if n>MAX_ZONE_BYTES or total+n>MAX_TOTAL_BYTES:
                            raise ValueError("source zone exceeds bounded artifact budget")
                        sha.update(block)
                        target.write(block)
                if n<21 or (lambda p: p.open("rb").read(4))(path)!=b"IWff":
                    path.unlink(missing_ok=True)
                    raise ValueError(f"original source FF header invalid: {name}")
                total+=n
                selected+=1
                report["source_ff_files"].append({
                    "original_member":name,
                    "artifact_filename":output_name,
                    "source_bytes":n,
                    "original_sha256":sha.hexdigest(),
                    "header_verified":True,
                })
                print("RECOVERED ORIGINAL",name,n,"bytes",flush=True)
                if selected>=max_files:
                    break
        except Exception as exc:
            report["errors"].append(str(exc)[:350])
    (dst/"iw5_full_source_zone_status.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2),flush=True)
    if selected==0:
        raise RuntimeError("No complete targeted original MW3 multiplayer FastFile recovered")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--max-files",default=1,type=int)
    args=p.parse_args()
    if not 1<=args.max_files<=4:raise ValueError("max-files must be 1..4")
    extract(args.out,args.max_files)
