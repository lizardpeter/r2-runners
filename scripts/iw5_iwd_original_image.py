#!/usr/bin/env python3
"""Find ONE source-owned IWI texture inside original nested IW5 IWD archives.

The source R2 object is an 18.4GB outer ZIP. Its Cloudflare custom domain
currently ignores HTTP Range, so this streams the outer archive and
incrementally streams every nested .iwd (a ZIP) rather than saving any IWD
or the entire game on disk. A real .iwi member is copied byte-for-byte,
never reconstructed, transcoded or inferred from its material name.

This is only a source-transfer tool in r2-runners; all decoding belongs
to asset_import/importers/iw5 in the PRIVATE Rust-test repo.
"""
import argparse
import hashlib
import json
import pathlib
import sys
from urllib.request import Request,urlopen
from stream_unzip import stream_unzip

URL="https://r2.houseofkublai.com/downloads/games/pluto_iw5_full_game.zip"
EXPECTED_CONTENT_LENGTH=18424199780
ORIGINAL_TARGET="friendorfoe_self_sp.iwi"
MAX_TARGET_BYTES=64*1024*1024

def body_stream(http,stats):
    while True:
        part=http.read(1024*1024)
        if not part:break
        stats["network_bytes_read"]+=len(part)
        yield part

def checked_path(raw):
    name=raw.decode("utf-8","replace").replace("\\","/")
    if name.startswith("/") or "\0" in name or ".." in name.split("/"):
        raise ValueError("unsafe archive path")
    return name

def scan(original_url,output):
    output.mkdir(parents=True,exist_ok=True)
    result={
        "source_archive_url":original_url,
        "source_archive_bytes":EXPECTED_CONTENT_LENGTH,
        "target_iwi":ORIGINAL_TARGET,
        "network_bytes_read":0,"iwd_scanned":0,
        "iwi_entries_scanned":0,"found":[],
        "truncated_outer_stream":False,
    }
    req=Request(original_url,headers={
        "User-Agent":"r2-runners-iw5-original-texture",
        "Accept-Encoding":"identity",
    })
    with urlopen(req,timeout=300) as response:
        if int(response.headers.get("Content-Length","0"))!=EXPECTED_CONTENT_LENGTH:
            raise ValueError("original Cloudflare R2 ZIP object changed size")
        try:
            for original_name,_size,entry_chunks in stream_unzip(body_stream(response,result)):
                name=checked_path(original_name)
                if not name.lower().endswith(".iwd"):
                    for _ in entry_chunks:pass
                    continue
                result["iwd_scanned"]+=1
                try:
                    for iwi_name,_iwi_size,iwi_chunks in stream_unzip(entry_chunks):
                        path=checked_path(iwi_name)
                        result["iwi_entries_scanned"]+=1
                        if pathlib.PurePosixPath(path).name.lower()!=ORIGINAL_TARGET:
                            for _ in iwi_chunks:pass
                            continue
                        sha=hashlib.sha256()
                        length=0
                        target=output/"friendorfoe_self_sp.original.iwi"
                        with target.open("wb") as dest:
                            for part in iwi_chunks:
                                length+=len(part)
                                if length>MAX_TARGET_BYTES:
                                    raise ValueError("original target IWI size exceeds 64 MiB cap")
                                sha.update(part)
                                dest.write(part)
                        result["found"].append({
                            "outer_member":name,"inner_member":path,
                            "bytes":length,"sha256":sha.hexdigest(),
                            "artifact_file":target.name,
                        })
                        # A single authenticated source IWI is sufficient;
                        # stream-unzip requires the outer member to be drained.
                        if result["found"]:
                            break
                except Exception as exc:
                    result.setdefault("nested_errors",[]).append({
                        "iwd":name,"error":str(exc)[:220]
                    })
                for _ in entry_chunks:pass
                if result["found"]:break
                if result["iwd_scanned"]%10==0:
                    print("inspected",result["iwd_scanned"],
                          "source IWDs and",result["network_bytes_read"],"network bytes",
                          flush=True)
        except Exception as exc:
            result["truncated_outer_stream"]=True
            result["outer_stream_error"]=type(exc).__name__+": "+str(exc)[:200]
    (output/"original_iwd_image_report.json").write_text(
        json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2),flush=True)
    if not result["found"]:
        raise RuntimeError("source IWI unavailable in scanned archive prefix")
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=pathlib.Path,required=True)
    a=p.parse_args()
    scan(URL,a.output)
