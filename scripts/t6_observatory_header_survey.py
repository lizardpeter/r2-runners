#!/usr/bin/env python3
"""Read-only 64-byte HTTP range survey for every indexed T6 .ff R2 object.

Signature-only evidence. Does not authenticate full original SHA256,
decrypt chunks, parse nested assets or claim any semantic byte coverage.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import struct
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

BASE="https://r2.houseofkublai.com/"
LIMIT=64
def classify(buf):
    if len(buf)<20:
        return "truncated_header",None
    if buf[:8]==b"TAff0100":
        ver=struct.unpack_from("<I",buf,8)[0]
        if ver==147 and buf[12:20]==b"PHEEBs71":
            return "t6_pc_signed_header",ver
        return "other_taff_header",ver
    if buf[:8]==b"IWffu100":
        return "iwffu100_not_t6_pc_signed",struct.unpack_from("<I",buf,8)[0]
    return "other_or_unknown_magic",None

def check_one(row):
    key=row["key"]; size=int(row["bytes"])
    if not key.startswith("bo2/") or not key.lower().endswith(".ff"):
        raise ValueError("Unexpected non-T6 corpus identity")
    entry={"r2_key":key,"r2_listed_bytes":size,"probe_length":LIMIT,"signature_status":"transport_unverified","version":None}
    if size<20:
        entry["signature_status"]="too_short_for_t6_header"
        return entry
    url=BASE+quote(key,safe="/")
    for attempt in range(3):
        try:
            req=Request(url,headers={"Range":f"bytes=0-{LIMIT-1}","Accept-Encoding":"identity",
                                     "User-Agent":"r2-runners/source-observatory/1"})
            with urlopen(req,timeout=35) as r:
                if urlsplit(r.url).hostname!="r2.houseofkublai.com":
                    raise ValueError("Unexpected redirect host")
                if r.status!=206:
                    raise ValueError(f"Non-range R2 reply {r.status}; rejecting potentially unbounded GET")
                claimed=r.headers.get("Content-Range","")
                wanted=f"bytes 0-{LIMIT-1}/{size}"
                if claimed!=wanted: raise ValueError(f"Content-Range {claimed!r} differs from {wanted!r}")
                buf=r.read(LIMIT+1)
                if len(buf)!=LIMIT:raise ValueError(f"Wrong range payload length {len(buf)}")
            kind,version=classify(buf)
            entry["signature_prefix8_hex"]=buf[:8].hex()
            entry["signature_prefix8_ascii"]="".join(chr(c) if 32<=c<127 else "." for c in buf[:8])
            entry["signature_status"]=kind
            entry["version"]=version
            entry["r2_content_range_verified"]=True
            return entry
        except Exception as exc:
            if attempt==2:
                entry["error"]=str(exc)[:400]
                return entry
            time.sleep(1+attempt)
    raise AssertionError("unreachable")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--corpus",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--workers",type=int,default=12)
    args=p.parse_args()
    corpus=json.loads(args.corpus.read_text())
    if corpus.get("schema")!="source-observatory/r2-fastfile-corpus/v1" or not corpus.get("complete_prefix_listing"):
        raise ValueError("Refuse unpinned or partial T6 R2 corpus")
    rows=corpus["objects"]
    if len(rows)!=571 or len({r["key"] for r in rows})!=len(rows):
        raise ValueError("Expected full original R2 object census, no duplicate keys")
    results=[]
    with ThreadPoolExecutor(max_workers=max(1,min(args.workers,20))) as pool:
        futures={pool.submit(check_one,row):row["key"] for row in rows}
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda e:e["r2_key"])
    from collections import Counter
    tally=Counter(e["signature_status"] for e in results)
    success=sum(bool(e.get("r2_content_range_verified")) for e in results)
    output={
      "schema":"source-observatory/t6-header-survey/v1",
      "corpus_snapshot":"2026-10-27",
      "source_r2_origin":BASE,
      "objects_listed":len(rows),
      "objects_range_verified":success,
      "complete_range_survey":success==len(rows),
      "signature_counts":dict(sorted(tally.items())),
      "method":"GET 0-63 with strict HTTP 206 and exact R2 Content-Range total",
      "proof_boundary":"Exact original header prefix ONLY. Full-file SHA256, decompression, XAsset bodies, and semantic coverage remain unknown unless individually proven by independent reports.",
      "files":results}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(output,indent=2)+"\n")
    print(json.dumps({k:output[k] for k in ("objects_listed","objects_range_verified","complete_range_survey","signature_counts")}))
    if not output["complete_range_survey"]:
        raise RuntimeError(f"Partial survey: {len(rows)-success} R2 range requests unverified. Report staged but NOT publishable as a completed survey.")
if __name__=="__main__":main()
