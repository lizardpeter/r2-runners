#!/usr/bin/env python3
"""Byte-accurate read-only R2 object signature inventory for any game prefix.

Reads live paginated metadata from the deployed metadata-only Worker and
cross-checks physical lengths with strict 206 Content-Range from the original
R2 origin. Never acquires entire game binaries. Signatures are observations,
NOT a claim that a decoder understands a serialized file.
"""
import argparse
from collections import Counter,defaultdict
from concurrent.futures import ThreadPoolExecutor,as_completed
import json
import time
from urllib.parse import quote,urlencode,urlsplit
from urllib.request import Request,urlopen
from pathlib import Path

SITE="https://source-coverage-observatory.hokroute.workers.dev"
R2="https://r2.houseofkublai.com"
MAX_PREFIX=64
def get_json(url):
    for attempt in range(3):
        try:
            with urlopen(Request(url,headers={"User-Agent":"r2-runners/source-observatory/2"}),timeout=45) as r:
                return json.load(r)
        except Exception:
            if attempt==2:raise
            time.sleep(1+attempt)
    raise AssertionError("unreachable")

def enumerate_game(game,expected):
    out=[]
    cursor=None
    visited=set()
    for page in range(60):
        url=SITE+"/api/files?"+urlencode({"game":game,"limit":400,**({"cursor":cursor} if cursor else {})})
        data=get_json(url)
        if data.get("schema")!="source-observatory/v1" or data.get("game")!=game:
            raise ValueError("Unrecognized source-site pagination schema")
        for o in data["files"]:
            if o["key"] in visited:raise ValueError("Repeated R2 object key in metadata pagination")
            visited.add(o["key"])
            out.append({"r2_key":o["key"],"r2_size":o["bytes"],"extension":o["extension"]})
        if not data["truncated"]:
            if len(out)!=expected:raise ValueError(f"R2 source listing size drift: expected {expected}, found {len(out)}")
            return out
        cursor=data.get("cursor")
        if not cursor:raise ValueError("R2 returned truncated page without cursor")
    raise ValueError("Excessive R2 listing pages")

def classify(data):
    sig4=data[:4];sig8=data[:8]
    # These are magic/syntactic markers, not successful full-file decode claims.
    if sig8==b"TAff0100":return "t6_signed_pc_fastfile"
    if sig8==b"TAsvu100":return "t6_unsigned_server_fastfile"
    if sig4==b"KAPI":return "ipak_little_endian_candidate"
    if sig4==b"IPAK":return "ipak_big_endian_candidate"
    if data.startswith(b"T3w"):return "t3w_wad_family_magic"
    if sig4==b"2UX#" and data[4:8]==bytes.fromhex("0e000000"):
        return "t6_sound_bank_magic_v14"
    if data.startswith(b"Microsoft C/C++"):return "microsoft_pdb_msf_magic"
    if data.startswith(b"BM"):return "bitmap_magic"
    if data.lstrip().startswith(b"<!DOCTYPE"):return "html_doctype_not_executable"
    if sig4==b"MSCF":return "windows_cabinet_magic"
    if sig4==b"PK\x03\x04":return "zip_local_header"
    if sig4==b"OggS":return "ogg_stream_magic"
    if sig4==b"RIFF":return "riff_container_magic"
    if sig4==b"DDS ":return "dds_magic"
    if sig4==b"BIKi":return "bink_magic"
    if sig4==b"ID3":return "id3_tag_magic"
    if sig4==b"\x1a\x45\xdf\xa3":return "ebml_magic"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):return "png_magic"
    if data.startswith(b"MZ"):return "dos_pe_header_candidate"
    if data.startswith(b"SQLite format 3\x00"):return "sqlite_magic"
    if len(data)<8:return "too_short_to_identify"
    return "unknown_signature"

def probe(row):
    out={**row,"bytes_sampled":0,"http_range_verified":False,
         "signature":"unverified","signature8_hex":None,"signature8_ascii":None,
         "proof_boundary":"Original source prefix signature only; does not prove parser, hash, completeness, or nested contents"}
    length=row["r2_size"]
    if not isinstance(length,int) or length<0:out["error"]="Invalid R2 metadata length";return out
    if length==0:
        out.update(signature="zero_byte_object",http_range_verified=True,bytes_sampled=0)
        return out
    limit=min(MAX_PREFIX,length)
    key=row["r2_key"]
    if not key.startswith("bo2/"):out["error"]="Unexpected source scope";return out
    url=R2+"/"+quote(key,safe="/")
    for attempt in range(3):
        try:
            req=Request(url,headers={"Range":f"bytes=0-{limit-1}",
               "Accept-Encoding":"identity","User-Agent":"r2-runners/source-observatory/2"})
            with urlopen(req,timeout=40) as r:
                if urlsplit(r.url).hostname!="r2.houseofkublai.com":
                    raise ValueError("R2 source redirected to untrusted host")
                if r.status!=206:raise ValueError(f"expected 206, received {r.status}")
                claimed=r.headers.get("Content-Range","")
                wanted=f"bytes 0-{limit-1}/{length}"
                if claimed!=wanted:raise ValueError(f"wrong Content-Range {claimed!r}, expected {wanted!r}")
                data=r.read(limit+1)
                if len(data)!=limit:raise ValueError("Unexpected R2 prefix byte count")
            out.update(bytes_sampled=limit,http_range_verified=True,
                signature=classify(data),
                signature8_hex=data[:8].hex(),
                signature8_ascii="".join(chr(x) if 32<=x<127 else "." for x in data[:8]))
            return out
        except Exception as e:
            if attempt==2:
                out["error"]=str(e)[:250]
                return out
            time.sleep(1+attempt)
    raise AssertionError("unreachable")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--game",default="bo2")
    p.add_argument("--expected",type=int,default=1287)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--workers",type=int,default=12)
    a=p.parse_args()
    if a.game!="bo2":p.error("v1 deliberately scoped to the audited T6 source collection")
    original=enumerate_game(a.game,a.expected)
    result=[]
    with ThreadPoolExecutor(max_workers=max(1,min(a.workers,20))) as pool:
        tasks=[pool.submit(probe,row) for row in original]
        for task in as_completed(tasks):result.append(task.result())
    result.sort(key=lambda x:x["r2_key"])
    by_ext=Counter(x["extension"] for x in result)
    by_sig=Counter(x["signature"] for x in result)
    failures=[x for x in result if not x["http_range_verified"]]
    document={"schema":"source-observatory/original-r2-signature-corpus/v1",
        "game":"bo2","prefix":"bo2/","r2_objects_listed":len(result),
        "r2_objects_prefix_verified":len(result)-len(failures),
        "complete_signature_survey":not failures,
        "source_bytes_total":sum(x["r2_size"] for x in result),
        "extension_counts":dict(sorted(by_ext.items(),key=lambda x:(-x[1],x[0]))),
        "signature_counts":dict(sorted(by_sig.items(),key=lambda x:(-x[1],x[0]))),
        "proof_boundary":"First <=64 original bytes per file, verified HTTP Content-Range against exact R2 object length. Extensions/magic do not certify any parser, inner records, semantics, or complete byte ownership.",
        "files":result}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(document,indent=2)+"\n")
    print(json.dumps({k:document[k] for k in ("r2_objects_listed","r2_objects_prefix_verified","complete_signature_survey","extension_counts","signature_counts")},indent=2))
    if failures:raise RuntimeError(f"{len(failures)} original R2 object header reads could not be independently verified")
if __name__=="__main__":main()
