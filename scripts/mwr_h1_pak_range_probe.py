"""Read only source-declared byte windows from the original H1 imagefile PAKs.

This is source-range/availability evidence, NOT image/mip ownership, texture
format certification, or material binding. Never publish proprietary bytes.
"""
import argparse
import hashlib
import json
import struct
from urllib.request import Request, urlopen
from urllib.error import HTTPError

ROW_BYTES=24
MAX_ROWS=262_144

def source_rows(table):
    if len(table)%ROW_BYTES:
        raise ValueError("H1 original image descriptor bytes truncated")
    rows=[]
    for i in range(len(table)//ROW_BYTES):
        w=struct.unpack_from("<6I",table,i*ROW_BYTES)
        if w[0]&65535:
            raise ValueError(f"H1 original stream row {i} has unknown flags")
        begin=w[2]|w[3]<<32
        end=w[4]|w[5]<<32
        if end<begin:
            raise ValueError(f"H1 original stream row {i} inverted range")
        rows.append((w[0]>>16,begin,end,i))
    return rows

def fetch_exact_range(url,start,end):
    if start<0 or end<start or end-start>1024*1024:
        raise ValueError("refusing unbounded H1 PAK range fetch")
    req=Request(url,headers={"Range":f"bytes={start}-{end-1}",
                             "Accept-Encoding":"identity", "User-Agent":"H1-source-probe/1"})
    with urlopen(req,timeout=35) as response:
        content_range=response.headers.get("Content-Range","")
        if response.status!=206 or not content_range.startswith(f"bytes {start}-{end-1}/"):
            raise ValueError("R2 did not honor exact bounded HTTP byte range")
        raw=response.read(end-start+1)
    if len(raw)!=end-start:raise ValueError("H1 R2 source PAK range short read")
    return raw

def inspect(original_url,pak_prefix):
    first=fetch_exact_range(original_url,0,28)
    magic,version=first[:8],struct.unpack_from("<I",first,8)[0]
    if magic not in (b"S1ff0100",b"S1ffu100") or version!=0x42:
        raise ValueError("source FastFile H1 magic/version mismatch")
    count=struct.unpack_from("<I",first,24)[0]
    if count>MAX_ROWS:raise ValueError("source H1 descriptor row count too large")
    data=fetch_exact_range(original_url,28,28+count*ROW_BYTES)
    rows=source_rows(data)
    archives={}
    for archive,start,end,ordinal in rows:
        if not archive:continue
        state=archives.setdefault(archive,{"rows":0,"highest_end":0,"candidate":None})
        state["rows"]+=1
        state["highest_end"]=max(state["highest_end"],end)
        if end-start>=64 and (state["candidate"] is None or
                              end-start<state["candidate"][2]-state["candidate"][1]):
            state["candidate"]=(ordinal,start,end)
    out={"source_rows":len(rows),"referenced_archives":len(archives),"archives":[]}
    for archive,state in sorted(archives.items()):
        url=f"{pak_prefix.rstrip('/')}/imagefile{archive}.pak"
        try:
            with urlopen(Request(url,method="HEAD",headers={"User-Agent":"H1-source-probe/1"}),timeout=30) as r:
                length=int(r.headers["Content-Length"])
        except HTTPError as e:
            if e.code==404:
                out["archives"].append({"id":archive,"status":"missing","rows":state["rows"]})
                continue
            raise
        record={"id":archive,"rows":state["rows"],"physical_bytes":length,
                "highest_source_end":state["highest_end"]}
        if length<state["highest_end"]:
            record["status"]="too_short"
        elif state["candidate"] is None:
            record["status"]="extent_only_no_nonempty_sample"
        else:
            ordinal,start,end=state["candidate"]
            raw=fetch_exact_range(url,start,start+64)
            record.update({"status":"original_range_proven_not_texture_owned",
                           "sample_row":ordinal,"sample_offset":start,
                           "sample_bytes":len(raw),"sample_sha256":hashlib.sha256(raw).hexdigest()})
        out["archives"].append(record)
    out["covered_descriptor_rows"]=sum(a["rows"] for a in out["archives"] if
        a["status"] in ("original_range_proven_not_texture_owned","extent_only_no_nonempty_sample"))
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--origin",default="https://r2.houseofkublai.com")
    p.add_argument("--prefix",default="h1/h1_full_files/zone")
    p.add_argument("--stem",default="mp_crash_snow")
    p.add_argument("--report",required=True)
    args=p.parse_args()
    if not args.stem.startswith("mp_") or not args.stem.replace("_","").isalnum():
        raise SystemExit("invalid source map stem")
    url=f"{args.origin.rstrip('/')}/{args.prefix.strip('/')}/{args.stem}.ff"
    result=inspect(url,f"{args.origin.rstrip('/')}/{args.prefix.strip('/')}")
    with open(args.report,"w") as f:json.dump(result,f,indent=2)
    print("H1 original PAK range audit:",len(result["archives"]),"referenced archives;",
          result["covered_descriptor_rows"],"image rows physically source-range verified")
    for a in result["archives"]:
        print(f"imagefile{a['id']}.pak: {a['status']} ({a['rows']} refs)")

if __name__=="__main__":main()