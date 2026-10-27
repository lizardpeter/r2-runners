#!/usr/bin/env python3
"""Inspect authentic T6 IPAK headers, section tables and index entries via R2 ranges.

Does not fetch multi-gigabyte data sections; keeps every entry payload opaque,
and never equates validated offsets with image semantic understanding.
"""
import argparse,hashlib,json,struct,time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from urllib.parse import quote,urlsplit
from urllib.request import Request,urlopen

R2="https://r2.houseofkublai.com/"
CHUNK=2*1024*1024

def getrange(key,total,start,length):
    if length==0:return b""
    if not (0<=start<total and 0<length<=total-start):
        raise ValueError("Range outside original R2 object")
    url=R2+quote(key,safe="/")
    pieces=[]
    at=start
    end=start+length
    while at<end:
        stop=min(end,at+CHUNK)-1
        wanted=f"bytes {at}-{stop}/{total}"
        for trial in range(3):
            try:
                req=Request(url,headers={"Range":f"bytes={at}-{stop}","Accept-Encoding":"identity",
                                        "User-Agent":"r2-runners/ipak-observatory/1"})
                with urlopen(req,timeout=70) as r:
                    if r.status!=206 or urlsplit(r.url).hostname!="r2.houseofkublai.com":
                        raise ValueError("Source response was not exact 206 from pinned R2 host")
                    got=r.headers.get("Content-Range","")
                    if got!=wanted:raise ValueError(f"Content-Range {got!r} != {wanted!r}")
                    blob=r.read(stop-at+2)
                    if len(blob)!=stop-at+1:raise ValueError("R2 source range truncated")
                pieces.append(blob)
                at=stop+1
                break
            except Exception:
                if trial==2:raise
                time.sleep(1+trial)
    return b"".join(pieces)

def check(f):
    key,total=f["r2_key"],f["r2_size"]
    row={"source_key":key,"original_r2_size":total,"status":"pending",
         "source_original_sha256":"not_hashed_full_object",
         "proof_boundary":"Original R2 header, section table and index ranges only; data payloads not fetched or understood"}
    try:
        prefix=getrange(key,total,0,16)
        magic=prefix[:4]
        if magic not in (b"KAPI",b"IPAK"):raise ValueError("Unexpected original magic")
        endian="<" if magic==b"KAPI" else ">"
        version,declared,nsec=struct.unpack_from(endian+"III",prefix,4)
        if version!=0x50000:raise ValueError(f"IPAK version unsupported: {version}")
        if declared!=total:raise ValueError(f"IPAK declared physical size {declared} != R2 {total}")
        if not 1<=nsec<=64:raise ValueError("Bad section count")
        table=getrange(key,total,16,16*nsec)
        sections=[]
        for n in range(nsec):
            typ,start,size,count=struct.unpack_from(endian+"IIII",table,16*n)
            if start+size>total:raise ValueError(f"section {n} outside object")
            sections.append({"id":n,"type":typ,"offset":start,"size":size,"item_count":count})
        indices=[x for x in sections if x["type"]==1]
        datas=[x for x in sections if x["type"]==2]
        if len(indices)!=1 or len(datas)!=1:
            raise ValueError("IPAK needs exactly one data and one index section")
        ix=indices[0];data=datas[0]
        length=ix["item_count"]*16
        if length>ix["size"]:raise ValueError("Index entries exceed declared index section")
        entries=getrange(key,total,ix["offset"],length)
        h=hashlib.sha256(entries).hexdigest()
        seen=set()
        total_payload=0
        for n in range(ix["item_count"]):
            dh,nh,offset,size=struct.unpack_from(endian+"IIII",entries,16*n)
            if offset+size>data["size"]:
                raise ValueError(f"data span escapes section at entry {n}")
            identity=(nh,dh)
            if identity in seen:raise ValueError(f"Duplicate exact source entry at {n}")
            seen.add(identity)
            total_payload+=size
        row.update(status="ipak_index_validated",magic=magic.decode("ascii"),
                   endian="little" if endian=="<" else "big",
                   version=version,section_count=nsec,sections=sections,
                   index_entry_count=ix["item_count"],
                   index_entry_table_bytes=length,index_entry_bytes_sha256=h,
                   payload_serialized_bytes_summed=total_payload,
                   original_r2_ranges_verified=2+(length+CHUNK-1)//CHUNK,
                   non_index_data_contents="not_examined")
    except Exception as e:
        row.update(status="ipak_range_or_format_error",error=str(e)[:800])
    return row

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--headers",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--workers",type=int,default=6)
    a=p.parse_args()
    source=json.loads(a.headers.read_text())
    if source["schema"]!="source-observatory/original-r2-signature-corpus/v1" or not source["complete_signature_survey"]:
        raise ValueError("Refusing unauthenticated R2 file list")
    files=[f for f in source["files"] if f["extension"]=="ipak"]
    if len(files)!=23:raise ValueError("Expected exactly 23 real IPAKs")
    with ThreadPoolExecutor(max_workers=min(8,max(1,a.workers))) as pool:
        jobs=[pool.submit(check,f) for f in files]
        reports=[j.result() for j in as_completed(jobs)]
    reports.sort(key=lambda f:f["source_key"])
    states=dict(Counter(x["status"] for x in reports))
    out={"schema":"source-observatory/t6-ipak-index/v1",
         "all_r2_ipaks_accounted":len(reports)==23,
         "original_ipaks":len(reports),
         "indexes_validated":states.get("ipak_index_validated",0),
         "state_counts":states,
         "total_indexed_entries":sum(f.get("index_entry_count",0) for f in reports),
         "proof_boundary":"Range-read exact original R2 headers, section tables and 16-byte entry directory spans. Source whole-file SHA256 not established by this range audit; compressed LZO/RAW texture blocks and image semantics remain unevaluated.",
         "files":reports}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({k:v for k,v in out.items() if k not in ("files","proof_boundary")},indent=2))
    if out["indexes_validated"]!=23:raise RuntimeError("One or more IPAK entry directories failed; all failures recorded")
if __name__=="__main__":main()
