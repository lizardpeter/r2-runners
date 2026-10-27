#!/usr/bin/env python3
"""Parse original 2UX# v14 SABS/SABL bank headers + 20-byte entry directory.

Reads only authenticated R2 HTTP byte ranges, never audio payloads. Proves
table structure and referenced bounds, not codec rendering or every byte.
"""
import argparse,hashlib,importlib.util,json,struct
from collections import Counter
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path

HEADER=2048
ENTRY=20

def parse(f,reader):
    key=f["r2_key"];length=f["r2_size"]
    row={"source_key":key,"original_r2_size":length,"extension":f["extension"],"status":"pending",
         "source_original_sha256":"not_hashed_full_object",
         "proof_boundary":"Original R2 v14 2UX# sound bank header and indexed 20-byte entry records only; payload codec and actual audio samples not decoded"}
    try:
        header=reader.getrange(key,length,0,HEADER)
        if header[:4]!=b"2UX#":raise ValueError("Unrecognized sound bank header")
        version,entry_size=struct.unpack_from("<II",header,4)
        if version!=14 or entry_size!=ENTRY:raise ValueError("Unsupported bank version or entry size")
        dep_size=struct.unpack_from("<I",header,0x10)[0]
        entry_count=struct.unpack_from("<I",header,0x14)[0]
        dep_count=struct.unpack_from("<I",header,0x18)[0]
        declared_size,table_offset=struct.unpack_from("<QQ",header,0x20)
        if declared_size!=length:raise ValueError("Declared soundbank size mismatches original R2 source")
        if table_offset>length or entry_count*ENTRY>length-table_offset:
            raise ValueError("Sound entry table exceeds original file")
        if dep_size and dep_count and dep_size*dep_count>HEADER-0x48:
            raise ValueError("Sound dependency table escapes the 2048-byte header")
        entries=reader.getrange(key,length,table_offset,entry_count*ENTRY)
        ids=set();dupes=0
        fmt=Counter();rates=Counter();channels=Counter();loops=Counter();samples=0
        for n in range(entry_count):
            aid,size,offset,frames=struct.unpack_from("<IIII",entries,ENTRY*n)
            fr,ch,loop,codec=struct.unpack_from("<BBBB",entries,ENTRY*n+16)
            if offset==0 or offset+size>length:
                raise ValueError(f"sound entry {n} references data outside source")
            if aid in ids:dupes+=1
            ids.add(aid)
            fmt[str(codec)]+=1
            rates[str(fr)]+=1
            channels[str(ch)]+=1
            loops[str(loop)]+=1
            samples+=size
        row.update(status="bank_entry_index_validated",magic="2UX#",version=version,
            entry_count=entry_count,unique_sound_ids=len(ids),duplicate_sound_ids=dupes,
            bank_entry_size=ENTRY,header_bytes_examined=HEADER,
            entry_directory_start=table_offset,entry_directory_bytes=len(entries),
            entry_directory_sha256=hashlib.sha256(entries).hexdigest(),
            dependency_count=dep_count,dependency_size=dep_size,
            frame_rate_index_counts=dict(sorted(rates.items())),
            audio_format_code_counts=dict(sorted(fmt.items())),
            channel_counts=dict(sorted(channels.items())),
            looping_flag_counts=dict(sorted(loops.items())),
            entry_payload_serialized_bytes_summed=samples,
            original_payload_samples="not_read")
    except Exception as exc:
        row.update(status="bank_header_or_index_error",error=str(exc)[:600])
    return row

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--headers",type=Path,required=True)
    p.add_argument("--reader",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--workers",type=int,default=8)
    a=p.parse_args()
    base=json.loads(a.headers.read_text())
    if base["schema"]!="source-observatory/original-r2-signature-corpus/v1" or not base["complete_signature_survey"]:
        raise ValueError("Full original R2 prefix survey required")
    sources=[x for x in base["files"] if x["extension"] in ("sabs","sabl")]
    if len(sources)!=116:raise ValueError("Expected 116 original sound bank files")
    spec=importlib.util.spec_from_file_location("r2_ranges",a.reader)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with ThreadPoolExecutor(max_workers=min(12,max(1,a.workers))) as pool:
        futures=[pool.submit(parse,f,module) for f in sources]
        results=sorted((f.result() for f in as_completed(futures)),key=lambda x:x["source_key"])
    states=dict(Counter(x["status"] for x in results))
    out={"schema":"source-observatory/t6-sound-bank-index/v1",
         "source_files":len(results),"source_sabs":sum(x["extension"]=="sabs" for x in results),
         "source_sabl":sum(x["extension"]=="sabl" for x in results),
         "entry_tables_validated":states.get("bank_entry_index_validated",0),
         "indexed_entry_records":sum(x.get("entry_count",0) for x in results),
         "state_counts":states,"semantic_complete":False,
         "proof_boundary":"The 2048-byte bank header and 20-byte sound entry directory ranges were read from original R2. Audio frames, SndAlias binding, runtime decode and full-bank hashes not established.",
         "files":results}
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({k:v for k,v in out.items() if k not in ("files","proof_boundary")},indent=2))
    if out["entry_tables_validated"]!=116:raise RuntimeError("One or more original sound bank directories failed")
if __name__=="__main__":main()
