#!/usr/bin/env python3
"""Read original T6 unsigned dedicated-server XChunks without Salsa20.

The magic/version selects three platform-specific TAsvu100 variants. Source
bytes are obtained from R2 by the surrounding audit. All decompressed bytes
are kept in a distinct XFile address space; padding and unknowns stay
accounted rather than called semantically parsed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

MAX_CHUNK=0x8000
RAW_BOUNDARY=0x80000
MAX_EXPANDED=600*1024*1024
ALLOWED={146:"ps3",147:"pc",148:"wiiu"}

def decode(data):
    if len(data)<12 or data[:8]!=b"TAsvu100":
        raise ValueError("Not original unsigned T6 server FastFile magic")
    version=struct.unpack_from("<I",data,8)[0]
    if version not in ALLOWED:raise ValueError(f"Unrecognized T6 server version {version}")
    pos=12
    rawmod=pos%RAW_BOUNDARY
    output=bytearray()
    recs=[]
    sentinel=False
    while pos+4<=len(data):
        if rawmod+4>RAW_BOUNDARY:
            skip=RAW_BOUNDARY-rawmod
            pos+=skip
            rawmod=0
            if pos+4>len(data):break
        offset=pos
        chunk_len=struct.unpack_from("<I",data,pos)[0]
        pos+=4
        rawmod=(rawmod+4)%RAW_BOUNDARY
        if chunk_len==0:
            sentinel=True
            break
        if chunk_len>MAX_CHUNK or pos+chunk_len>len(data):
            raise ValueError(f"Invalid XChunk {len(recs)} size={chunk_len} offset={pos}")
        compressed=data[pos:pos+chunk_len]
        z=zlib.decompressobj(wbits=-15)
        decoded=z.decompress(compressed,MAX_CHUNK+1)
        decoded+=z.flush()
        if not z.eof or z.unused_data or z.unconsumed_tail or len(decoded)>MAX_CHUNK:
            raise ValueError(f"XChunk {len(recs)} not one complete raw DEFLATE stream")
        if len(output)+len(decoded)>MAX_EXPANDED:
            raise ValueError("Expanded XFile exceeds conservative test memory bound")
        recs.append({"index":len(recs),"input_length_field_start":offset,
                     "input_payload_start":pos,"input_payload_end":pos+chunk_len,
                     "expanded_end":len(output)+len(decoded),"expanded_length":len(decoded)})
        output.extend(decoded)
        pos+=chunk_len
        rawmod=(rawmod+chunk_len)%RAW_BOUNDARY
    else:
        raise ValueError("No terminal zero-length XChunk or source exhausted")
    # The original file can contain 0x40-aligned trailing padding. Track all
    # input bytes even where the ownership is not proven semantically.
    trailing=data[pos:]
    return bytes(output),{"chunk_count":len(recs),"chunks":recs,
                          "consumed_bytes_including_zero_chunk":pos,
                          "trailing_bytes":len(trailing),
                          "trailing_all_zero":all(b==0 for b in trailing),
                          "terminated_at_zero_chunk":sentinel,
                          "platform_by_t6_header_version":ALLOWED[version],
                          "version":version}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args()
    raw=a.source.read_bytes()
    expanded,proof=decode(raw)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_bytes(expanded)
    proof.update({"source_bytes":len(raw),
                  "source_sha256":hashlib.sha256(raw).hexdigest(),
                  "expanded_bytes":len(expanded),
                  "expanded_sha256":hashlib.sha256(expanded).hexdigest(),
                  "semantic_complete":False,
                  "proof_boundary":"Unsigned original XChunks and raw DEFLATE expansion only. Zone asset semantics not verified."})
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps({k:v for k,v in proof.items() if k not in ("chunks",)}))
if __name__=="__main__":
    try:main()
    except Exception as e:
        print("T6_UNSIGNED_FAIL_CLOSED: "+str(e),file=sys.stderr)
        sys.exit(1)
