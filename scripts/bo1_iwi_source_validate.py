#!/usr/bin/env python3
"""Validate ALL original BO1 map image files against their original IWI mip layout.

Consumes genuine complete IWI bytes from the 11GB retail client provenance
workflow, not a JSON report or generated image fixture. Checks exact SHA-256,
IWI v0D header, format/flags, and source full-resolution encoded mip spans.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

def validate_original_iwi(path:Path)->str:
    data=path.read_bytes()
    if len(data)<48 or data[:4]!=b"IWi\x0d":
        raise ValueError(f"Not original T5 version-0x0D IWI: {path}")
    fmt,usage=data[4:6]
    width,height,depth=struct.unpack_from("<HHH",data,6)
    if not 1<=width<=8192 or not 1<=height<=8192 or depth!=1 or usage&4:
        raise ValueError(f"Not an original two-dimensional IWI: {path}")
    if fmt not in (11,12,13):
        raise ValueError(f"Original IWI source format not covered yet: {path}, {fmt}")
    block_count=((width+3)//4)*((height+3)//4)
    expected=block_count*(8 if fmt==11 else 16)
    offsets=struct.unpack_from("<8I",data,16)
    if len(data)==48+expected and all(offset==len(data) for offset in offsets):
        return "eof_single_mip"
    spans=sorted(set(offset for offset in offsets if 48<=offset<len(data)))
    for i,start in enumerate(spans):
        end=spans[i+1] if i+1<len(spans) else len(data)
        if end-start==expected:
            return "full_resolution_multi_mip"
    raise ValueError(f"Original source IWI has no exact top mip: {path}")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path,required=True)
    p.add_argument("--transfer-manifest",type=Path,required=True)
    args=p.parse_args()
    manifest=json.loads(args.transfer_manifest.read_text())
    files=manifest["files"]
    mips=Counter();formats=Counter()
    image_count=0
    for source in files:
        path=args.source_root/source["path"]
        if not path.is_file() or path.stat().st_size!=source["size"]:
            raise ValueError(f"Original exact source file not transferred: {path}")
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest!=source["sha256"]:
            raise ValueError(f"Original BO1 source SHA256 changed: {path}")
        if not path.suffix.lower()==".iwi":continue
        mode=validate_original_iwi(path)
        mips[mode]+=1
        with path.open("rb") as f:
            f.seek(4)
            formats[f.read(1).hex()]+=1
        image_count+=1
    if image_count!=162 or dict(formats)!={"0b":24,"0d":138} or        mips["full_resolution_multi_mip"]!=162:
        raise ValueError(f"BO1 retail map texture closure incomplete: "
                         f"image_count={image_count}, formats={formats}, mips={mips}")
    print("VERIFIED source IWI: all 162 complete original image files, "
          "exact SHA256, 24 BC1 + 138 BC3 and 162/162 validated "
          "full-resolution source multi-mip payloads.")
if __name__=="__main__":
    main()
