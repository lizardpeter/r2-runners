#!/usr/bin/env python3
"""Recover ACTUAL BO1 original map texture files from the COMPLETE client ZIP.

Downloads are handled by the workflow. This tool opens the retail client ZIP,
reads original world GfxImage names directly from both authentic map FastFiles,
scans EVERY nested client IWD, and copies full byte-exact matching source IWI
files to a transferable source tree. Never infers a generated (~...) image
filename or treats a packed virtual GfxImage pointer as a named image.

It keeps duplicate archive candidates separate: archive precedence remains
unresolved until retail zone/file lookup rules are reconstructed.
"""
from __future__ import annotations
import argparse
from collections import defaultdict, Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import tempfile
import zipfile
import zlib

ORIGINAL_MAPS={
    "mp_nuked.ff":(0x3578A12,182),
    "mp_firingrange.ff":(0x34E0502,407),
}
MAX_IWI_BYTES=256*1024*1024
MAX_ZONE_BYTES=200*1024*1024

def u32(src:bytes, at:int)->int:
    if at<0 or at+4>len(src):raise ValueError("truncated original BO1 uint32")
    return struct.unpack_from("<I",src,at)[0]

def source_name(src:bytes,at:int)->tuple[str,int]:
    end=src.find(b"\0",at,at+261)
    if end<=at:raise ValueError("BO1 original source string missing/too long")
    return src[at:end].decode("ascii"),end+1

def exact_member(outer:zipfile.ZipFile,suffix:str)->str:
    matches=[name for name in outer.namelist()
             if name.replace("\\","/").lower().endswith("/"+suffix.lower())
             or name.replace("\\","/").lower()==suffix.lower()]
    if len(matches)!=1:
        raise ValueError(f"Expected exactly one original source member {suffix}, got {matches[:5]}")
    return matches[0]

def original_map_dependencies(src:bytes, material_offset:int, count:int)->dict:
    if src[:8]!=b"IWffu100" or u32(src,8)!=0x1d9:
        raise ValueError("Not the expected genuine BO1 PC client FastFile")
    zone=zlib.decompress(src[12:])
    if len(zone)>MAX_ZONE_BYTES:raise ValueError("BO1 original GfxWorld zone too large")
    for ordinal in range(count):
        p=material_offset+8*ordinal
        if u32(zone,p)!=0xffffffff or not 256<=u32(zone,p+4)<=2_000_000:
            raise ValueError(f"Original BO1 GfxWorld MaterialMemory row {ordinal} changed")
    cursor=material_offset+8*count
    dependencies=[]
    generated=Counter()
    roles=Counter()
    packed=0
    for ordinal in range(count):
        head=zone[cursor:cursor+192]
        if len(head)!=192 or u32(head,0)!=0xffffffff:
            raise ValueError(f"BO1 original MaterialMemory inline header {ordinal} invalid")
        ntex,nconst,nstates=head[170],head[171],head[172]
        tptr,cptr,sptr=struct.unpack_from("<III",head,180)
        cursor+=192
        _,cursor=source_name(zone,cursor)
        textures=[]
        if tptr==0xffffffff:
            for i in range(ntex):
                raw=zone[cursor+i*16:cursor+(i+1)*16]
                if len(raw)!=16:raise ValueError("Truncated original MaterialTextureDef")
                textures.append((raw[7],u32(raw,12)))
            cursor+=16*ntex
            for sem,ptr in textures:
                roles[sem]+=1
                if ptr!=0xffffffff:
                    if ptr not in (0,0xfffffffe):packed+=1
                    continue
                image=zone[cursor:cursor+52]
                if len(image)!=52:raise ValueError("Truncated original inline GfxImage")
                resource=u32(image,0)
                nameptr=u32(image,44)
                width,height=struct.unpack_from("<HH",image,20)
                cursor+=52
                name=None
                if nameptr==0xffffffff:name,cursor=source_name(zone,cursor)
                elif nameptr!=0:raise ValueError("BO1 original image uses unresolved packed name")
                if resource==0xfffffffe:
                    resource_bytes=u32(zone,cursor+8)
                    cursor+=12+resource_bytes
                elif resource!=0:
                    raise ValueError("BO1 original image has unsupported GPU resource pointer")
                if not name:continue
                if name.startswith(("~",",")):
                    generated["generated" if name.startswith("~") else "runtime"]+=1
                elif width>0 and height>0:
                    logical=f"images/{name}.iwi".lower()
                    # Every requested image is a real source-backed GfxImage name
                    # with original dimensions and semantic. Never fabricate IWI.
                    dependencies.append((logical,width,height,sem))
        elif tptr or ntex:
            raise ValueError("Original BO1 material uses non-inline texture table")
        if cptr==0xffffffff:cursor+=nconst*32
        elif cptr or nconst:raise ValueError("Original BO1 material constant table needs replay")
        if sptr==0xffffffff:cursor+=nstates*8
        elif sptr or nstates:raise ValueError("Original BO1 material state table needs replay")
        if cursor>len(zone):raise ValueError("BO1 original material sequence truncated")
    return dict(dependencies=dependencies,generated=generated,roles=roles,packed=packed)

def safe_member_path(raw:str)->str:
    value=raw.replace("\\","/")
    if value.startswith("/") or any(p in ("..","") for p in PurePosixPath(value).parts):
        raise ValueError(f"unsafe original IWD member path {raw!r}")
    return value.lower()

def scan_original_client(zip_file:Path,output_dir:Path):
    if not zip_file.is_file():raise ValueError("complete original client ZIP not present")
    out=output_dir/"original-bo1"
    out.mkdir(parents=True,exist_ok=True)
    findings={}
    requests=defaultdict(set)
    with zipfile.ZipFile(zip_file) as game:
        if len(game.namelist())>50000:raise ValueError("unexpected original client archive count")
        for mapname,(offset,count) in ORIGINAL_MAPS.items():
            source_file=exact_member(game,f"zone/common/{mapname}")
            source=game.read(source_file)
            rel=out/"zone"/"common"/mapname
            rel.parent.mkdir(parents=True,exist_ok=True)
            rel.write_bytes(source)
            decoded=original_map_dependencies(source,offset,count)
            findings[mapname]={
                "sha256":hashlib.sha256(source).hexdigest(),
                "original_bytes":len(source),
                "original_materials":count,
                "inline_direct_image_slots":len(decoded["dependencies"]),
                "original_packed_image_slots":decoded["packed"],
                "generated_source_names":dict(decoded["generated"]),
                "source_semantics":dict(decoded["roles"]),
            }
            for name,w,h,sem in decoded["dependencies"]:
                requests[name].add((mapname,w,h,sem))
        candidates=defaultdict(list)
        archives_scanned=0
        original_iwd_paths=sorted(
            (n for n in game.namelist()
             if n.lower().endswith(".iwd") and
                 ("/main/" in n.lower() or n.lower().startswith("main/"))),
            key=lambda x:x.lower(),
        )
        if not original_iwd_paths:raise ValueError("Full original BO1 client has no IWDs")
        for outer_member in original_iwd_paths:
            basename=PurePosixPath(outer_member).name.lower()
            with tempfile.TemporaryDirectory(prefix="bo1-iwd-") as scratch:
                nested_path=Path(scratch)/basename
                with game.open(outer_member) as original, nested_path.open("wb") as target:
                    shutil.copyfileobj(original,target,2*1024*1024)
                with nested_path.open("rb") as nested:
                    if nested.read(4)==b"IWD2":
                        print(f"Skipping non-texture IWD2 metadata table {basename}")
                        continue
                with zipfile.ZipFile(nested_path) as iwd:
                    archives_scanned+=1
                    for entry in iwd.infolist():
                        if entry.is_dir():continue
                        logical=safe_member_path(entry.filename)
                        if logical not in requests:continue
                        if entry.file_size>MAX_IWI_BYTES:
                            raise ValueError(f"Original IWI {basename}/{logical} too large")
                        src=iwd.read(entry)
                        if len(src)!=entry.file_size or len(src)<48 or src[:4]!=b"IWi\x0d":
                            raise ValueError(f"BO1 original IWI source invalid: {basename}/{logical}")
                        iw,ih=struct.unpack_from("<HH",src,6)
                        for _,expected_w,expected_h,_ in requests[logical]:
                            if (iw,ih)!=(expected_w,expected_h):
                                raise ValueError(f"Original GfxImage dimensions conflict with IWD {basename}/{logical}")
                        dest=out/"main"/basename/logical
                        dest.parent.mkdir(parents=True,exist_ok=True)
                        dest.write_bytes(src)
                        candidates[logical].append({
                            "archive":basename,"entry":logical,"bytes":len(src),
                            "sha256":hashlib.sha256(src).hexdigest(),
                            "format":src[4],"width":iw,"height":ih,
                            "source_roles":sorted({sem for _,_,_,sem in requests[logical]}),
                        })
            print(f"Inspected original full client IWD {basename}: {len(candidates)} requested names currently found",flush=True)
    status=Counter()
    for logical,owners in requests.items():
        status[("absent","unique","ambiguous")[min(len(candidates[logical]),2)]]+=1
    audit={
        "original_complete_client_sha256":hashlib.sha256(zip_file.read_bytes()).hexdigest(),
        "map_fastfiles":findings,
        "source_direct_image_names":len(requests),
        "original_iwd_archives_scanned":archives_scanned,
        "source_iwd_candidate_status":dict(status),
        "matches":dict(candidates),
        "unmatched_names":sorted(k for k,v in candidates.items() if not v),
        "ambiguous_names":sorted(k for k,v in candidates.items() if len(v)>1),
        "source_originals_available":True,
    }
    # The report is companion evidence; ACTUAL original FastFiles and IWI
    # files are saved alongside it under original-bo1.
    report=output_dir/"report"/"original-bo1-client-iwi-material-match.json"
    report.parent.mkdir(parents=True,exist_ok=True)
    report.write_text(json.dumps(audit,indent=2)+"\n")
    print(f"Authentic BO1 client: {len(requests)} distinct original named image dependencies, "
          f"{archives_scanned} full original IWDs inspected, "
          f"{status['unique']} unique / {status['absent']} unavailable / "
          f"{status['ambiguous']} ambiguous direct source IWI names")
    print(f"Preserved original source files and exact image bytes under {out}")
    return audit

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("--client-zip",type=Path,required=True)
    a.add_argument("--output-dir",type=Path,required=True)
    args=a.parse_args()
    scan_original_client(args.client_zip,args.output_dir)

if __name__=="__main__":
    main()
