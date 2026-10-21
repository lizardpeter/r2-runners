#!/usr/bin/env python3
"""Full-game BO1/T5 retail XAsset census from ACTUAL complete client ZIP.

All FastFiles are copied out byte-for-byte to runner-local source staging and
can be transferred as complete source files. Every successfully decoded
XAssetList record retains original zone/path/ordinal/type/pointer provenance.
Unsupported signed/compression zones are explicit failures, NEVER "decoded".
No fabricated names, no inferred attachment/camo/calling-card type enums.

The 43 XAssetType entries are the original T5 order, not T6's.
"""
from __future__ import annotations
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path,PurePosixPath
import struct
import zipfile
import zlib

T5_TYPES=[
"XMODELPIECES","PHYSPRESET","PHYSCONSTRAINTS","DESTRUCTIBLEDEF",
"XANIMPARTS","XMODEL","MATERIAL","TECHNIQUE_SET","IMAGE","SOUND",
"SOUND_PATCH","CLIPMAP","CLIPMAP_PVS","COMWORLD","GAMEWORLD_SP",
"GAMEWORLD_MP","MAP_ENTS","GFXWORLD","LIGHT_DEF","UI_MAP","FONT",
"MENULIST","MENU","LOCALIZE_ENTRY","WEAPON","WEAPONDEF",
"WEAPON_VARIANT","SNDDRIVER_GLOBALS","FX","IMPACT_FX","AITYPE",
"MPTYPE","MPBODY","MPHEAD","CHARACTER","XMODELALIAS","RAWFILE",
"STRINGTABLE","PACK_INDEX","XGLOBALS","DDL","GLASSES","EMBLEMSET",
]
assert len(T5_TYPES)==43
ZIP_SHA256="09722cfb94a30e24a90a3544df53e78c93894304bb75511067dcf3cdaf11ee9b"
ZIP_BYTES=11161080622
MAX_SOURCE_FF=900*1024*1024
MAX_ZONE=1024*1024*1024
MAX_ASSET_COUNT=2_000_000

def original_u32(src:bytes,at:int)->int:
    if at<0 or at+4>len(src):
        raise ValueError(f"truncated T5 source record at 0x{at:X}")
    return struct.unpack_from("<I",src,at)[0]

def source_address(value:int,blocks:tuple[int,...]):
    if value==0:return {"kind":"null"}
    if value==0xffffffff:return {"kind":"following"}
    if value==0xfffffffe:return {"kind":"insert"}
    addr=value-1
    block=addr>>29
    off=addr&0x1fffffff
    if block>=7 or off>=blocks[block]:
        raise ValueError(f"BO1 pointer 0x{value:08X} outside original XFile block")
    return {"kind":"packed","block":block,"offset":off}

def exact_t5_zone(raw:bytes)->bytes:
    if len(raw)<14 or raw[:8]!=b"IWffu100" or original_u32(raw,8)!=0x1d9:
        raise ValueError(f"unsupported signed/non-T5 FastFile variant {raw[:12].hex()}")
    dec=zlib.decompressobj()
    out=bytearray()
    for p in range(12,len(raw),2*1024*1024):
        out.extend(dec.decompress(raw[p:p+2*1024*1024],MAX_ZONE+1-len(out)))
        if len(out)>MAX_ZONE:raise ValueError("original T5 expanded zone >1GiB")
    out.extend(dec.flush(MAX_ZONE+1-len(out)))
    if not dec.eof or len(out)<52:
        raise ValueError("truncated original T5 zlib expanded zone")
    return bytes(out)

def parse_original_zone(raw:bytes,source_path:str)->dict:
    exp=exact_t5_zone(raw)
    capacities=struct.unpack_from("<7I",exp,8)
    strings=original_u32(exp,36)
    sptr=original_u32(exp,40)
    n=original_u32(exp,44)
    aptr=original_u32(exp,48)
    if strings>MAX_ASSET_COUNT or n>MAX_ASSET_COUNT:
        raise ValueError("BO1 source XAsset/script list count out of bounds")
    cursor=52
    if strings:
        if sptr!=0xffffffff:
            raise ValueError("BO1 source script strings require virtual-pointer load replay")
        end=cursor+strings*4
        if end>len(exp):raise ValueError("original script pointer array truncated")
        vals=struct.unpack_from("<"+"I"*strings,exp,cursor)
        cursor=end
        for value in vals:
            kind=source_address(value,capacities)["kind"]
            if kind=="null":continue
            if kind!="following":
                raise ValueError("BO1 source script-text pointer requires loader replay")
            end=exp.find(b"\0",cursor,min(cursor+1024*1024+1,len(exp)))
            if end<0:raise ValueError("original script string unterminated")
            exp[cursor:end].decode("utf-8")
            cursor=end+1
    elif sptr!=0:
        raise ValueError("BO1 script count=0 but original pointer not null")
    if n and aptr!=0xffffffff:
        raise ValueError("BO1 original XAssetList pointer requires source block relocation")
    if cursor+n*8>len(exp):
        raise ValueError("original BO1 XAssetList exceeds source bytes")
    entries=[]
    counts=Counter()
    pointer_kinds=Counter()
    for ordinal in range(n):
        at=cursor+ordinal*8
        typ=original_u32(exp,at)
        if typ>=len(T5_TYPES):
            raise ValueError(f"BO1 original type {typ} at XAsset ordinal {ordinal} unsupported")
        original_ptr=original_u32(exp,at+4)
        parsed=source_address(original_ptr,capacities)
        counts[T5_TYPES[typ]]+=1
        pointer_kinds[parsed["kind"]]+=1
        entries.append({
            "original_ordinal":ordinal,
            "type_id":typ,
            "type_name":T5_TYPES[typ],
            "source_xasset_pointer":original_ptr,
            "source_pointer_kind":parsed,
            "source_xasset_table_physical_offset":at,
            "body_structure_decoded":False,
        })
    return {
        "original_zone":source_path,
        "expanded_bytes":len(exp),
        "original_script_strings":strings,
        "original_xasset_table_offset":cursor,
        "original_block_sizes":capacities,
        "asset_count":n,
        "type_counts":dict(sorted(counts.items())),
        "source_pointer_kind_counts":dict(pointer_kinds),
        "assets":entries,
    }

def whole_sha(path:Path):
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(16*1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()

def run(archive_path:Path,out:Path):
    if archive_path.stat().st_size!=ZIP_BYTES or whole_sha(archive_path)!=ZIP_SHA256:
        raise ValueError("Original complete BO1 game ZIP does not match the source-authenticated retail SHA256")
    originals=out/"original-bo1"
    reports=out/"report"
    originals.mkdir(parents=True,exist_ok=True)
    reports.mkdir(parents=True,exist_ok=True)
    inventory=[]
    totals=Counter()
    errors=[]
    scanned=0
    with zipfile.ZipFile(archive_path) as original:
        for item in original.infolist():
            raw_path=item.filename.replace("\\","/")
            if item.is_dir() or not raw_path.lower().endswith(".ff"):continue
            path=PurePosixPath(raw_path)
            if any(part in (".","..") for part in path.parts) or path.is_absolute():
                raise ValueError(f"Unsafe BO1 source path: {raw_path}")
            relative=PurePosixPath(*path.parts[-3:])
            if not relative.parts[0].lower()=="zone" or relative.suffix.lower()!=".ff":
                raise ValueError(f"Original FF source path does not match zone layout: {raw_path}")
            dst=originals/relative
            dst.parent.mkdir(parents=True,exist_ok=True)
            if item.file_size>MAX_SOURCE_FF:
                raise ValueError(f"Original source FF {raw_path} exceeds per-file scanner read bound")
            raw=original.read(item)
            if len(raw)!=item.file_size:raise ValueError(f"BO1 truncated original {raw_path}")
            dst.write_bytes(raw)
            source_digest=hashlib.sha256(raw).hexdigest()
            entry={
                "relative_path":relative.as_posix(),
                "original_fastfile_bytes":len(raw),
                "original_sha256":source_digest,
                "original_file_preserved":True,
            }
            scanned+=1
            try:
                parsed=parse_original_zone(raw,relative.as_posix())
                entry.update(parsed)
                entry["status"]="source_xasset_table_decoded"
                totals.update(parsed["type_counts"])
            except Exception as error:
                entry["status"]="original_layout_unresolved"
                entry["decode_error"]=str(error)
                errors.append({"path":relative.as_posix(),"error":str(error)})
            inventory.append(entry)
            print(f"BO1 original {relative}: {entry.get('asset_count','unknown')} XAsset table records [{entry['status']}]",flush=True)
    inventory.sort(key=lambda x:x["relative_path"].lower())
    if scanned<4:raise ValueError("Full original game ZIP contains unexpectedly few source FFs")
    result={
        "source_zip_sha256":ZIP_SHA256,
        "all_original_fastfiles_preserved":scanned,
        "source_zones_xasset_indexed":scanned-len(errors),
        "source_zones_unresolved":len(errors),
        "original_xasset_table_records":sum(totals.values()),
        "type_totals":dict(sorted(totals.items())),
        "source_unresolved_zone_details":errors,
        "all_source_classes":T5_TYPES,
        "no_decoded_body_claim":True,
        "asset_subsystems_not_direct_enum_types":[
            "attachments","scorestreaks","camos","calling_cards",
            "weapon_audio_events","player_outfits","soundbanks",
        ],
        "zones":inventory,
    }
    (reports/"bo1-complete-original-xasset-catalog.json").write_text(
        json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(f"BO1 verified complete client: {scanned} exact original FastFiles PRESERVED, "
          f"{scanned-len(errors)} source XAsset tables indexed, "
          f"{sum(totals.values())} source records, {len(errors)} unresolved zones.")
    print("Source XAsset totals by original type:",sorted(totals.items()))
    if errors:print("UNRESOLVED SOURCE ZONES:",errors[:15])
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-game-zip",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    a=p.parse_args()
    run(a.original_game_zip,a.output_dir)
if __name__=="__main__":main()
