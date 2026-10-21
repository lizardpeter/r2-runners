#!/usr/bin/env python3
"""Probe source-authenticated T7 world roots in ANY original zone FastFile.

The first available world-root source is core_frontend.ff, not a hardcoded
map adapter. The script selects zone by env and audits all five typed world
root indices, their source ordering, and nearby potential world-name evidence.
No FF bytes, textures, model payloads or authored strings are uploaded.
"""
import hashlib,json,os,re,struct,sys,zlib
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import BASE,PREFIX,SOURCES,parse_zlib_zone,parse_directory

WORLD_TYPES={12:"col_map",13:"com_map",14:"game_map",15:"map_ents",16:"gfx_map"}
def bounded_directory_prefix(path,limit=8*1024*1024):
    out=bytearray()
    at=0x248
    blocks=0
    with path.open("rb") as f:
        size=path.stat().st_size
        while at+16<=size:
            f.seek(at)
            comp,n,span,original=struct.unpack("<IIII",f.read(16))
            if span==0:break
            if original!=at or comp==0 or span<comp or at+16+span>size:
                raise ValueError("Original T7 source prefix block header invalid")
            if n==0:
                at=(at+16+0x7fffff)&~0x7fffff
                continue
            if len(out)+n>limit:break
            coded=f.read(comp)
            plain=zlib.decompress(coded)
            if len(plain)!=n:raise ValueError("Original T7 prefix decoded source length mismatch")
            out.extend(plain)
            blocks+=1
            at+=16+span
    return out,blocks
def inspect(name):
    if name not in SOURCES:raise ValueError(f"Source zone not authenticated allowlist: {name}")
    with TemporaryDirectory(prefix="bo3-t7-world-roots-") as p:
        target=Path(p)/name
        orig_size,sha,_=download(BASE+"/"+quote(PREFIX+name,safe="/"),target)
        if orig_size!=SOURCES[name]:raise ValueError("Original BO3 zone size changed")
        bounded,read_blocks=bounded_directory_prefix(target)
        decoded,blocks=parse_zlib_zone(target)
    if blocks["status"]!="end_marker":raise ValueError("Cannot analyze incomplete T7 source zone")
    d=parse_directory(decoded)
    if d["status"]!="t7_asset_table_layout_verified":raise ValueError("Typed world directory incomplete")
    pd=parse_directory(bounded)
    if pd["status"]!="t7_asset_table_layout_verified":
        raise ValueError("BO3 prefix-only 8MiB source has no authentic full XAsset directory")
    if pd["asset_count"]!=d["asset_count"] or pd["asset_table"]["table_offset"]!=d["asset_table"]["table_offset"]:
        raise ValueError("BO3 bounded prefix and full source disagree on world roots")
    source_table_end=d["asset_table"]["table_offset"]+d["asset_count"]*16
    if bounded[:source_table_end]!=decoded[:source_table_end]:
        raise ValueError("Bounded T7 XAsset source root bytes differ from complete decoder")
    base=d["asset_table"]["table_offset"]
    count=d["asset_count"]
    world=[]
    type_ids=[]
    for row in range(count):
        typ,pointer=struct.unpack_from("<QQ",decoded,base+16*row)
        type_ids.append(typ)
        if typ in WORLD_TYPES:
            world.append({"original_asset_row":row,"root_type_id":typ,
                "type_name":WORLD_TYPES[typ],
                "header_pointer":f"0x{pointer:016x}",
                "preceding_type_ids":type_ids[max(0,row-4):row],
                "following_type_ids":[struct.unpack_from("<Q",decoded,base+16*k)[0]
                                      for k in range(row+1,min(count,row+5))]})
    # Source name evidence, no proprietary string contents exported: count
    # and byte offsets only. Map root names are not established by this.
    phrases=[b"core_frontend",b"mp_",b"frontend",b"core_common",b"map_ents",
             b"col_map",b"gfx_map",b"safehouse",b"front_end",b"ui_frontend"]
    names={}
    for term in phrases:
        cursor=0
        offsets=[]
        while len(offsets)<24:
            at=decoded.find(term,cursor)
            if at<0:break
            offsets.append(at)
            cursor=at+len(term)
        names[term.decode("ascii")]={"first_source_offsets":offsets,
                                     "truncated_at_24":len(offsets)==24}
    return {"source":name,"source_sha256":sha,
        "original_compressed_bytes":orig_size,
        "decoded_bytes":len(decoded),
        "bounded_prefix_decoded_bytes":len(bounded),
        "bounded_prefix_compressed_blocks":read_blocks,
        "prefix_vs_complete_original_root_table_verified":True,
        "decoded_blocks":blocks["block_count"],
        "source_xasset_count":count,
        "physical_source_asset_table_begin":base,
        "physical_source_asset_table_end":base+count*16,
        "original_world_root_rows":world,
        "world_root_count":len(world),
        "all_required_map_root_types_present":all(any(w["root_type_id"]==i for w in world)
                                                    for i in WORLD_TYPES),
        "source_world_name_search":names,
        "warning":"Typed world XAsset root pointers are not reconstructed GfxWorld surfaces, map entities, collision or playable spawns."}
def main():
    names=os.environ.get("BO3_WORLD_ZONES","core_frontend.ff").split(",")
    report=[inspect(n.strip()) for n in names]
    for part in report:print(json.dumps({"bo3_source_world":part},sort_keys=True),flush=True)
    target=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    target.mkdir(parents=True,exist_ok=True)
    (target/"bo3_source_world_root_probe.json").write_text(
        json.dumps({"zones":report},indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"Original BO3 world root probe failed: {e}",file=sys.stderr);raise SystemExit(1)
