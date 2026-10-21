#!/usr/bin/env python3
"""Find source-consistent T7 0x2040 GfxWorld headers across any original FF.

Generic structural search: original T7 GfxWorld has two source pointers,
then signed plane/node/surface counts (offsets 0x10/0x14/0x18). Requires
source-typed GfxWorld root and tests all plausible original headers; a
candidate is NOT an authenticated world until root loader ownership closes.
"""
import hashlib, json, os, struct, sys
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import BASE,PREFIX,SOURCES,parse_zlib_zone,parse_directory
LEN=0x2040
INLINE=b"\xff"*8
def analyze(name):
    if name not in SOURCES:raise ValueError("T7 source FF absent from original manifest")
    with TemporaryDirectory(prefix="bo3-world-bodies-") as td:
        path=Path(td)/name
        n,sha,_=download(BASE+"/"+quote(PREFIX+name,safe="/"),path)
        z,meta=parse_zlib_zone(path)
    if meta["status"]!="end_marker":raise ValueError("Incomplete source decode")
    dir=parse_directory(z)
    if dir["status"]!="t7_asset_table_layout_verified":raise ValueError("Source directory not verified")
    table=dir["asset_table"]["table_offset"]
    gfx_rows=[i for i in range(dir["asset_count"]) if struct.unpack_from("<QQ",z,table+i*16)==(16,0xffffffffffffffff)]
    if len(gfx_rows)!=1:raise ValueError("Expected uniquely inlined source GfxWorld root")
    strong=[]
    relaxed=[]
    candidates=0
    tag_hist={}
    at=table+dir["asset_count"]*16
    while at+LEN<=len(z):
        p=z.find(INLINE,at)
        if p<0 or p+LEN>len(z):break
        at=p+8
        a,b=struct.unpack_from("<QQ",z,p)
        if a!=0xffffffffffffffff:continue
        # T7 pointers are tagged 0x5N source references, zero, inline, -2.
        if b not in (0,0xffffffffffffffff,0xfffffffffffffffe) and (b>>56)!=0x50:
            continue
        planes,nodes,surfaces=struct.unpack_from("<iii",z,p+16)
        if not (0<=planes<2_000_000 and 0<=nodes<2_000_000 and 0<surfaces<1_000_000):
            continue
        candidates+=1
        stream0,stream1=struct.unpack_from("<QQ",z,p+0x20)
        # Preserve independent source evidence. No assumed streamInfo
        # layout or renderer admission from these counts.
        sample={"physical_original_header_offset":p,
          "name_source_pointer":f"0x{a:016x}",
          "base_name_source_pointer":f"0x{b:016x}",
          "plane_count":planes,"node_count":nodes,"surface_count":surfaces,
          "stream_qword0":f"0x{stream0:016x}",
          "stream_qword1":f"0x{stream1:016x}",
          "trailing_struct_sha256":hashlib.sha256(z[p+LEN-64:p+LEN]).hexdigest(),
          "first_0x60_source_bytes_hex":bytes(z[p:p+96]).hex()}
        # Structural positive cases: not a repeated material array,
        # no implausibly large plane/node count relative to surfaces.
        if planes<=200000 and nodes<=200000 and surfaces<=200000 and planes+nodes>0:
            strong.append(sample)
        elif len(relaxed)<120:relaxed.append(sample)
    return {"source":name,"sha256":sha,"source_gfx_root_rows":gfx_rows,
       "full_decoded_bytes":len(z),
       "initial_inline_pointer_gfxworld_header_candidates":candidates,
       "positive_structural_candidates_count":len(strong),
       "positive_structural_candidates":strong[:70],
       "weak_structural_candidates":relaxed[:60],
       "warning":"Header signatures are candidates; exact GfxWorld XAsset root-loader stream position and owned surfaces must be reconstructed."}
def main():
    name=os.environ.get("BO3_WORLD_ZONE","core_frontend.ff")
    result=analyze(name)
    print(json.dumps({"gfxworld_structural_search":result},sort_keys=True),flush=True)
    target=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));target.mkdir(parents=True,exist_ok=True)
    (target/"bo3_gfxworld_structural_search.json").write_text(json.dumps(result,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"T7 original GfxWorld structural scan blocked: {e}",file=sys.stderr);raise SystemExit(1)
