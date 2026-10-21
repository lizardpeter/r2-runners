#!/usr/bin/env python3
"""T7 PC GfxWorld typed header structural check on original FastFile.

Reference T7 GfxWorld header layout is 0x2040 bytes, name pointer at +0,
baseName at +8, plane/node/surface counts at +0x10/+0x14/+0x18,
streamInfo at +0x20. Test possible physical header ownership using
the actual inline source names; never call any random matching byte
sequence a finished GfxWorld.
"""
import hashlib,json,os,re,struct,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import BASE,PREFIX,SOURCES,parse_zlib_zone,parse_directory

GFXWORLD_BYTES=0x2040
def tagged(value):return value in (0,(1<<64)-1,(1<<64)-2) or (value>>56)==0x50
def detail(data,start,name_pos,name):
    if start<0 or start+GFXWORLD_BYTES>len(data):return None
    ptr,base,planes,nodes,surf=struct.unpack_from("<QQIII",data,start)
    return {"candidate_source_start":start,"candidate_name_source_offset":name_pos,
        "source_name":name,"name_ptr":f"0x{ptr:016x}","base_name_ptr":f"0x{base:016x}",
        "source_planes":planes,"source_nodes":nodes,"source_surfaces":surf,
        "original_0x20_streaminfo_qword":f"0x{struct.unpack_from('<Q',data,start+0x20)[0]:016x}",
        "both_initial_source_pointers_tagged":tagged(ptr) and tagged(base),
        "plausible_bounded_counts":0<=planes<2_000_000 and 0<=nodes<2_000_000 and 0<surf<2_000_000}
def main():
    name=os.environ.get("BO3_WORLD_ZONE","core_frontend.ff")
    if name not in SOURCES:raise ValueError("Original FastFile not in R2 source manifest")
    with TemporaryDirectory(prefix="t7-gfxworld-header-") as td:
        target=Path(td)/name
        n,sha,_=download(BASE+"/"+quote(PREFIX+name,safe="/"),target)
        source,meta=parse_zlib_zone(target)
    d=parse_directory(source)
    if d["status"]!="t7_asset_table_layout_verified":raise ValueError("Unverified source XAsset rows")
    base=d["asset_table"]["table_offset"]
    gfx_rows=[i for i in range(d["asset_count"]) if struct.unpack_from("<Q",source,base+16*i)[0]==16]
    if len(gfx_rows)!=1:raise ValueError(f"Expected exactly one original gfx_map source row, got {gfx_rows}")
    candidates=[]
    for needle in (b"core_frontend\x00",b"maps/core/core_frontend.d3dbsp\x00"):
        position=0
        while True:
            at=source.find(needle,position)
            if at<0:break
            position=at+1
            candidates.append(detail(source,at-GFXWORLD_BYTES,at,needle[:-1].decode()))
            if len(candidates)>400:break
    candidates=[x for x in candidates if x]
    feasible=[c for c in candidates if c["both_initial_source_pointers_tagged"]
                                  and c["plausible_bounded_counts"]]
    report={"original_source":name,"source_sha256":sha,
      "gfx_world_typed_asset_rows":gfx_rows,
      "genuine_source_name_suffix_candidate_count":len(candidates),
      "genuine_struct_start_plausible_count":len(feasible),
      "source_name_candidates":candidates[:48],
      "bounded_tagged_plausible_candidates":feasible,
      "note":"Type16 root association remains unproven until original T7 serialization order and nested GfxWorld buffers are checked."}
    print(json.dumps(report,sort_keys=True),flush=True)
    out=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));out.mkdir(parents=True,exist_ok=True)
    (out/"bo3_first_gfxworld_header_candidates.json").write_text(json.dumps(report,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"Source GfxWorld structural probe blocked: {e}",file=sys.stderr);raise SystemExit(1)
