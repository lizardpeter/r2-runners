#!/usr/bin/env python3
"""Cross-check original T7 map-script model placements against local XModel headers.

A placement name matching one valid source XModel 0x188-byte header is
source-authenticated identity, NOT a full model->mesh/geometry/render join.
No source bytes exported and no fabricated world meshes.
"""
import hashlib,json,os,struct,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import BASE,PREFIX,SOURCES,parse_zlib_zone,parse_directory
from bo3_world_entity_probe import parse_entities,MAP_NAME

def validptr(x):return x in (0xffffffffffffffff,0xfffffffffffffffe) or (x>>56) in (0x50,0x60)
def original_xmodel(zone,offset,name):
    if offset<0 or offset+0x188+len(name)+1>len(zone):return None
    if zone[offset:offset+8]!=b"\xff"*8:return None
    bones=zone[offset+8]
    lod=zone[offset+0x40]
    mat,=struct.unpack_from("<Q",zone,offset+0xc8)
    if bones>80 or not 1<=lod<=8 or not validptr(mat) or mat==0:return None
    refs=list(struct.unpack_from("<8Q",zone,offset+0x88))
    if any(not validptr(x) or (i<lod and x==0) for i,x in enumerate(refs)):return None
    return {"source_xmodel_header":offset,"authored_bones":bones,
      "authored_lods":lod,"material_owner_source_pointer":f"0x{mat:016x}",
      "first_lod_ref":f"0x{refs[0]:016x}"}
def main():
    name=os.environ.get("BO3_WORLD_ZONE","core_frontend.ff")
    if name not in SOURCES:raise ValueError("Original source file not in verified manifest")
    with TemporaryDirectory(prefix="bo3-xmodel-world-") as td:
        f=Path(td)/name
        size,sha,_=download(BASE+"/"+quote(PREFIX+name,safe="/"),f)
        z,blocks=parse_zlib_zone(f)
    d=parse_directory(z)
    if d["status"]!="t7_asset_table_layout_verified":raise ValueError("Zone typed source table unauthenticated")
    at=MAP_NAME.search(z)
    if at is None:raise ValueError("Original map entities source name not found")
    body=at.end()
    end=z.find(b"\0",body,body+32*1024*1024)
    if end<0:raise ValueError("Original map text unterminated")
    ents=parse_entities(z[body:end])
    authored=[(i,e) for i,e in enumerate(ents) if e.get("classname")=="script_model" and e.get("model")]
    unique=sorted({e["model"] for _,e in authored})
    joined={}
    for text in unique:
        blob=text.encode()+b"\0"
        if len(blob)>170:continue
        original_matches=[]
        string_occurrences=0
        start=0
        while True:
            index=z.find(blob,start)
            if index<0:break
            start=index+1
            string_occurrences+=1
            header=original_xmodel(z,index-0x188,text)
            if header is not None:original_matches.append(header)
        joined[text]={"source_string_occurrences":string_occurrences,
                      "original_struct_verified_xmodel_count":len(original_matches),
                      "original_struct_verified_xmodel_headers":original_matches[:4]}
    admitted_names={name for name,match in joined.items()
                    if match["original_struct_verified_xmodel_count"]==1}
    scene={"zone":name,"original_sha256":sha,"authored_script_model_entities":len(authored),
      "unique_script_model_names":len(unique),
      "uniquely_authentic_xmodel_names":len(admitted_names),
      "script_model_placements_with_local_xmodel_identity":sum(
          e["model"] in admitted_names for _,e in authored),
      "model_source_joins":joined,
      "original_gfxworld_geometry_admitted":0,
      "original_model_surface_mesh_owner_resolved":0,
      "warning":"Proven XModel source header name does not establish XModelMesh, model shader, skinning or GfxWorld placement render parity."}
    print(json.dumps({"model_source_placement_joins":scene},sort_keys=True),flush=True)
    report=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));report.mkdir(parents=True,exist_ok=True)
    (report/"bo3_first_world_xmodel_placement_identity.json").write_text(json.dumps(scene,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"Original T7 model placement join failed: {e}",file=sys.stderr);raise SystemExit(1)
