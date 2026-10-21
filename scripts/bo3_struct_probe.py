#!/usr/bin/env python3
"""Corroborate T7 material/XModel/mesh struct fields with original PC FastFiles.

The exact sizes and field offsets come from independently reverse-engineered
T7 loader tables. Here they are cross-checked against real decoded R2 source
rather than accepting a pattern scan as proof of decoded game assets.
No retail bytes are emitted to outputs.
"""
from __future__ import annotations
import hashlib,json,os,struct,sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import parse_zlib_zone,parse_directory

BASE="https://r2.houseofkublai.com/bo3/DUMP/zone/"
SOURCES={
    "en_core_common.ff":545024,
    "core_gfx.ff":6790208,
    "core_pre_gfx.ff":22285376,
    "en_core_frontend.ff":2977856,
    "core_specialists.ff":51386816,
}
LAYOUTS={
    "material":{"id":6,"bytes":0x2a0,"name_offset":0x2a0},
    "xmodel":{"id":4,"bytes":0x188,"name_offset":0x188},
    "xmodelmesh":{"id":5,"bytes":0x78,"name_offset":0x78},
}
MARKER=b"\xff"*8
PTRS={0,0xffffffffffffffff,0xfffffffffffffffe}
def tagged(p):return p in PTRS or (p>>60)<=8 or (p>>56)==0x50
def printable(zone,offset,maxlen=196):
    if offset>=len(zone):return None
    end=zone.find(b"\0",offset,min(len(zone),offset+maxlen))
    if end<offset+3:return None
    raw=zone[offset:end]
    if any(x<32 or x>126 for x in raw):return None
    txt=raw.decode("ascii")
    if len(txt)>160:return None
    return txt

def survey(zone:bytes,source:str):
    directory=parse_directory(bytearray(zone))
    types=directory.get("asset_table",{}).get("type_counts",{})
    count=Counter()
    candidates={}
    for label,info in LAYOUTS.items():
        start=0;valid=[];near=[]
        name_off=info["name_offset"]
        while True:
            p=zone.find(MARKER,start)
            if p<0:break
            start=p+1
            if p+name_off+4>=len(zone):continue
            name=printable(zone,p+name_off)
            if not name:continue
            props={"source_offset":p,"name":name}
            if label=="material":
                tex_count=zone[p+0x270]
                extra=(zone[p+0x271],zone[p+0x272])
                technique_ptr=struct.unpack_from("<Q",zone,p+0x278)[0]
                tex_ptr=struct.unpack_from("<Q",zone,p+0x280)[0]
                material_ptr=struct.unpack_from("<Q",zone,p+0x298)[0]
                if tex_count>96 or not all(tagged(q) for q in (technique_ptr,tex_ptr,material_ptr)):
                    continue
                props.update({"tex_count":tex_count,"technique_ptr":hex(technique_ptr),
                    "textures_ptr":hex(tex_ptr),"owning_material_ptr":hex(material_ptr),
                    "private_bytes_counts":extra,
                    "nonzero_textures_have_pointer":tex_count==0 or tex_ptr!=0})
                if tex_count and tex_ptr==0:near.append(props);continue
            if label=="xmodel":
                # T7 loader: model owns XModelMesh at +0x110 and materials
                # from LOD struct at +0xc8.
                lod_count=zone[p+8]
                meshptr=struct.unpack_from("<Q",zone,p+0x110)[0]
                model_ptr=struct.unpack_from("<Q",zone,p+0x128)[0]
                if not tagged(meshptr) or not tagged(model_ptr):continue
                props.update({"lod_byte":lod_count,"mesh_pointer":hex(meshptr),
                              "physics_pointer":hex(model_ptr)})
            if label=="xmodelmesh":
                surfaces=zone[p+0x3c]
                surfaceptr=struct.unpack_from("<Q",zone,p+0x68)[0]
                if surfaces>128 or not tagged(surfaceptr):continue
                props.update({"surfaces":surfaces,"surfaceptr":hex(surfaceptr)})
            valid.append(props)
            if len(valid)>=100000:break
        candidates[label]={"candidate_count":len(valid),
            "preview":valid[:15],
            "count_fields":dict(Counter(x.get("tex_count",x.get("surfaces",x.get("lod_byte"))) for x in valid).most_common(14)),
            "near_invalid":near[:8],
            "source_names_digest":hashlib.sha256("\n".join(sorted(x["name"] for x in valid)).encode()).hexdigest(),
            "all_offsets_digest":hashlib.sha256("\n".join(str(x["source_offset"]) for x in valid).encode()).hexdigest(),
        }
    return {"original_source":source,"decoded_zone_bytes":len(zone),
            "directory_asset_count":directory.get("asset_count"),
            "directory_status":directory.get("status"),
            "directory_type_counts":types,
            "authored_struct_candidates":candidates}

def main():
    mode=os.environ.get("BO3_STRUCT_PRESET","small")
    names={
        "small":["en_core_common.ff","core_gfx.ff","core_pre_gfx.ff"],
        "models":["en_core_common.ff","core_specialists.ff","en_core_frontend.ff"],
    }.get(mode)
    if names is None:raise ValueError("Unknown BO3 model audit preset")
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    reports=[]
    with TemporaryDirectory(prefix="real-bo3-structs-") as temp:
        for name in names:
            local=Path(temp)/name
            got,digest,_=download(BASE+quote(name),local)
            if got!=SOURCES[name]:raise ValueError(f"Original source size mismatch: {name}")
            data,blocks=parse_zlib_zone(local)
            result=survey(data,name)
            result["source_sha256"]=digest
            reports.append(result)
            print(json.dumps(result,sort_keys=True),flush=True)
    (root/"bo3_material_model_struct_probes.json").write_text(
        json.dumps(reports,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":
    try:main()
    except Exception as error:
        print(f"BO3 T7 source struct probe failed: {error}",file=sys.stderr)
        sys.exit(1)
