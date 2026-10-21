#!/usr/bin/env python3
"""Prove sequential first-owned XModelMesh body locations in BO3 retail FF.

Only recover source offsets, sizes and structural field metadata. No meshes,
script strings, or retail binary payloads leave the runner. First root body
must start EXACTLY at the end of the validated original XAsset directory.
"""
from __future__ import annotations
import hashlib,json,os,struct,sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import parse_zlib_zone,parse_directory
from bo3_struct_probe import printable,tagged
NAME="en_core_common.ff"
SOURCE_BYTES=545024
BASE="https://r2.houseofkublai.com/bo3/DUMP/zone/"
ROOT_KIND=5
MARKER=b"\xff"*8

def valid_mesh(z,p):
    if p<0 or p+0x78>=len(z) or z[p:p+8]!=MARKER:return None
    n=z[p+0x3c]
    ptr=struct.unpack_from("<Q",z,p+0x68)[0]
    if not (1<=n<=128 and tagged(ptr) and ptr!=0):return None
    name=printable(z,p+0x78)
    if not name:return None
    return {"offset":p,"name":name,"surface_count":n,
            "source_surface_pointer":ptr,
            "source_auxiliary_pointer":struct.unpack_from("<Q",z,p+0x70)[0]}

def candidate_mesh_stream_info(z,start,end):
    """Test source-owned 44-byte BO3 mesh stream header, no guessed payload."""
    matches=[]
    for pos in range(start,min(end-44,start+384)):
        flag=z[pos]
        if flag & 0xfc:continue
        verts,weights,faces=struct.unpack_from("<III",z,pos+4)
        pointer=struct.unpack_from("<Q",z,pos+16)[0]
        size,p_off,uv_off,f_off,w_off=struct.unpack_from("<IIIII",z,pos+24)
        if not (0<verts<100_000 and 0<faces<200_000
                and weights<verts*4 and 0<size<=128*1024*1024):
            continue
        if not tagged(pointer):continue
        if p_off+verts*12>size or uv_off+verts*16>size or f_off+faces*6>size:
            continue
        if weights and w_off+weights*12>size:
            continue
        matches.append({
            "original_decoded_offset":pos,"relative_to_name_end":pos-start,
            "status_flag":flag,"vertex_count":verts,"weights_count":weights,
            "face_count":faces,"source_buffer_bytes":size,
            "position_stream_offset":p_off,"uv_stream_offset":uv_off,
            "face_stream_offset":f_off,"weight_stream_offset":w_off,
            "buffer_ptr_kind":"inline" if pointer==0xffffffffffffffff else
                ("resident" if pointer==0xfffffffffffffffe else
                 ("absent" if pointer==0 else "block_ref")),
        })
        if len(matches)>=4:break
    return matches

def survey(z):
    d=parse_directory(bytearray(z))
    if d["status"]!="t7_asset_table_layout_verified":
        raise ValueError("Source zone's complete XAsset table not verified")
    at=d["asset_table"]["table_offset"]
    amount=d["asset_count"]
    table_end=at+16*amount
    rows=[struct.unpack_from("<QQ",z,at+16*i) for i in range(amount)]
    roots=0
    for kind,ptr in rows:
        if kind!=ROOT_KIND or ptr!=0xffffffffffffffff:break
        roots+=1
    if roots<=0:raise ValueError("No initial inline XModelMesh root list")
    candidates=[]
    i=table_end
    while True:
        p=z.find(MARKER,i)
        if p<0:break
        i=p+1
        info=valid_mesh(z,p)
        if info:candidates.append(info)
    first=candidates[0] if candidates else None
    if first is None or first["offset"]!=table_end:
        raise ValueError("First real inline mesh body does not begin at original asset-table end")
    if len(candidates)<roots:
        raise ValueError(f"Found {len(candidates)} mesh headers but need at least {roots} leading inline roots")
    all_header_count=len(candidates)
    candidates=candidates[:roots]
    # Every original mesh name from these source structs must be unique, and
    # bodies remain sequential with a strictly positive bounded read region.
    if len({x["name"] for x in candidates})!=len(candidates):
        raise ValueError("Ambiguous duplicate original modelmesh header names")
    records=[]
    surfaces_total=0
    for k,x in enumerate(candidates):
        next_at=(candidates[k+1]["offset"] if k+1<len(candidates) else len(z))
        size=next_at-x["offset"]
        if size<=0 or size>8*1024*1024:raise ValueError("T7 source mesh region unbounded")
        surfaces_total+=x["surface_count"]
        name_end=x["offset"]+0x78+len(x["name"])+1
        stream_candidates=candidate_mesh_stream_info(z,name_end,next_at)
        records.append({
            "candidate_source_mesh_info":stream_candidates,
            "xasset_row":k,
            "original_decoded_offset":x["offset"],
            "bytes_until_next_header":size if k+1<len(candidates) else None,
            "model_name":x["name"],
            "surface_count":x["surface_count"],
            "surface_source_pointer":f"0x{x['source_surface_pointer']:016x}",
            "auxiliary_source_pointer":f"0x{x['source_auxiliary_pointer']:016x}",
            "residue_read_after_name":next_at-(x["offset"]+0x78+len(x["name"])+1) if k+1<len(candidates) else None,
        })
    return {
        "file":NAME,
        "zone_bytes":len(z),
        "xasset_rows":amount,
        "asset_table_start":at,
        "asset_table_end":table_end,
        "initial_inline_mesh_roots":roots,
        "structurally_valid_mesh_bodies":all_header_count,
        "initial_mesh_bodies_assigned":len(candidates),
        "remaining_mesh_header_candidates_unassigned":all_header_count-len(candidates),
        "first_root_body_exactly_after_table":True,
        "surface_count_total":surfaces_total,
        "leading_meshes_with_plausible_stream_structs":sum(bool(x["candidate_source_mesh_info"]) for x in records),
        "source_order_digest_sha256":hashlib.sha256(
            "\n".join(x["model_name"] for x in records).encode()).hexdigest(),
        "first_15_mesh_placements":records[:15],
        "last_5_mesh_placements":records[-5:],
    }

def main():
    output=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    output.mkdir(parents=True,exist_ok=True)
    with TemporaryDirectory(prefix="t7-first-mesh-") as t:
        p=Path(t)/NAME
        n,digest,_=download(BASE+quote(NAME),p)
        if n!=SOURCE_BYTES:raise ValueError("T7 original en_core_common.ff length changed")
        z,blocks=parse_zlib_zone(p)
        v=survey(z)
        v.update({"sha256_original":digest,"decoded_zlib_blocks":blocks["block_count"]})
        print(json.dumps(v,sort_keys=True),flush=True)
        (output/"bo3_first_owned_mesh_placements.json").write_text(json.dumps(v,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 initial XModelMesh ownership proof failed: {e}",file=sys.stderr)
        raise SystemExit(1)
