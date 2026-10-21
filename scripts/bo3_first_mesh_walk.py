#!/usr/bin/env python3
"""Prove sequential first-owned XModelMesh body locations in BO3 retail FF.

Only recover source offsets, sizes and structural field metadata. No meshes,
script strings, or retail binary payloads leave the runner. First root body
must start EXACTLY at the end of the validated original XAsset directory.
"""
from __future__ import annotations
import hashlib,json,math,os,struct,sys
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
        if flag & 0xe0:continue
        verts,weights,faces=struct.unpack_from("<III",z,pos+4)
        pointer=struct.unpack_from("<Q",z,pos+16)[0]
        size,p_off,uv_off,f_off,w_off=struct.unpack_from("<IIIII",z,pos+24)
        if not (0<verts<100_000 and 0<faces<200_000
                and weights<verts*4 and 0<size<=128*1024*1024):
            continue
        if not tagged(pointer):continue
        # Retail BO3 MeshInfo.FaceCount is a count of 16-bit indices.
        # Individual XSurface.FacesCount is a triangle count.
        if faces%3!=0 or p_off+verts*12>size or uv_off+verts*16>size or f_off+faces*2>size:
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

def find_original_surface_records(z,begin,end,expected_count,mesh_vertices,mesh_indices):
    """Require actual T7 XSurface 0x60-byte vertices, triangle and index bounds."""
    matches=[]
    if expected_count>128:return matches
    for offset in range(begin,max(begin,end-0x60+1)):
        vc,tri=struct.unpack_from("<HH",z,offset+4)
        vb,ib=struct.unpack_from("<II",z,offset+8)
        if not (0<vc<=mesh_vertices and 0<tri and
                vb+vc<=mesh_vertices and ib+tri*3<=mesh_indices):
            continue
        matches.append({"original_offset":offset,"source_vertices":vc,
                        "authored_triangles":tri,"vertex_base":vb,"index_base":ib,
                        "weight_flags":list(z[offset:offset+4])})
        if len(matches)>=8:break
    return matches

def nearby_mesh_info_fields(z,name_end,interval_end):
    out=[]
    for step in (0,1,2,3,4,5,6,7,8,12,16,24,32,48,64,80):
        p=name_end+step
        if p+44>interval_end:continue
        verts,weights,faces=struct.unpack_from("<III",z,p+4)
        ptr=struct.unpack_from("<Q",z,p+16)[0]
        fields=struct.unpack_from("<IIIII",z,p+24)
        out.append({
            "distance_after_name":step,
            "flag":z[p],
            "vertex_count":verts,"weight_count":weights,
            "triangle_count":faces,
            "buffer_ptr_tag":f"0x{ptr:016x}",
            "buffer_size":fields[0],"data_offsets":list(fields[1:]),
        })
    return out

def decode_authentic_rigid_geometry(zone,source_info,surface):
    """Decode *actual retail* T7 float3 / f16 UV / u16 triangles in memory."""
    buffer_start=source_info.get("original_inline_buffer_offset")
    if buffer_start is None:return {"status":"inline_buffer_unresolved"}
    data=memoryview(zone)[buffer_start:source_info["original_inline_buffer_end"]]
    vc,face_count=surface["source_vertices"],surface["authored_triangles"]
    vertex_base,index_base=surface["vertex_base"],surface["index_base"]
    mesh_verts=source_info["vertex_count"]
    mesh_indices=source_info["face_count"]
    if vertex_base+vc>mesh_verts or index_base+3*face_count>mesh_indices:
        return {"status":"source_ranges_outside_mesh"}
    p_off=source_info["position_stream_offset"]+vertex_base*12
    a_off=source_info["uv_stream_offset"]+vertex_base*16
    i_off=source_info["face_stream_offset"]+index_base*2
    if (p_off+vc*12>len(data) or a_off+vc*16>len(data) or
            i_off+face_count*6>len(data)):
        return {"status":"source_byte_ranges_exceeded"}
    positions=[]
    uvs=[]
    for n in range(vc):
        p=struct.unpack_from("<fff",data,p_off+12*n)
        uv=struct.unpack_from("<ee",data,a_off+16*n+4)
        if any(not math.isfinite(x) for x in p+uv):
            return {"status":"nonfinite_original_position_or_uv"}
        if any(abs(x)>1000000 for x in p):
            return {"status":"original_position_unreasonably_large"}
        positions.append(p)
        uvs.append(uv)
    indices=struct.unpack_from("<"+str(face_count*3)+"H",data,i_off)
    if any(i>=vc for i in indices):
        return {"status":"retail_index_references_nonlocal_vertex",
                "bad_indices":sum(i>=vc for i in indices)}
    nondegenerate=0
    for i in range(face_count):
        a,b,c=(positions[k] for k in indices[i*3:i*3+3])
        ab=[b[j]-a[j] for j in range(3)]
        ac=[c[j]-a[j] for j in range(3)]
        n=[ab[1]*ac[2]-ab[2]*ac[1],ab[2]*ac[0]-ab[0]*ac[2],
           ab[0]*ac[1]-ab[1]*ac[0]]
        if sum(q*q for q in n)>1e-12:nondegenerate+=1
    return {
        "status":"original_rigid_surface_decoded",
        "vertices":vc,
        "authored_triangles":face_count,
        "valid_indices":len(indices),
        "nondegenerate_triangles":nondegenerate,
        "source_position_min":[min(p[j] for p in positions) for j in range(3)],
        "source_position_max":[max(p[j] for p in positions) for j in range(3)],
        "source_uv_min":[min(p[j] for p in uvs) for j in range(2)],
        "source_uv_max":[max(p[j] for p in uvs) for j in range(2)],
        "unique_vertex_colors":len({bytes(data[a_off+16*n:a_off+16*n+4]) for n in range(vc)}),
        "vertex_position_bytes_sha256":hashlib.sha256(
            bytes(data[p_off:p_off+vc*12])
        ).hexdigest(),
        "triangle_index_bytes_sha256":hashlib.sha256(
            bytes(data[i_off:i_off+face_count*6])
        ).hexdigest(),
    }

def exact_original_surface_array(zone,start,end,count,mesh_info):
    """Read source-authored 0x60 XSurface list contiguously only when all
    records and their index/vertex extents pass strong bounds checks."""
    if not (1<count<=128) or start+count*0x60>end:return None
    all_surfaces=[]
    for i in range(count):
        at=start+i*0x60
        vc,tri=struct.unpack_from("<HH",zone,at+4)
        vb,ib=struct.unpack_from("<II",zone,at+8)
        if not(0<vc<=mesh_info["vertex_count"] and
               0<tri<=65535 and
               vb+vc<=mesh_info["vertex_count"] and
               ib+3*tri<=mesh_info["face_count"]):
            return None
        surf={"original_offset":at,"source_vertices":vc,"authored_triangles":tri,
              "vertex_base":vb,"index_base":ib,"weight_flags":list(zone[at:at+4])}
        decoded=decode_authentic_rigid_geometry(zone,mesh_info,surf)
        if decoded.get("status")!="original_rigid_surface_decoded":return None
        surf["real_geometry"]=decoded
        all_surfaces.append(surf)
    return {
        "status":"original_multisurface_array_decoded",
        "authored_surfaces":count,
        "real_vertices":sum(x["real_geometry"]["vertices"] for x in all_surfaces),
        "real_triangles":sum(x["real_geometry"]["authored_triangles"] for x in all_surfaces),
        "source_surface_locations":[x["original_offset"] for x in all_surfaces],
    }

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
        for info in stream_candidates:
            inline_begin=info["original_decoded_offset"]+0x50
            inline_end=inline_begin+info["source_buffer_bytes"]
            if (info["buffer_ptr_kind"]=="inline" and
                inline_end <= next_at):
                info["original_inline_buffer_offset"]=inline_begin
                info["original_inline_buffer_end"]=inline_end
                info["buffer_sha256"]=hashlib.sha256(z[inline_begin:inline_end]).hexdigest()
                info["surface_records_after_buffer"]=find_original_surface_records(
                    z,inline_end,min(next_at,inline_end+768),
                    x["surface_count"],info["vertex_count"],info["face_count"]
                )
                # Admission requires a source XSurface at the exact buffer
                # boundary, not an approximate hit hundreds of bytes later.
                exact=[surf for surf in info["surface_records_after_buffer"]
                       if surf["original_offset"]==inline_end]
                if x["surface_count"]==1 and len(exact)==1:
                    info["decoded_retail_surface"]=decode_authentic_rigid_geometry(
                        z,info,exact[0]
                    )
                elif x["surface_count"]>1:
                    multi=exact_original_surface_array(
                        z,inline_end,next_at,x["surface_count"],info
                    )
                    if multi is not None:
                        info["decoded_retail_surface_array"]=multi
        records.append({
            "candidate_source_mesh_info":stream_candidates,
            "early_mesh_info_field_probes":nearby_mesh_info_fields(z,name_end,next_at) if k<4 else [],
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
        "leading_meshes_with_bounded_inline_mesh_buffers":sum(any("original_inline_buffer_offset" in c for c in x["candidate_source_mesh_info"]) for x in records),
        "verified_actual_retail_surface_decodes":sum(c.get("decoded_retail_surface",{}).get("status")=="original_rigid_surface_decoded" for x in records for c in x["candidate_source_mesh_info"]),
        "verified_actual_retail_vertices":sum(c.get("decoded_retail_surface",{}).get("vertices",0) for x in records for c in x["candidate_source_mesh_info"]),
        "verified_actual_retail_triangles":sum(c.get("decoded_retail_surface",{}).get("authored_triangles",0) for x in records for c in x["candidate_source_mesh_info"]),
        "verified_original_multisurface_arrays":sum(c.get("decoded_retail_surface_array",{}).get("status")=="original_multisurface_array_decoded" for x in records for c in x["candidate_source_mesh_info"]),
        "verified_original_multi_triangles":sum(c.get("decoded_retail_surface_array",{}).get("real_triangles",0) for x in records for c in x["candidate_source_mesh_info"]),
        "stream_header_status_flags":dict(Counter(c["status_flag"] for x in records for c in x["candidate_source_mesh_info"])),

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
