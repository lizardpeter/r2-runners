"""Independently certify the original H1 GfxSurface 40-byte array.

All 40-byte records must pass original world vertex and index range checks.
A complete array must contain exactly GfxWorld.surfaceCount records in the
same source byte phase. This is not yet proof of where index bytes live.
"""
import hashlib
import struct
from collections import Counter
from mwr_h1_world_vertex_verify import extract_source_window
from mwr_h1_surface_probe import plausible_surface, STRIDE

def inspect_source_material_tag_blocks(material_refs,block_bytes):
    """Bound-check tagged ORIGINAL source references; no alias relocation."""
    if block_bytes is None or len(block_bytes)!=7:
        return {"status":"no_source_memory_block_lengths"}
    per_block={}
    invalid=[]
    special=Counter()
    for ptr,ref_count in material_refs.items():
        if ptr in (0,0xFDFDFDFFFFFFFFFF,0xFDFDFDFFFFFFFFFE):
            special["null" if ptr==0 else "inline_marker"]+=ref_count
            continue
        hi=ptr>>32
        if not 0xFDFDFDF0<=hi<0xFDFDFDF7:
            special["unknown_tag"]+=ref_count
            if len(invalid)<12:invalid.append(f"{ptr:016x}")
            continue
        block=hi-0xFDFDFDF0
        offset=ptr&0xffffffff
        length=block_bytes[block]
        use=per_block.setdefault(block,{"reference_count":0,
            "distinct_tags":0,"minimum_offset":offset,"maximum_offset":offset,
            "declared_block_bytes":length})
        use["reference_count"]+=ref_count
        use["distinct_tags"]+=1
        use["minimum_offset"]=min(use["minimum_offset"],offset)
        use["maximum_offset"]=max(use["maximum_offset"],offset)
        if offset>=length:
            special["offset_outside_declared_block"]+=ref_count
            if len(invalid)<12:invalid.append(f"{ptr:016x}")
    return {"status":"all_source_material_refs_fit_blocks"
                if not invalid else "unresolved_source_reference_bounds",
            "source_virtual_block_candidates":per_block,
            "other_source_refs":dict(special),
            "bounded_invalid_tag_samples":invalid,
            "CAUTION":"Block bounds are not a decompressed source seek/asset alias resolution."}


def verify_source_surface_array(ff_path,ff_header,stream_class,report,world,block_bytes=None):
    candidates=report.get("largest_source_surface_runs",[])
    target=int(world["surface_count"])
    if not candidates or candidates[0]["source_surface_records"]<target*0.9:
        return {"status":"no_near_complete_original_surface_array"}
    seed=candidates[0]
    begin=max(0,seed["start"]-256*1024)
    end=min(report["decoded_bytes_scanned"],seed["end"]+256*1024)
    data=extract_source_window(ff_path,ff_header,stream_class,begin,end)
    phase=(seed["start"]-begin)%STRIDE
    active=None
    spans=[]
    for at in range(phase,len(data)-STRIDE+1,STRIDE):
        valid=plausible_surface(data,at,world["vertex_count"],world["index_count"])
        if valid and active is None:active=at
        if not valid and active is not None:
            spans.append((active,at))
            active=None
    if active is not None:
        last=phase+((len(data)-STRIDE-phase)//STRIDE+1)*STRIDE
        spans.append((active,last))
    spans.sort(key=lambda a:a[1]-a[0],reverse=True)
    report_spans=[{"offset":begin+a,"end":begin+b,
                   "records":(b-a)//STRIDE} for a,b in spans[:12]]
    found=next((t for t in report_spans if t["records"]>=target),None)
    if not found:
        return {"status":"near_complete_surface_boundaries_unresolved",
                "world_header_surface_count":target,
                "largest_qualified_runs":report_spans}
    source_start=found["offset"]
    array=data[source_start-begin:source_start-begin+target*STRIDE]
    if len(array)!=target*STRIDE:
        raise ValueError("authenticated H1 GfxSurface span is truncated")
    if not all(plausible_surface(array,i*STRIDE,
           world["vertex_count"],world["index_count"]) for i in range(target)):
        raise ValueError("H1 source surface verifier disagrees on original record bounds")
    total_indices=0
    max_index=0
    max_vertex=0
    tri_counts=[]
    source_samples=[]
    material_refs=Counter()
    material_triangles=Counter()
    tag_prefixes=Counter()
    for i in range(target):
        at=i*STRIDE
        first=struct.unpack_from("<I",array,at+4)[0]
        vcount,tri=struct.unpack_from("<HH",array,at+16)
        base=struct.unpack_from("<I",array,at+20)[0]
        end_index=base+tri*3
        max_index=max(max_index,end_index)
        max_vertex=max(max_vertex,first+vcount)
        total_indices+=tri*3
        tri_counts.append(tri)
        material_ref=struct.unpack_from("<Q",array,at+24)[0]
        material_refs[material_ref]+=1
        material_triangles[material_ref]+=tri
        tag_prefixes[material_ref>>32]+=1
        if i in (0,1,2,target//4,target//2,(3*target)//4,target-3,target-2,target-1):
            source_samples.append({
                "source_surface_record":i,"original_first_vertex":first,
                "source_vertex_count":vcount,"triangle_count":tri,
                "source_base_index":base,
                "source_material_tag":f"{struct.unpack_from('<Q',array,at+24)[0]:016x}",
            })
    return {
        "status":"complete_original_surface_struct_array_verified",
        "complete_source_surface_start":source_start,
        "complete_source_surface_end":source_start+target*STRIDE,
        "source_stride":STRIDE,
        "original_surfaces_verified":target,
        "source_array_sha256":hashlib.sha256(array).hexdigest(),
        "total_surface_triangle_indices":total_indices,
        "header_world_index_count":world["index_count"],
        "surface_index_count_matches_world_indices":total_indices==world["index_count"],
        "max_surface_index_end":max_index,
        "max_surface_vertex_end":max_vertex,
        "authored_world_vertex_count":world["vertex_count"],
        "triangle_counts_min":min(tri_counts),
        "triangle_counts_max":max(tri_counts),
        "source_samples":source_samples,
        "material_tag_block_bounds":inspect_source_material_tag_blocks(
            material_refs,block_bytes),
        "material_source_reference_census":{
            "source_surface_material_tags_distinct":len(material_refs),
            "source_surface_null_material_ref_count":material_refs.get(0,0),
            "source_material_pointer_prefix_histogram":{
                f"{prefix:08x}":count for prefix,count in tag_prefixes.most_common()
            },
            "top_surface_material_refs":[
                {"source_pointer_tag":f"{ptr:016x}",
                 "authored_surface_count":count,
                 "authored_triangle_count":material_triangles[ptr]}
                for ptr,count in material_refs.most_common(24)
            ],
            "NOTE":"Tagged pointers are original source references, not resolved material names or textures."
        },
        "note":"Actual source index-buffer byte address still needs independent cross-reference."
    }
