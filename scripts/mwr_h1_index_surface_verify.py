"""Certify H1 world indices using source-array serialization and ALL surfaces.

Correct byte start is not chosen by a score: the H1 GfxWorldDraw source
serializes vertexLayerData immediately after 44-byte vertices, followed by
u16 indices. A +6-byte (one triangle) shift passes many topology tests but
cannot be the authored original start. Enforce the exact source-order
adjacency, complete 3,542,247 index count and every GfxSurface local range.
"""
import hashlib
import struct
from mwr_h1_world_vertex_verify import extract_source_window

def validate_full_indices(data,at,surfaces,expected_index_count):
    """Read all original u16 triangle references with no guessed vertex IDs."""
    if at<0 or at+expected_index_count*2>len(data):
        return {"status":"truncated_source_index_bytes"}
    if not surfaces or surfaces[0][0]!=0:
        return {"status":"original_surface_base_indices_do_not_begin_at_zero"}
    total=0
    maximal_end=0
    degenerate=0
    local_max=0
    for ordinal,(base,n,vertex_count) in enumerate(surfaces):
        if n<3 or n%3 or vertex_count<3:
            return {"status":"invalid_source_surface_tri_count","surface":ordinal}
        end=base+n
        if end>expected_index_count:
            return {"status":"source_surface_index_range_outside_buffer",
                    "surface":ordinal}
        maximal_end=max(maximal_end,end)
        words=struct.unpack_from("<"+str(n)+"H",data,at+base*2)
        if any(i>=vertex_count for i in words):
            return {"status":"invalid_source_local_vertex_index",
                    "surface":ordinal}
        local_max=max(local_max,max(words))
        for i in range(0,n,3):
            a,b,c=words[i:i+3]
            if a==b or b==c or c==a:degenerate+=1
        total+=n
    if maximal_end!=expected_index_count or total!=expected_index_count:
        return {"status":"surface_index_count_mismatch",
                "declared":expected_index_count,"covered":total,"max_end":maximal_end}
    triangle_count=total//3
    if degenerate>max(1,triangle_count//200):
        return {"status":"source_triangle_topology_inconsistent",
                "degenerate":degenerate,"triangles":triangle_count}
    return {
        "status":"complete_original_index_array_verified",
        "authored_u16_indices_verified":expected_index_count,
        "total_triangles_checked":triangle_count,
        "nondegenerate_triangles":triangle_count-degenerate,
        "maximum_local_index":local_max,
        "nondegenerate_fraction":round(1.-degenerate/triangle_count,9),
    }

def verify_original_index_bytes(ff_file,ff_header,stream_class,world,verts,surfs):
    if verts.get("status")!="complete" or surfs.get("status")!="complete_original_surface_struct_array_verified":
        return {"status":"missing_full_verified_source_geometry"}
    vertex_end=verts["complete_source_array_end"]
    layer_bytes=world.get("vertex_layer_bytes")
    if not isinstance(layer_bytes,int) or layer_bytes<0:
        return {"status":"unresolved_original_vertex_layer_size"}
    first=vertex_end+layer_bytes
    index_count=world["index_count"]
    end=first+index_count*2
    surface_start=surfs["complete_source_surface_start"]
    surface_end=surfs["complete_source_surface_end"]
    if not(vertex_end<=first<end<=surface_start<surface_end):
        return {"status":"invalid_original_H1_draw_source_order"}
    if surface_end-vertex_end>128*1024*1024:
        return {"status":"H1_source_validation_window_exceeds_cap"}
    data=extract_source_window(ff_file,ff_header,stream_class,vertex_end,surface_end)
    offset=surface_start-vertex_end
    original_surfaces=[]
    for i in range(world["surface_count"]):
        row=offset+i*40
        vertex_count,triangles=struct.unpack_from("<HH",data,row+16)
        base=struct.unpack_from("<I",data,row+20)[0]
        original_surfaces.append((base,triangles*3,vertex_count))
    index_start=first-vertex_end
    result=validate_full_indices(data,index_start,original_surfaces,index_count)
    if result["status"]!="complete_original_index_array_verified":
        return {**result,"expected_serialized_index_source_start":first}
    blob=data[index_start:index_start+index_count*2]
    return {
        **result,
        "decoded_index_start":first,
        "decoded_index_end":end,
        "source_index_sha256":hashlib.sha256(blob).hexdigest(),
        "source_boundary_is_exact_vertex_end_plus_declared_layer":True,
        "original_vertex_array_end":vertex_end,
        "original_vertex_layer_data_bytes":layer_bytes,
        "source_surface_array_begin":surface_start,
        "source_surface_count_checked":len(original_surfaces),
        "source_map_independent":True,
    }
