"""H1 source-owned ClipMap root from original verified XAssetList order.

When an authentic XAssetList begins with type 24, decode native clipMap_t
0x280 at exactly the end of that source array. Do not use any zone filename,
world name or FF byte offsets. Counts and unresolved pointer kinds are
retained, but no brush/plane array is assigned until nested pointer ownership
and the source serialization order are verified.
"""
import struct

ROOT_BYTES=0x280
INLINE=0xFDFDFDFFFFFFFFFF
SHARED=0xFDFDFDFFFFFFFFFE
FIELDS=(
    ("plane_count",16,4),("planes",24,8),
    ("clip_material_count",32,4),("clip_materials",40,8),
    ("leaf_brush_node_count",48,4),("leaf_brush_nodes",56,8),
    ("leaf_brush_count",64,4),("leaf_brush_indices",72,8),
    ("collision_aabb_count",80,4),("collision_aabbs",88,8),
    ("collision_static_models",96,2),("collision_static_model_nodes",98,2),
    ("collision_static_model_node_ptr",104,8),
    ("brush_side_count",112,4),("brush_sides",120,8),
    ("brush_edge_count",128,4),("brush_edges",136,8),
    ("brush_count",144,4),("brushes",152,8),
    ("brush_bounds",160,8),("brush_contents",168,8),
    ("collision_vertex_count",176,4),("collision_vertices",184,8),
    ("collision_triangle_count",192,4),("collision_triangle_indices",200,8),
    ("collision_tri_walkable",208,8),
    ("collision_border_count",216,4),("collision_borders",224,8),
    ("collision_partition_count",232,4),("collision_partitions",240,8),
    ("collision_static_model_count",248,4),("collision_static_models_ptr",256,8),
    ("p_info",264,8),("node_count",272,4),("nodes",280,8),
    ("leaf_count",288,4),("leafs",296,8),
    ("submodel_count",304,4),("submodels",312,8),
    ("map_entities",320,8),("stages",328,8),
    ("stage_count",336,1),("dyn_ent_anchor_count",464,4),
    ("checksum",576,4),
)
POINTER_FIELDS={name for name,_,size in FIELDS if size==8}
def pointer_kind(raw):
    if raw==0:return "null"
    if raw==INLINE:return "inline_owned"
    if raw==SHARED:return "inline_shared"
    tag=raw>>32
    if 0xFDFDFDF0<=tag<=0xFDFDFDF6:
        return f"source_virtual_block_{tag-0xFDFDFDF0}"
    return "unrecognized_source_value"
def clipmap_fields(blob):
    if len(blob)<ROOT_BYTES:raise ValueError("truncated original 0x280 clipMap_t")
    decoded={}
    pointers={}
    for name,offset,size in FIELDS:
        value=int.from_bytes(blob[offset:offset+size],"little")
        if name in POINTER_FIELDS:
            decoded[name]=f"{value:016x}"
            pointers[name]=pointer_kind(value)
        else:decoded[name]=value
    return decoded,pointers

def inspect_first_authored_clipmap(prefix,verified):
    if verified.get("status")!="fully_verified" or len(verified.get("validated_tables",[]))!=1:
        return {"status":"not_a_unique_original_asset_directory"}
    table=verified["validated_tables"][0]
    if table.get("first_16_asset_types",[])[:1]!=[24]:
        return {"status":"first_original_asset_not_clipmap"}
    at=table["end_offset"]
    if at+ROOT_BYTES>len(prefix):
        return {"status":"source_prefix_truncated_before_clipmap_root",
                "source_root":at}
    blob=prefix[at:at+ROOT_BYTES]
    name_ptr=struct.unpack_from("<Q",blob,0)[0]
    in_use=struct.unpack_from("<I",blob,8)[0]
    fields,pointers=clipmap_fields(blob)
    name=None
    name_end=None
    if name_ptr==INLINE:
        tail=prefix[at+ROOT_BYTES:at+ROOT_BYTES+4097]
        end=tail.find(bytes([0]))
        if 0<end<=4096:
            try:
                name=tail[:end].decode("utf-8")
                if any(ord(c)<32 for c in name):name=None
                else:name_end=at+ROOT_BYTES+end+1
            except UnicodeDecodeError:pass
    count_link=[
        ("plane_count","planes"),("clip_material_count","clip_materials"),
        ("brush_side_count","brush_sides"),("brush_edge_count","brush_edges"),
        ("brush_count","brushes"),("collision_vertex_count","collision_vertices"),
        ("collision_triangle_count","collision_triangle_indices"),
        ("node_count","nodes"),("leaf_count","leafs"),
        ("submodel_count","submodels"),
    ]
    not_supported=[]
    for count,pointer in count_link:
        if fields[count] and pointers[pointer]=="null":
            not_supported.append(f"{count}_nonzero_{pointer}_null")
    if in_use not in (0,1):not_supported.append("is_in_use_outside_native_boolean")
    if name is None:not_supported.append("source_name_not_inline_valid")
    if fields["plane_count"]>10_000_000: not_supported.append("unbounded_plane_count")
    return {
        "status":"authored_type24_source_root_structural" if not not_supported
                 else "authored_type24_header_requires_more_relocation_research",
        "original_source_offset":at,
        "original_fixed_header_bytes":ROOT_BYTES,
        "original_source_name_pointer":f"{name_ptr:016x}",
        "original_source_name":name,
        "name_source_end":name_end,
        "is_in_use":in_use,
        "typed_native_fields":fields,
        "pointer_classifications":pointers,
        "unresolved_conditions":not_supported,
        "nested_collision_arrays_admitted":False,
        "NOTE":"ClipInfo fields are recovered from original type24 ownership, not guessed scan hits. Raw pointer labels are not decoded file seeks."
    }
