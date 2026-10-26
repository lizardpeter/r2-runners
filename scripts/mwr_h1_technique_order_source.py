"""First original type-15 MaterialTechniqueSet from signed H1 asset order.

No signature scans, map offsets or technique-name guesses. Require a uniquely
verified full XAsset directory with type 15 at ordinal zero; inspect exactly
the 0x790-byte H1 set root, its 240 original source-pointer slots, and
source-inline name. Never jump across unproven MaterialTechnique pass arrays.
"""
import struct
from collections import Counter
from mwr_h1_clipmap_source import pointer_kind
ROOT_BYTES=0x790
TECHNIQUE_COUNT=240
INLINE=0xFDFDFDFFFFFFFFFF

def inspect_first_authored_technique_set(prefix,verified):
    if verified.get("status")!="fully_verified" or len(verified.get("validated_tables",[]))!=1:
        return {"status":"no_unique_source_authored_asset_directory"}
    table=verified["validated_tables"][0]
    if table.get("first_16_asset_types",[])[:1]!=[15]:
        return {"status":"first_authored_asset_not_technique_set"}
    at=table["end_offset"]
    if at+ROOT_BYTES>len(prefix):
        return {"status":"source_technique_set_root_truncated","original_root_offset":at}
    fixed=prefix[at:at+ROOT_BYTES]
    name_ptr=struct.unpack_from("<Q",fixed,0)[0]
    flags,vertex_format,pre_displacement=struct.unpack_from("<HBB",fixed,8)
    slots=struct.unpack_from("<240Q",fixed,16)
    classifications=Counter(pointer_kind(s) for s in slots)
    unusual=[{"slot":i,"pointer":f"{p:016x}"}
             for i,p in enumerate(slots)
             if pointer_kind(p)=="unrecognized_source_value"][:8]
    active=[(i,s) for i,s in enumerate(slots) if s]
    name=None
    name_end=None
    if name_ptr==INLINE:
        tail=prefix[at+ROOT_BYTES:at+ROOT_BYTES+4097]
        end=tail.find(bytes([0]))
        if 0<end<=4096:
            try:
                maybe=tail[:end].decode("utf-8")
                if all(ord(c)>=32 for c in maybe):
                    name=maybe
                    name_end=at+ROOT_BYTES+end+1
            except UnicodeDecodeError:
                pass
    return {
        "status":"source_owned_first_type15_fixed_header_and_name_verified"
            if name is not None and not unusual and active
            else "source_owned_first_type15_header_needs_nested_loader_research",
        "original_root_offset":at,
        "native_root_bytes":ROOT_BYTES,
        "name_pointer":f"{name_ptr:016x}",
        "source_name":name,
        "source_name_end":name_end,
        "flags":flags,
        "original_world_vertex_format":vertex_format,
        "original_pre_displacement_only_count":pre_displacement,
        "original_240_slot_tag_categories":dict(classifications),
        "original_populated_technique_slots":len(active),
        "first_12_original_active_slots":[{"slot":i,"source_ptr":f"{p:016x}"}
                                          for i,p in active[:12]],
        "first_invalid_source_refs":unusual,
        "material_pass_arrays_not_yet_source_relocated":True,
    }
