"""Name-anchored native H1 ClipMap root candidates in real decoded FastFiles.

No map-specific offsets or hardcoded fixture names. Require a real native
0x280 clipMap_t body, an inline source name immediately after it, and
multiple independent original ClipInfo count/pointer cross-checks. This is
research evidence, NOT proof of type-24 XAsset ownership or brush relocation.
"""
import struct
from collections import Counter
from mwr_h1_clipmap_source import (
    clipmap_fields,ROOT_BYTES,INLINE,pointer_kind
)
MAX_NAME_BYTES=256
CARRY=ROOT_BYTES+MAX_NAME_BYTES+64
MAGIC=struct.pack("<Q",INLINE)

def classify_clipmap_root_at(decoded,at):
    if at<0 or at+ROOT_BYTES+8>len(decoded):return None
    if struct.unpack_from("<Q",decoded,at)[0]!=INLINE:return None
    in_use=struct.unpack_from("<I",decoded,at+8)[0]
    if in_use not in (0,1):return None
    b=decoded[at:at+ROOT_BYTES]
    values,ptrs=clipmap_fields(b)
    typed=(
        ("plane_count","planes",10000000),
        ("clip_material_count","clip_materials",1000000),
        ("brush_count","brushes",2000000),
        ("node_count","nodes",2000000),
        ("leaf_count","leafs",2000000),
        ("submodel_count","submodels",100000),
        ("brush_side_count","brush_sides",10000000),
        ("collision_vertex_count","collision_vertices",10000000),
    )
    for count,ptr,cap in typed:
        n=values[count]
        if n>cap:return None
        if n and ptrs[ptr] in ("null","unrecognized_source_value"):
            return None
    important=("plane_count","clip_material_count","brush_count",
               "node_count","leaf_count","submodel_count")
    if any(values[k]==0 for k in important):return None
    if values["stage_count"]>128:return None
    name_offset=at+ROOT_BYTES
    tail=decoded[name_offset:name_offset+MAX_NAME_BYTES+1]
    n=tail.find(b"\0")
    if not 3<=n<=MAX_NAME_BYTES:return None
    text=tail[:n]
    if not all(32<=v<127 for v in text):return None
    source_name=text.decode("ascii")
    # Native H1 collision world names may use a map path, but a file
    # extension alone cannot authenticate XAsset ownership.
    return {
        "original_inline_name_candidate":source_name,
        "native_root_bytes":ROOT_BYTES,
        "source_name_relative_offset":ROOT_BYTES,
        "clipmap_name_extension_looks_like_map":source_name.endswith(".d3dbsp"),
        "source_counts":{k:values[k] for k in (
            "plane_count","clip_material_count","brush_count",
            "brush_side_count","brush_edge_count","collision_vertex_count",
            "collision_triangle_count","node_count","leaf_count",
            "submodel_count","stage_count")},
        "source_ptr_categories":{k:ptrs[k] for k in (
            "planes","clip_materials","brushes","brush_sides",
            "nodes","leafs","submodels","p_info","map_entities")},
    }

class H1NamedClipMapScanner:
    def __init__(self):
        self.decoded_at=0
        self.carry=b""
        self.hits={}
    def push(self,chunk):
        combined=self.carry+chunk
        origin=self.decoded_at-len(self.carry)
        cursor=0
        while True:
            at=combined.find(MAGIC,cursor)
            if at<0:break
            cursor=at+1
            if at+ROOT_BYTES+MAX_NAME_BYTES+1>len(combined):continue
            source_at=origin+at
            if source_at<0:continue
            evidence=classify_clipmap_root_at(combined,at)
            if evidence is not None:self.hits[source_at]=evidence
        self.decoded_at+=len(chunk)
        self.carry=combined[-CARRY:]
    def report(self):
        return {
            "status":"original_named_clipmap_structural_root_candidates_not_XAsset_relocated",
            "original_decoded_bytes_scanned":self.decoded_at,
            "candidate_count":len(self.hits),
            "first_20":[{"original_source_offset":offset,**value}
                       for offset,value in sorted(self.hits.items())[:20]],
            "no_collision_arrays_accepted":True,
        }
