"""Find source-authentic H1 GfxWorld from geometry field relationships.

Unlike naive pointer-pair matching, anchor on H1 GfxWorldDraw's vertex and
index buffer refs at source-root offsets 312 and 376. Validate correlated
vertex/index/surface counts, DPVS counts and source pointer tag patterns.

Research only: a match remains a candidate until its original source
asset loader returns the corresponding type-31 record.
"""
from collections import Counter
import struct

TAG=0xFDFDFDFFFFFFFFFF
NEED=0xB30
VERTEX_PTR=176+136
INDEX_PTR=176+200
WORLD_SURFACE_PTR=1864+664

def ptr(b,at):
    return struct.unpack_from("<Q",b,at)[0]
def u32(b,at):
    return struct.unpack_from("<I",b,at)[0]
def valid_ptr(v):
    return v in (0,TAG) or v>>48==0xFDFD

class GfxWorldGeometryScanner:
    def __init__(self):
        self.offset=0
        self.carry=b""
        self.hits={}
        self.marker_hits=0
        self.count_check=Counter()
    def push(self,chunk):
        b=self.carry+chunk
        base=self.offset-len(self.carry)
        tag=struct.pack("<Q",TAG)
        cursor=0
        while True:
            pos=b.find(tag,cursor)
            if pos<0:break
            cursor=pos+8
            self.marker_hits+=1
            start=pos-VERTEX_PTR
            if start<0 or start+NEED>len(b):continue
            surface=u32(b,start+28)
            vertex=u32(b,start+176+128)
            index=u32(b,start+176+192)
            model=u32(b,start+1864)
            static=u32(b,start+1864+8)
            sky=u32(b,start+32)
            if not(100<=surface<=1_000_000 and
                   100<=vertex<=5_000_000 and
                   100<=index<=20_000_000 and
                   static<=surface and model<=2_000_000 and sky<200):
                continue
            self.count_check["counts_plausible"]+=1
            index_ptr=ptr(b,start+INDEX_PTR)
            world_name=ptr(b,start)
            base_name=ptr(b,start+8)
            surface_ptr=ptr(b,start+WORLD_SURFACE_PTR)
            if not all(map(valid_ptr,(index_ptr,world_name,base_name,surface_ptr))):
                self.count_check["rejected_ptrs"]+=1
                continue
            self.count_check["pointer_tags_valid"]+=1
            if vertex<surface or index<surface:
                self.count_check["rejected_less_than_surfaces"]+=1
                continue
            bsp=u32(b,start+16)
            plane=u32(b,start+20)
            node=u32(b,start+24)
            self.hits[base+start]={
                "decoded_source_root_offset":base+start,
                "bsp_version":bsp,"plane_count":plane,"node_count":node,
                "surface_count":surface,"vertex_count":vertex,"index_count":index,
                "static_surface_count":static,"static_model_count":model,
                "sky_count":sky,
                "name_ptr":f"{world_name:016x}",
                "basename_ptr":f"{base_name:016x}",
                "vertex_ptr":f"{TAG:016x}",
                "index_ptr":f"{index_ptr:016x}",
                "surface_ptr":f"{surface_ptr:016x}"
            }
        self.offset+=len(chunk)
        self.carry=b[-(NEED+512):]
    def report(self):
        return {"decompressed_bytes_scanned":self.offset,
                "candidate_ref_markers_seen":self.marker_hits,
                "plausibility_checks":dict(self.count_check),
                "unique_typed_world_root_candidates":len(self.hits),
                "candidates":list(self.hits.values())[:24]}
