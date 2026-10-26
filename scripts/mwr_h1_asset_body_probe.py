"""Find H1 asset body *candidates* in actual decompressed original bytes.

This is structural evidence, NOT XAsset ownership or virtual-block pointer
relocation. Exact H1 runtime offsets are checked, source offsets are reported,
and the scanner keeps only metadata, never proprietary asset payloads.
"""
import math
import struct
from collections import Counter

INLINE=struct.pack("<Q",0xFDFDFDFFFFFFFFFF)
CARRY=1024
SIZES={"material":0x250,"image":0x68,"xmodel":0x2a8,"clipmap":0x280}

def uint(data,at):return struct.unpack_from("<I",data,at)[0]
def u64(data,at):return struct.unpack_from("<Q",data,at)[0]
def fp(data,at):return struct.unpack_from("<f",data,at)[0]
def tag(p):return p in (0,0xFDFDFDFFFFFFFFFF) or p>>48==0xFDFD

def material(b,at):
    if at<0 or at+0x250>len(b):return None
    if u64(b,at)!=0xFDFDFDFFFFFFFFFF:return None
    tc,cc,st,flags,region,mt,lc=b[at+288:at+295]
    if not (1<=tc<=48 and cc<=96 and st<=240 and region<=16 and mt<=96 and lc<=16):
        return None
    ptrs=[u64(b,at+i) for i in (296,304,312,320,568,584)]
    if not all(tag(p) for p in ptrs) or ptrs[0]==0 or ptrs[1]==0:return None
    if cc>0 and ptrs[2]==0 or st>0 and ptrs[3]==0:return None
    # Do not require a particular technique pointer block. This is a
    # candidate until linked against the asset-owned table and string.
    return {"texture_slots":tc,"constants":cc,"states":st,
            "material_type":mt,"technique_ptr":f"{ptrs[0]:016x}",
            "texture_table_ptr":f"{ptrs[1]:016x}"}

def image(b,at):
    if at<0 or at+0x68>len(b):return None
    if u64(b,at+96)!=0xFDFDFDFFFFFFFFFF:return None
    fmt=uint(b,at+24)
    map_type,semantic,cat,flags=b[at+28:at+32]
    width,height,depth,elems=struct.unpack_from("<4H",b,at+44)
    mips,streamed=b[at+52:at+54]
    if not (1<=fmt<=200 and 2<=map_type<=6 and 1<=width<=16384 and 1<=height<=16384
            and 1<=elems<=2048 and 1<=mips<=20 and streamed in (0,1)):
        return None
    pixel=u64(b,at+56)
    if not tag(pixel):return None
    return {"dxgi_format":fmt,"width":width,"height":height,
            "mips":mips,"streamed":streamed,"semantic":semantic,
            "pixel_ptr":f"{pixel:016x}"}

def xmodel(b,at):
    if at<0 or at+0x2a8>len(b):return None
    if u64(b,at)!=0xFDFDFDFFFFFFFFFF:return None
    bones,root,surfaces=b[at+8:at+11]
    scale=fp(b,at+16)
    lods=b[at+512]
    mats=u64(b,at+120)
    if not (0<=root<=bones<=255 and 1<=surfaces<=255 and 1<=lods<=6
            and math.isfinite(scale) and 0.0001<=scale<=10_000
            and tag(mats) and mats!=0):
        return None
    first_lod=u64(b,at+136)
    if not tag(first_lod):return None
    return {"bones":bones,"surfaces":surfaces,"lod_count":lods,
            "scale":scale,"material_handles_ptr":f"{mats:016x}",
            "lod0_model_surfs_ptr":f"{first_lod:016x}"}

def clipmap(b,at):
    if at<0 or at+0x280>len(b):return None
    if u64(b,at)!=0xFDFDFDFFFFFFFFFF:return None
    planes,nodes,leafs,models=(uint(b,at+i) for i in (16,272,288,304))
    mats=uint(b,at+32)
    brush=uint(b,at+16+96+32)
    if not (1<=planes<=5_000_000 and 1<=nodes<=5_000_000
            and 1<=leafs<=5_000_000 and 1<=models<=100_000
            and 1<=mats<=200_000 and 1<=brush<=2_000_000):
        return None
    pointers=[u64(b,at+i) for i in (24,40,280,296,312,16+96+40)]
    if any(not tag(p) or p==0 for p in pointers):return None
    return {"planes":planes,"materials":mats,"nodes":nodes,"leafs":leafs,
            "submodels":models,"brushes":brush,
            "plane_ptr":f"{pointers[0]:016x}",
            "brush_ptr":f"{pointers[-1]:016x}"}

class H1TypedBodyScanner:
    def __init__(self):
        self.offset=0
        self.carry=b""
        self.matches={kind:{} for kind in SIZES}
        self.candidate_counters=Counter()
    def push(self,chunk):
        blob=self.carry+chunk
        base=self.offset-len(self.carry)
        start=0
        while True:
            where=blob.find(INLINE,start)
            if where<0:break
            start=where+1
            # Source name pointers are at start for three types; image name
            # is at +96 of a native 0x68-byte GfxImage struct.
            for kind,at,validator in (
                ("material",where,material),
                ("xmodel",where,xmodel),
                ("clipmap",where,clipmap),
                ("image",where-96,image),
            ):
                if at<0 or base+at<0:continue
                if at+SIZES[kind]>len(blob):continue
                evidence=validator(blob,at)
                if evidence is None:continue
                absolute=base+at
                self.matches[kind][absolute]=evidence
        self.offset+=len(chunk)
        self.carry=blob[-CARRY:]
    def report(self):
        return {"status":"typed_source_layout_candidates_only_not_relocated",
                "decoded_bytes_scanned":self.offset,
                "candidates":{kind:{"count":len(hits),
                    "first_30":[{"decoded_source_offset":at,**details}
                               for at,details in sorted(hits.items())[:30]]}
                              for kind,hits in self.matches.items()},
                "WARNING":"Matches are structural candidates; H1 XAsset identity, "
                   "pointer alias relocation and source shader/texture bindings remain unproven."}
