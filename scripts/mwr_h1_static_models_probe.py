"""Source-count-anchored scanner for ORIGINAL H1 static-model draw instances.

The array consists of 80-byte GfxStaticModelDrawInst structs. The source
GfxWorld root supplies the expected count; no map/file offsets or invented
model meshes are used. A full candidate is only source-layout evidence
until XModel pointer aliases and LOD meshes have been independently resolved.
"""
import math
import struct

STRIDE=80
ANCHOR=8
MAX_CARRY=4*1024*1024
PTR_HIGH=b"\xf3\xfd\xfd\xfd"

def plausible_draw_record(blob,at):
    if at<0 or at+STRIDE>len(blob):
        return False
    if blob[at+60:at+64]!=PTR_HIGH:
        return False
    xyz=struct.unpack_from("<13f",blob,at)
    origin=xyz[:3]
    axes=[xyz[3:6],xyz[6:9],xyz[9:12]]
    scale=xyz[12]
    if any(not math.isfinite(v) or abs(v)>2_000_000 for v in origin):
        return False
    if not math.isfinite(scale) or not (0.001<=abs(scale)<=1000):
        return False
    if any(not math.isfinite(v) or abs(v)>2.0 for row in axes for v in row):
        return False
    if any(not (0.25<=sum(v*v for v in row)<=4.0) for row in axes):
        return False
    return True

class H1StaticModelDrawScanner:
    def __init__(self):
        self.decoded=0
        self.carry=b""
        self.expected_count=None
        self.full_matches={}
        self.largest_provisional=None

    def bind_root(self,root):
        n=root["static_model_count"]
        if not isinstance(n,int) or n<1 or n>2_000_000:
            raise ValueError("invalid authored H1 GfxWorld static model count")
        if self.expected_count is not None and self.expected_count!=n:
            raise ValueError("ambiguous H1 world static model counts")
        self.expected_count=n

    def push(self,chunk):
        data=self.carry+chunk
        base=self.decoded-len(self.carry)
        target=self.expected_count
        if target is None:
            # Before the real GfxWorld supplies its authored count there is
            # nothing we can validate. Do not rescan multi-MiB history.
            self.decoded+=len(chunk)
            self.carry=b""
            return
        if len(data)>=ANCHOR*STRIDE:
            pos=0
            while True:
                hi=data.find(PTR_HIGH,pos)
                if hi<0:
                    break
                start=hi-60
                if start>=0 and all(plausible_draw_record(data,start+i*STRIDE)
                                    for i in range(ANCHOR)):
                    first=start
                    while first>=STRIDE and plausible_draw_record(data,first-STRIDE):
                        first-=STRIDE
                    end=start+ANCHOR*STRIDE
                    while end+STRIDE<=len(data) and plausible_draw_record(data,end):
                        end+=STRIDE
                    count=(end-first)//STRIDE
                    absolute=base+first
                    if count==target and absolute>=0:
                        self.full_matches[absolute]={
                            "start":absolute,"end":base+end,"records":count,
                            "source_model_references_only":True
                        }
                    if self.largest_provisional is None or count>self.largest_provisional["records"]:
                        self.largest_provisional={"start":absolute,"end":base+end,"records":count}
                    pos=max(hi+1,end)
                else:
                    pos=hi+1
        self.decoded+=len(chunk)
        # Retain only enough overlap to contain one *whole authored array*
        # crossing arbitrary H1 LZ4 block boundaries. No retail count baked in.
        carry_size=min(MAX_CARRY,max(target*STRIDE+STRIDE*2,ANCHOR*STRIDE))
        self.carry=data[-carry_size:]

    def report(self):
        matches=sorted(self.full_matches.values(),key=lambda x:x["start"])
        return {
            "status":("unique_complete_original_static_model_draw_span"
                      if len(matches)==1 else
                      "ambiguous_complete_original_static_model_draw_spans"
                      if len(matches)>1 else
                      "no_complete_original_static_model_draw_span"),
            "expected_count_from_gfxworld":self.expected_count,
            "candidate_matches":matches[:8],
            "largest_provisional_run":self.largest_provisional,
            "decoded_bytes_scanned":self.decoded,
            "no_meshes_or_materials_inferred":True,
        }
