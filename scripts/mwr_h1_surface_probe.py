"""Original H1 GfxSurface 40-byte record stream research.

Checks source fields from the H1 runtime layout against the exact authored
world vertex/index counts. Source byte patterns may be reported as candidates;
only a complete 39,695-style surface count with source range validation can
certify the array. No procedurally generated triangles are emitted.
"""
import math
import struct

STRIDE=40
ANCHOR=12
CARRY=STRIDE*80
MAX_VERTICES=5_000_000
MAX_INDICES=20_000_000

def plausible_surface(b,at,vertices,indices):
    if at<0 or at+40>len(b):return False
    vstart=struct.unpack_from("<I",b,at+4)[0]
    edge=struct.unpack_from("<f",b,at+8)[0]
    vcount,tricount=struct.unpack_from("<HH",b,at+16)
    base=struct.unpack_from("<I",b,at+20)[0]
    material=struct.unpack_from("<Q",b,at+24)[0]
    if vcount==0 or tricount==0 or vstart+vcount>vertices:
        return False
    if base+tricount*3>indices:
        return False
    if not math.isfinite(edge) or edge<0 or edge>=1_000_000:
        return False
    if material!=0 and material>>48!=0xFDFD:
        return False
    return True

class H1SurfaceSourceScanner:
    def __init__(self):
        self.vertices=MAX_VERTICES
        self.indices=MAX_INDICES
        self.expected_surface_count=None
        self.seen=0
        self.carry=b""
        self.runs=[]
        self.source_chunks=0

    def bind_root(self,world):
        self.vertices=world["vertex_count"]
        self.indices=world["index_count"]
        self.expected_surface_count=world["surface_count"]

    def push(self,raw):
        b=self.carry+raw
        base=self.seen-len(self.carry)
        for phase in range(STRIDE):
            if phase+ANCHOR*STRIDE>len(b):break
            if not all(plausible_surface(b,phase+i*STRIDE,
                        self.vertices,self.indices) for i in range(ANCHOR)):
                continue
            count=ANCHOR
            while (phase+(count+1)*STRIDE<=len(b) and
                   plausible_surface(b,phase+count*STRIDE,
                                    self.vertices,self.indices)):
                count+=1
            if base+phase>=0:
                self.runs.append((base+phase,count))
        self.seen+=len(raw)
        self.source_chunks+=1
        self.carry=b[-CARRY:]

    def report(self):
        by_phase={}
        for at,n in sorted(set(self.runs)):
            by_phase.setdefault(at%STRIDE,[]).append((at,at+n*STRIDE))
        clusters=[]
        for phase,entries in by_phase.items():
            current=[]
            for at,end in entries:
                if current and at<=current[-1][1]:
                    current[-1][1]=max(current[-1][1],end)
                else:
                    current.append([at,end])
            for at,end in current:
                clusters.append({"start":at,"end":end,
                    "source_surface_records":(end-at)//STRIDE,
                    "source_stride_phase":phase})
        clusters.sort(key=lambda x:-x["source_surface_records"])
        return {
            "status":"source_candidate_scan",
            "decoded_bytes_scanned":self.seen,
            "authored_surface_count":self.expected_surface_count,
            "candidate_surface_clusters":len(clusters),
            "largest_source_surface_runs":clusters[:24],
            "note":"Full source surface/index correlation is required before declaring a rendered map."
        }
