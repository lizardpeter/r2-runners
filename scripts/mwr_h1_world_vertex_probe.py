"""Find original H1 44-byte GfxWorldVertex array runs from retail zone bytes.

No synthetic mesh output, no extracted binary. Exact source-structure tests:
12-byte XYZ f32, 4-byte authored binormal sign, 4-byte RGBA, 2x UV,
2x lightmap UV, u32 packed normal and tangent. Non-finite/oversized
coordinates and unexpected binormal signs are rejected. Candidate runs
remain hypotheses until crosschecked against GfxWorld.vertexCount.
"""
import math
import struct

STRIDE=44
SIGN_BYTES={b"\0\0\x80\x3f",b"\0\0\x80\xbf"}
MIN_CANDIDATE_VERTICES=16
MAX_CARRY=STRIDE*(MIN_CANDIDATE_VERTICES+3)
class WorldVertexRunScanner:
    def __init__(self,expected_count=None):
        self.expected_count=expected_count
        self.offset=0
        self.carry=b""
        self.runs=[]
        self.signatures_examined=0
        self.signatures_valid=0
        self.top_blocks=[]
        self.run_histo={}
    @staticmethod
    def is_vertex(b,at):
        if at<0 or at+STRIDE>len(b):return False
        if b[at+12:at+16] not in SIGN_BYTES:return False
        x,y,z=struct.unpack_from("<fff",b,at)
        if not all(math.isfinite(n) and abs(n)<2_000_000 for n in (x,y,z)):return False
        u,v,lu,lv=struct.unpack_from("<ffff",b,at+20)
        if not all(math.isfinite(n) and abs(n)<100_000 for n in (u,v,lu,lv)):return False
        return True
    def push(self,raw):
        b=self.carry+raw
        base=self.offset-len(self.carry)
        cursor=0
        longest=0
        while cursor+STRIDE*MIN_CANDIDATE_VERTICES<=len(b):
            plus=b.find(b"\0\0\x80\x3f",cursor+12)
            minus=b.find(b"\0\0\x80\xbf",cursor+12)
            hits=[n for n in (plus,minus) if n>=0]
            if not hits:break
            p=min(hits)
            start=p-12
            self.signatures_examined+=1
            if not self.is_vertex(b,start):
                cursor=p+4
                continue
            sample_count=0
            while start+(sample_count+1)*STRIDE<=len(b) and self.is_vertex(
                   b,start+sample_count*STRIDE):
                sample_count+=1
            longest=max(longest,sample_count)
            if sample_count>=MIN_CANDIDATE_VERTICES:
                self.signatures_valid+=1
                absolute=base+start
                if absolute>=0:
                    self.runs.append((absolute,sample_count))
                cursor=start+max(1,sample_count)*STRIDE
            else:
                cursor=p+4
        self.offset+=len(raw)
        self.carry=b[-MAX_CARRY:]
        if longest>=MIN_CANDIDATE_VERTICES:
            self.top_blocks.append((self.offset-len(raw),longest))
            self.top_blocks=sorted(self.top_blocks,key=lambda t:-t[1])[:32]
    def report(self):
        runs=sorted(set(self.runs))
        merged=[]
        for at,count in runs:
            end=at+count*STRIDE
            if merged and at<=merged[-1]["end_offset"]:
                previous=merged[-1]
                previous["end_offset"]=max(previous["end_offset"],end)
                previous["potential_vertices"]=max(previous["potential_vertices"],
                    (previous["end_offset"]-previous["start_offset"])//STRIDE)
                previous["confirmed_windows"]+=1
            else:
                merged.append({"start_offset":at,"end_offset":end,
                               "potential_vertices":count,"confirmed_windows":1})
        return {
          "source_bytes_scanned":self.offset,
          "GfxWorld_vertex_count_from_authored_header":self.expected_count,
          "binormal_sign_patterns_considered":self.signatures_examined,
          "at_least_16_vertex_runs_found":self.signatures_valid,
          "source_run_clusters":len(merged),
          "longest_clusters":sorted(merged,key=lambda v:-v["potential_vertices"])[:20],
          "longest_single_decode_blocks":self.top_blocks[:16],
          "note":"Candidates are exact-stride source checks, not vertex/index offset certification."
        }
