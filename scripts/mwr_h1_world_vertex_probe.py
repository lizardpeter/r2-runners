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
        self.long_run_break_reasons=[]
    @staticmethod
    def is_vertex(b,at):
        if at<0 or at+STRIDE>len(b):return False
        binormal=struct.unpack_from("<f",b,at+12)[0]
        if not math.isfinite(binormal) or abs(binormal)>1.1:return False
        x,y,z=struct.unpack_from("<fff",b,at)
        if not all(math.isfinite(n) and abs(n)<2_000_000 for n in (x,y,z)):return False
        u,v,lu,lv=struct.unpack_from("<ffff",b,at+20)
        if not all(math.isfinite(n) and abs(n)<100_000 for n in (u,v,lu,lv)):return False
        packed_normal,packed_tangent=struct.unpack_from("<II",b,at+36)
        if packed_normal==0 and packed_tangent==0:
            # All-zero memory is not authenticated world geometry.
            return False
        return True
    def push(self,raw):
        b=self.carry+raw
        base=self.offset-len(self.carry)
        cursor=0
        longest=0
        # Once a preceding decode block revealed a valid 44-byte array
        # phase, continue it over chunk boundaries even when the original
        # binormalSign no longer contains literal +/-1.0.
        for phase in range(STRIDE):
            n=0
            while (phase+(n+1)*STRIDE<=len(b) and
                   self.is_vertex(b,phase+n*STRIDE)):
                n+=1
            if n>=MIN_CANDIDATE_VERTICES:
                at=base+phase
                if at>=0:
                    self.runs.append((at,n))
                    self.signatures_valid+=1
                    longest=max(longest,n)
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
                if sample_count>=32 and len(self.long_run_break_reasons)<24:
                    stop=start+sample_count*STRIDE
                    after=[]
                    for j in range(4):
                        p=stop+j*STRIDE
                        if p+STRIDE>len(b):break
                        xyz=struct.unpack_from("<fff",b,p)
                        sign=struct.unpack_from("<f",b,p+12)[0]
                        uv=struct.unpack_from("<ffff",b,p+20)
                        after.append({
                            "delta_vertices":j,
                            "position":[round(v,6) for v in xyz],
                            "binormal_sign":round(sign,7) if math.isfinite(sign) else None,
                            "uv_lightmap":[round(v,5) for v in uv],
                            "valid_strict":self.is_vertex(b,p),
                        })
                    self.long_run_break_reasons.append({
                        "run_source_offset":base+start,
                        "consecutive_strict_vertices":sample_count,
                        "end_offset":base+stop,
                        "next_four_vertices_at_same_stride":after,
                    })
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
        # A coincident byte interval does NOT prove vertex-array continuity.
        # Alignments with different absolute offsets modulo 44 can overlap
        # extensively, and unconditionally merging them created a false
        # 1.617 million 'vertex' claim. Keep each authenticated 44B phase
        # independent, merging ONLY touching/overlapping runs with exactly
        # the same original file-byte alignment.
        by_phase={}
        for at,count in sorted(set(self.runs)):
            if count<MIN_CANDIDATE_VERTICES:continue
            by_phase.setdefault(at%STRIDE,[]).append((at,at+count*STRIDE))
        merged=[]
        for phase,runs in by_phase.items():
            runs.sort()
            local=[]
            for at,end in runs:
                if local and at<=local[-1]["end_offset"]:
                    local[-1]["end_offset"]=max(local[-1]["end_offset"],end)
                    local[-1]["verified_vertex_records"]=(local[-1]["end_offset"]-
                        local[-1]["start_offset"])//STRIDE
                    local[-1]["confirmed_windows"]+=1
                else:
                    local.append({"start_offset":at,"end_offset":end,
                                  "verified_vertex_records":(end-at)//STRIDE,
                                  "confirmed_windows":1,"source_stride_phase":phase})
            merged.extend(local)
        merged.sort(key=lambda v:v["start_offset"])
        # Legacy name retained for downstream report consumers, but the value
        # now counts ONLY strict same-phase contiguous original 44B records.
        for entry in merged:
            entry["potential_vertices"]=entry["verified_vertex_records"]
        return {
          "source_bytes_scanned":self.offset,
          "GfxWorld_vertex_count_from_authored_header":self.expected_count,
          "binormal_sign_patterns_considered":self.signatures_examined,
          "at_least_16_vertex_runs_found":self.signatures_valid,
          "source_run_clusters":len(merged),
          "longest_clusters":sorted(merged,key=lambda v:-v["potential_vertices"])[:20],
          "longest_single_decode_blocks":self.top_blocks[:16],
          "sampled_strict_vertex_run_boundaries":self.long_run_break_reasons[:20],
          "note":"Only touching or overlapping source ranges in the identical 44-byte phase are merged. These are strict original source vertex candidates, not a full buffer certification."
        }
