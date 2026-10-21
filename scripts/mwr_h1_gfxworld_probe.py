"""Read-only, bounded GfxWorld root research from real H1 decompressed data.

H1 runtime's GfxWorld root has name/baseName pointers at 0/8,
bspVersion at 16, plane/node/surface counts at 20/24/28 and skyCount at
32. This scanner tests exact bytes across block boundaries and never
creates geometry, assigns guessed dimensions, or chooses a map-specific
offset in the importer. Results are candidate metadata only until their
source owner is established by asset order and nested references.
"""
import struct
from collections import Counter

INLINE = 0xFDFDFDFFFFFFFFFF
ROOT_SPAN=256
NEED=ROOT_SPAN
class GfxWorldCandidateScanner:
    def __init__(self, expected_stem=None):
        self.seen=0
        self.carry=b""
        self.expected_stem=expected_stem
        self.root_candidates=[]
        self.path_matches=[]
        self.version_hist=Counter()
        self.total_pair_hits=0

    def push(self,data):
        base=self.seen-len(self.carry)
        b=self.carry+data
        marker=struct.pack("<Q",INLINE)
        pos=0
        while True:
            k=b.find(marker,pos)
            if k<0:break
            pos=k+8
            if k+NEED>len(b):continue
            second=struct.unpack_from("<Q",b,k+8)[0]
            if second not in (0,INLINE):continue
            self.total_pair_hits+=1
            version,plane,node,surface,sky=struct.unpack_from("<IIIII",b,k+16)
            if not (1<=version<=4096 and 0<=plane<=20_000_000 and
                    0<=node<=20_000_000 and 0<surface<=10_000_000
                    and 0<=sky<=32):continue
            if plane==0 and node==0:continue
            skies=struct.unpack_from("<Q",b,k+40)[0]
            if skies not in (0,INLINE):continue
            portal_groups=struct.unpack_from("<I",b,k+48)[0]
            if portal_groups>100_000:continue
            self.root_candidates.append({
                "decoded_offset":base+k,
                "bsp_version":version,"plane_count":plane,
                "node_count":node,"surface_count":surface,
                "sky_count":sky,"sky_pointer":f"{skies:016x}",
                "portal_group_count":portal_groups,
                "first_96_hex":b[k:k+96].hex(" ")
            })
            self.version_hist[version]+=1
        # The string search looks for H1 .d3dbsp source names without
        # choosing a world candidate based on an unverified neighbor.
        needle=b".d3dbsp"
        pos=0
        while True:
            k=b.find(needle,pos)
            if k<0:break
            pos=k+len(needle)
            before=b[max(0,k-72):k]
            start=max(before.rfind(b"\0"),before.rfind(b"\xff"))+1
            prefix=before[start:]
            printable=all(32<=c<=126 for c in prefix)
            if printable and len(prefix)<72:
                string=prefix+needle
                expected=(self.expected_stem or "").encode()
                self.path_matches.append({
                    "decoded_end_offset":base+k+len(needle),
                    "source_name":string.decode("ascii","replace")[:130],
                    "map_stem_matches":bool(expected and expected in string)
                })
        self.seen+=len(data)
        self.carry=b[-8192:]
    def report(self):
        dedup={}
        for c in self.root_candidates:dedup[c["decoded_offset"]]=c
        paths={p["decoded_end_offset"]:p for p in self.path_matches}
        candidates=list(dedup.values())
        candidates.sort(key=lambda x:x["decoded_offset"])
        return {
            "source_decoded_bytes_scanned":self.seen,
            "pointer_pair_candidates":self.total_pair_hits,
            "plausible_gfxworld_root_count":len(candidates),
            "candidate_roots":candidates[:48],
            "bsp_version_histogram":dict(self.version_hist.most_common(24)),
            "d3dbsp_filename_occurrences":len(paths),
            "source_paths":list(paths.values())[:48]
        }
