"""Stream a real H1 decoded zone and find candidate XAsset array runs.

Works on exact 64KiB-ish LZ4 blocks and keeps only small bounded windows.
All candidate offsets are decoded-zone offsets, never guesses about FF seek
addresses. No original or decompressed asset bytes are uploaded.
"""
import struct
from collections import Counter
MARKER=b"\xff\xff\xff\xff\xff\xfd\xfd\xfd"
VALID_TYPES=71

class AssetRunScanner:
    def __init__(self, minimum_records=8, carry_bytes=4096):
        self.offset=0
        self.carry=b""
        self.carry_bytes=carry_bytes
        self.minimum_records=minimum_records
        self.hits={}
        self.total_candidates=0
        self.type_hist=Counter()

    @staticmethod
    def inspect(blob, start, cap=160):
        if start<0 or start+16>len(blob):
            return None
        types=Counter()
        pointers=Counter()
        max_count=min(cap,(len(blob)-start)//16)
        for n in range(max_count):
            at=start+n*16
            kind,pad,pointer=struct.unpack_from("<IIQ",blob,at)
            if kind>=VALID_TYPES or pad!=0:
                break
            if pointer==0xFDFDFDFFFFFFFFFF:
                tag="inline"
            elif pointer==0:
                tag="null"
            else:
                # No unsupported pointer accepted as proven
                break
            types[kind]+=1
            pointers[tag]+=1
        count=sum(types.values())
        if count<8:
            return None
        return {"consecutive":count,"first_types":dict(types.most_common(12)),
                "pointer_tags":dict(pointers),"verified_byte_span":count*16}

    def push(self, data):
        blob=self.carry+data
        start_offset=self.offset-len(self.carry)
        seek=0
        while True:
            pos=blob.find(MARKER,seek)
            if pos<0: break
            seek=pos+8
            begin=pos-8
            if begin<0:continue
            if begin%8:continue
            if begin+16>len(blob):continue
            kind,pad=struct.unpack_from("<II",blob,begin)
            if kind>=VALID_TYPES or pad!=0:
                continue
            candidate=self.inspect(blob,begin)
            if candidate:
                physical=start_offset+begin
                if physical<0:continue
                self.total_candidates+=1
                # The same run may be sighted at several consecutive
                # records. Save the longest match at each absolute start.
                old=self.hits.get(physical)
                if old is None or candidate["consecutive"]>old["consecutive"]:
                    self.hits[physical]=candidate
        self.offset+=len(data)
        self.carry=blob[-self.carry_bytes:]

    def report(self):
        hits=[{"decoded_offset":at,**item} for at,item in self.hits.items()]
        hits.sort(key=lambda d:(-d["consecutive"],d["decoded_offset"]))
        # Cluster neighboring candidates into distinct regions.
        clusters=[]
        for hit in hits:
            if any(abs(hit["decoded_offset"]-c["decoded_offset"])<=4096 for c in clusters):
                continue
            clusters.append(hit)
            if len(clusters)>=20:break
        return {"decoded_input_bytes_scanned":self.offset,
                "candidate_starts":self.total_candidates,
                "best_disjoint_asset_array_candidates":clusters}
