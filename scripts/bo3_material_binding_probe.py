#!/usr/bin/env python3
"""Recover original T7 material texture slot ownership from retail PC zone.

Material names/typed headers are source-proven, but the engine advances
several logical stream cursors after material header. This diagnostic records
possible *complete* 0x20-byte MaterialImage arrays, exact semantic IDs and
source image pointer tags near each original material, then tests per-material
cardinality and layout. It does not claim ownership from mere proximity.
"""
from __future__ import annotations
import os,sys,struct,json,hashlib
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import parse_zlib_zone,parse_directory
from bo3_struct_probe import survey as source_headers
BASE="https://r2.houseofkublai.com/bo3/DUMP/zone/"
SIZES={"en_core_common.ff":545024,"core_gfx.ff":6790208}
SEMANTICS={0xA0AB1041:"diffuse",0x59D30D0F:"normal",0xEC443804:"specular"}
def tag(p):return p in (0,0xffffffffffffffff,0xfffffffffffffffe) or (p>>56) in (0x50,0x60)
def examine(zone,mat,end):
    count=mat["tex_count"]
    name=mat["name"]
    start=mat["source_offset"]+0x2a0+len(name)+1
    before=min(len(zone),max(start,end),start+4096)
    hits=[]
    for p in range(start,before-12):
        word=struct.unpack_from("<I",zone,p+8)[0]
        if word in SEMANTICS:
            ptr=struct.unpack_from("<Q",zone,p)[0]
            if tag(ptr):
                hits.append({"source_offset":p,"after_name":p-start,
                             "image_ref":f"0x{ptr:016x}",
                             "semantic":SEMANTICS[word],
                             "semantic_hash":f"0x{word:08x}",
                             "first_32_bytes_sha256":hashlib.sha256(zone[p:p+32]).hexdigest()})
    arrays=[]
    for sample in hits:
        base=sample["source_offset"]
        for skip in range(count):
            start_candidate=base-skip*32
            if start_candidate<start or start_candidate+count*32>len(zone):continue
            slots=[]
            seen=True
            for i in range(count):
                at=start_candidate+i*32
                ptr=struct.unpack_from("<Q",zone,at)[0]
                semantic=struct.unpack_from("<I",zone,at+8)[0]
                if not tag(ptr) or ptr==0 or semantic==0:
                    seen=False
                    break
                slots.append({"src":at,"source_pointer":f"0x{ptr:016x}",
                              "semantic":SEMANTICS.get(semantic,"other"),
                              "raw_semantic_hash":f"0x{semantic:08x}"})
            if seen and start_candidate not in [v["begin"] for v in arrays]:
                arrays.append({"begin":start_candidate,"after_name":start_candidate-start,
                               "slots":slots})
    return {"name":name,"name_end":start,"reported_slots":count,
            "original_source_header_offset":mat["source_offset"],
            "candidate_semantic_records":len(hits),
            "near_semantics":hits[:12],
            "complete_consecutive_slot_arrays":arrays[:8],
            "all_arrays_count":len(arrays),
            "candidate_array_offsets":[x["begin"] for x in arrays],
            "scan_end":before}
def analyze(zone):
    headers=source_headers(zone,"in_memory")["authored_struct_candidates"]["material"]
    mats=headers["preview"] # need all: iterate original names/headers with independently known fields
    # Scan actual source material headers using same strict field/pointer grammar.
    found=[]
    pos=0
    while True:
        at=zone.find(b"\xff"*8,pos)
        if at<0:break
        pos=at+1
        if at+0x2a1>=len(zone):continue
        name_end=zone.find(b"\0",at+0x2a0,min(len(zone),at+0x2a0+161))
        if name_end<at+0x2a3:continue
        name_bytes=zone[at+0x2a0:name_end]
        if any(x<32 or x>126 for x in name_bytes):continue
        name=name_bytes.decode("ascii")
        ct=zone[at+0x270]
        if not 0<ct<=48:continue
        pointers=struct.unpack_from("<QQ",zone,at+0x278)
        if not all(tag(x) for x in pointers) or pointers[1]==0:continue
        found.append({"name":name,"source_offset":at,"tex_count":ct,
                      "texture_ptr":f"0x{pointers[1]:016x}"})
    results=[]
    for index,mat in enumerate(found):
        next_start=found[index+1]["source_offset"] if index+1<len(found) else len(zone)
        results.append(examine(zone,mat,next_start))
    return {"candidate_materials_with_texture_slots":len(found),
            "semantic_observations":sum(x["candidate_semantic_records"] for x in results),
            "complete_original_slot_arrays":sum(x["all_arrays_count"] for x in results),
            "material_source_records":results[:80]}

def main():
    preset=os.environ.get("BO3_MATERIAL_PRESET","en_core_common.ff")
    if preset not in SIZES:raise ValueError("Unknown BO3 material source")
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    with TemporaryDirectory(prefix="original-t7-mat-") as tmp:
        p=Path(tmp)/preset
        count,digest,_=download(BASE+quote(preset),p)
        if count!=SIZES[preset]:raise ValueError("BO3 R2 source changed")
        zone,blocks=parse_zlib_zone(p)
        records=analyze(zone)
        records.update({"source_zone":preset,"original_source_sha256":digest,
                        "decoded_bytes":len(zone),"original_zlib_blocks":blocks["block_count"]})
        print(json.dumps(records,sort_keys=True),flush=True)
        (root/"bo3_authentic_material_texture_ownership.json").write_text(json.dumps(records,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 material ownership diagnostic failed: {e}",file=sys.stderr)
        sys.exit(1)
