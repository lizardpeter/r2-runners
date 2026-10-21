#!/usr/bin/env python3
"""Cross-link original T7 XModel LOD stream keys to the authentic base.xpak.

Runs on the isolated R2 GitHub runner. Reads original FF bytes locally and
the complete real 116,837-key KAPI index via exact range requests. Does not
download base.xpak or publish source asset payloads.
"""
from __future__ import annotations
from collections import Counter
import hashlib,json,math,os,struct,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import parse_zlib_zone
from bo3_base_index import read_base_index
BASE="https://r2.houseofkublai.com/bo3/DUMP/zone/"
FILES={"en_core_common.ff":545024,"core_specialists.ff":51386816}
def source_pointer(v:int)->bool:
    return v in (0,0xffffffffffffffff,0xfffffffffffffffe) or (v>>56) in (0x50,0x60)
def survey(zone:bytes,keys:set[int],max_matches:int=200_000):
    matches=[]
    valid=[]
    seen=set()
    count=Counter()
    views=memoryview(zone)
    # 8 residue classes cover every possible *unaligned* packed struct field.
    for lane in range(8):
        size=(len(zone)-lane)//8
        words=views[lane:lane+size*8].cast("Q")
        for idx,value in enumerate(words):
            if value not in keys:
                continue
            at=lane+idx*8
            if at in seen:continue
            seen.add(at)
            count["original_xpak_hash_matches"]+=1
            if at<0x48 or at+0x30>len(zone):continue
            lod=at-0x48
            n=zone[lod+0x3c]
            if not(0<n<=128):continue
            dist_min,dist_max=struct.unpack_from("<ff",zone,lod+0x40)
            if not(math.isfinite(dist_min) and math.isfinite(dist_max)
                   and 0<=dist_min<=1000000 and 0<=dist_max<=1000000):continue
            surfaceptr,meshptr=struct.unpack_from("<QQ",zone,lod+0x68)
            if not(source_pointer(surfaceptr) and source_pointer(meshptr)):
                continue
            count["verified_lod_layout"]+=1
            valid.append({
                "xpak_stream_hash":f"0x{value:016x}",
                "source_lod_offset":lod,
                "source_mip_hash_position":at,
                "surfaces":n,
                "lod_min_distance":dist_min,"lod_distance":dist_max,
                "source_surface_pointer":f"0x{surfaceptr:016x}",
                "source_mesh_pointer":f"0x{meshptr:016x}",
            })
            if len(valid)>=max_matches:break
        if len(valid)>=max_matches:break
    return {"total_hash_matches":count["original_xpak_hash_matches"],
            "lod_struct_candidates":len(valid),
            "sample_lod_source_records":valid[:25],
            "unique_lod_stream_keys":len({x["xpak_stream_hash"] for x in valid}),
            "source_key_digest_sha256":hashlib.sha256(
                "\n".join(sorted(x["xpak_stream_hash"] for x in valid)).encode()
            ).hexdigest()}
def main():
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    info,index=read_base_index()
    reports=[]
    with TemporaryDirectory(prefix="t7-model-hash-") as temp:
        for name,size in FILES.items():
            file=Path(temp)/name
            got,digest,_=download(BASE+quote(name),file)
            if got!=size:raise ValueError("BO3 source FF length changed")
            zone,blocks=parse_zlib_zone(file)
            print(f"Scanning original T7 zone {name}, {len(zone)} decoded bytes",flush=True)
            result=survey(zone,set(index))
            result.update({"file":name,"source_sha256":digest,
                           "source_decoded_bytes":len(zone),
                           "source_blocks":blocks["block_count"],
                           "base_index_sha256":info["hash_index_sha256"]})
            reports.append(result)
            print(json.dumps(result,sort_keys=True),flush=True)
    (root/"bo3_real_model_lod_stream_keys.json").write_text(
        json.dumps(reports,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 model LOD original key survey failed: {e}",file=sys.stderr)
        sys.exit(1)
