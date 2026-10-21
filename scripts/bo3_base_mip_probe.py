#!/usr/bin/env python3
"""Verify exact BO3 base.xpak streamed image bytes against real FastFile mips.

Uses complete original core_frontend_patch.ff and the full authenticated
base.xpak hash index. Fetches selected exact original packed spans over R2,
decodes them transiently in RAM and checks the source GfxImage mip sizes.
"""
from __future__ import annotations
import hashlib,io,json,os,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_base_index import KEY,EXPECTED_BYTES,range_read,read_base_index
from bo3_zone_decode import parse_zlib_zone
from bo3_images_probe import scan_images
from bo3_xpak_decode import probe_entry,MAX_ENTRY_SOURCE,MAX_ENTRY_DECODED

ZONE="core_frontend_patch.ff"
ZONE_BYTES=72319872
URL="https://r2.houseofkublai.com/bo3/DUMP/zone/"+ZONE

def main():
    out=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));out.mkdir(parents=True,exist_ok=True)
    base_meta,base_entries=read_base_index()
    with TemporaryDirectory(prefix="t7-image-base-") as temp:
        target=Path(temp)/ZONE
        n,digest,_=download(URL,target)
        if n!=ZONE_BYTES:raise ValueError("Original FastFile length changed")
        decoded,blocks=parse_zlib_zone(target)
        listing=scan_images(decoded,set(base_entries))
        stream=listing.get("all_name_hashes",[])
        candidates=[]
        for item in stream:
            if item["kind"]!="xpak":continue
            key=int(item["source_key"],16)
            if key not in base_entries:continue
            start,size=base_entries[key]
            if size>MAX_ENTRY_SOURCE or item["source_bytes"]>MAX_ENTRY_DECODED:continue
            candidates.append((item,key,start,size))
        candidates.sort(key=lambda t:(t[0]["source_bytes"],t[3]))
        results=[]
        max_samples=20
        for item,key,offset,size in candidates[:max_samples]:
            original=range_read(KEY,base_meta["data_offset"]+offset,size,EXPECTED_BYTES)
            result=probe_entry(io.BytesIO(original),{"data_start":0},
                               {"relative_offset":0,"packed_bytes":size})
            results.append({
                "name":item["name"],"format":item["format"],
                "mip_width":item["width"],"mip_height":item["height"],
                "original_mip_hash":f"0x{key:016x}",
                "packed_source_bytes":size,
                "declared_mip_bytes":item["source_bytes"],
                "stream_decoder_state":result["state"],
                "decoded_bytes":result.get("decoded_bytes"),
                "source_length_matches":result.get("decoded_bytes")==item["source_bytes"]
                                        if result["state"]=="decoded" else False,
                "unresolved_codec":result.get("codec"),
                "payload_sha256":result.get("decoded_sha256"),
            })
        report={
            "source_zone":ZONE,"source_sha256":digest,
            "base_source_index_sha256":base_meta["hash_index_sha256"],
            "base_indexed_hash_keys":base_meta["hash_count"],
            "source_images_total":listing["confirmed_image_descriptions"],
            "source_streamed_images":listing["source_kinds"].get("xpak",0),
            "candidates_within_test_budget":len(candidates),
            "sampled":len(results),
            "matched_complete_mip_payloads":sum(x["source_length_matches"] for x in results),
            "results":results,
        }
        print(json.dumps(report,sort_keys=True),flush=True)
        (out/"bo3_real_base_mip_payloads.json").write_text(
            json.dumps(report,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 original base mip probe failed: {e}",file=sys.stderr)
        sys.exit(1)
