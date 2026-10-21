#!/usr/bin/env python3
"""Prove T7 material image source ownership from actual loader ordering.

Start from 12 unique original MaterialImage tables, compare their inline
GfxImage pointer counts to complete structurally confirmed GfxImage headers
before the next source-owned material. Only exact cardinality and ordered
source proofs become an edge; ambiguous cases remain explicitly unresolved.
Source asset bytes never published.
"""
from __future__ import annotations
import os,sys,json,hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from r2_download import download
from bo3_base_index import read_base_index
from bo3_images_probe import scan_images
from bo3_material_binding_probe import analyze,SIZES,BASE
from bo3_zone_decode import parse_zlib_zone

NAME="en_core_common.ff"
def source_links(zone,hashes):
    mats=analyze(zone)["material_source_records"]
    images=scan_images(zone,hashes).get("all_name_hashes",[])
    images.sort(key=lambda x:x["source_offset"])
    linked=[]
    unmatched=[]
    for i,mat in enumerate(mats):
        if mat["all_arrays_count"]!=1:
            unmatched.append({"material":mat["name"],"error":"no_unique_original_material_array"})
            continue
        data=mat["complete_consecutive_slot_arrays"][0]
        upper=mats[i+1]["original_source_header_offset"] if i+1<len(mats) else len(zone)
        end=data["begin"]+mat["reported_slots"]*32
        original_inlines=[(j,x) for j,x in enumerate(data["slots"]) if x["source_pointer"]=="0xffffffffffffffff"]
        within=[x for x in images if end<=x["source_offset"]<upper]
        row={"material":mat["name"],"source_material_header":mat["original_source_header_offset"],
             "source_image_table":data["begin"],"texture_slots":mat["reported_slots"],
             "inline_source_image_slots":len(original_inlines),
             "structural_original_images_before_next_material":len(within),
             "source_images":[{"source_image_offset":x["source_offset"],"name":x["name"],
                               "pixel_storage":x["kind"],"format":x["format"],
                               "width":x["width"],"height":x["height"],
                               "stream_hash":x["source_key"]} for x in within[:32]]}
        if len(within)==len(original_inlines):
            row["status"]="ordered_inline_image_ownership_cardinality_verified"
            row["ordered_material_edges"]=[
                {"material_slot":slot,"source_hash":data["slots"][slot]["raw_semantic_hash"],
                 "source_image_offset":img["source_offset"],"image_name":img["name"]}
                for (slot,_),img in zip(original_inlines,within)
            ]
            linked.append(row)
        else:
            row["status"]="source_cardinality_unresolved_no_edges_claimed"
            unmatched.append(row)
    return {
        "material_binding_tables":len(mats),
        "source_gfximage_descriptions":len(images),
        "unique_ordered_image_owner_materials":len(linked),
        "unresolved_material_owners":len(unmatched),
        "total_unique_material_slot_to_image_edges":sum(len(x["ordered_material_edges"]) for x in linked),
        "linked_materials":linked,"unresolved":unmatched,
    }

def main():
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    index_info,keys=read_base_index()
    with TemporaryDirectory(prefix="bo3-material-image-link-") as tmp:
        path=Path(tmp)/NAME
        got,digest,_=download(BASE+NAME,path)
        if got!=SIZES[NAME]:raise ValueError("BO3 source FF length changed")
        data,blocks=parse_zlib_zone(path)
        result=source_links(data,set(keys))
        result.update({"source_file":NAME,"source_sha256":digest,
                       "base_xpak_index_sha256":index_info["hash_index_sha256"]})
        print(json.dumps(result,sort_keys=True),flush=True)
        (root/"bo3_material_to_original_image_links.json").write_text(
            json.dumps(result,indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 original material-to-image source link proof failed: {e}",file=sys.stderr)
        raise SystemExit(1)
