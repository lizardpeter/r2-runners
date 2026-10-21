#!/usr/bin/env python3
"""Validate BO3 original XModel fields against real T7 source before binding materials.

The independently recovered BO3XModel struct has 0x188 bytes:
- number of LODs at +0x40
- LOD pointers (eight 64-bit fields) at +0x88
- per-LOD material-handle owner ptr at +0xc8
- late aux fields at +0x110 do NOT automatically identify a mesh.
Prior possible XModel->mesh links from +0x110 must be reclassified as
candidates until backed by source LOD structures.
"""
from __future__ import annotations
import json,os,struct,sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import parse_zlib_zone,parse_directory
from bo3_struct_probe import printable,tagged
BASE="https://r2.houseofkublai.com/bo3/DUMP/zone/"
NAMES={"en_core_common.ff":545024,"core_specialists.ff":51386816}
def inspect(zone):
    models=[]
    start=0
    while True:
        p=zone.find(b"\xff"*8,start)
        if p<0:break
        start=p+1
        if p+0x189>=len(zone):continue
        name=printable(zone,p+0x188)
        if not name:continue
        nb=zone[p+8]
        lod_count=zone[p+0x40]
        lodrefs=[struct.unpack_from("<Q",zone,p+0x88+i*8)[0] for i in range(8)]
        materials_ptr=struct.unpack_from("<Q",zone,p+0xc8)[0]
        aux_110=struct.unpack_from("<Q",zone,p+0x110)[0]
        if not(0<lod_count<=8 and nb<=80 and tagged(materials_ptr)):
            continue
        if not all(tagged(q) for q in lodrefs[:lod_count]):continue
        if any(x not in (0,0xffffffffffffffff,0xfffffffffffffffe)
               and (x>>56) not in (0x50,0x60) for x in lodrefs[lod_count:]):
            continue
        models.append({
            "model":name,"source_header":p,"num_bones":nb,"num_lods":lod_count,
            "original_lod_pointers":[f"0x{x:016x}" for x in lodrefs[:lod_count]],
            "material_handle_source_pointer":f"0x{materials_ptr:016x}",
            "auxiliary_word_at_0x110":f"0x{aux_110:016x}",
        })
    return models
def main():
    mode=os.environ.get("BO3_XMODEL_PRESET","en_core_common.ff")
    if mode not in NAMES:raise ValueError("Unknown BO3 original zone selection")
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    with TemporaryDirectory(prefix="bo3-original-lod-") as t:
        path=Path(t)/mode
        n,sha,_=download(BASE+quote(mode),path)
        if n!=NAMES[mode]:raise ValueError(f"Original R2 source changed ({n})")
        zone,block=parse_zlib_zone(path)
        directory=parse_directory(bytearray(zone))
        declared=directory["asset_table"]["type_counts"].get("4:xmodel")
        models=inspect(zone)
        out={
            "source_file":mode,"source_sha256":sha,"decoded_bytes":len(zone),
            "original_declared_xmodel_count":declared,
            "original_full_xmodel_header_candidates":len(models),
            "num_lods_histogram":dict(Counter(m["num_lods"] for m in models)),
            "candidate_headers":models[:40],
        }
        print(json.dumps(out,sort_keys=True),flush=True)
        (root/"bo3_actual_model_lod_material_offsets.json").write_text(
            json.dumps(out,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"T7 source XModel field validation failed: {e}",file=sys.stderr)
        sys.exit(1)
