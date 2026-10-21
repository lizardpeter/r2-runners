#!/usr/bin/env python3
"""Locate real T7 XModelLod 0x78-byte source records by validated parent models.

A model's true LOD pointer array starts at +0x88 and its material-owner
pointer is at +0xc8. The record's +0x70 field, not XModel +0x110, owns
XModelMesh. This diagnostic scans bounded serialized child regions
and records all plausible original records without declaring matches
until per-model LOD source count and physical alignment validate.
"""
from __future__ import annotations
import json,math,os,struct,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from r2_download import download
from bo3_zone_decode import parse_zlib_zone
from bo3_model_material_fields import inspect,BASE,NAMES
def valid_ptr(n):
 return n in (0xffffffffffffffff,0xfffffffffffffffe) or (n>>56)==0x50
def candidates(z,start,stop,max_out=100):
 out=[]
 for at in range(start,max(start,stop-0x78+1)):
  n=z[at+0x3c]
  if not 0<n<=64:continue
  u=struct.unpack_from("<H",z,at+0x3e)[0]
  near,far=struct.unpack_from("<ff",z,at+0x40)
  if not (math.isfinite(near) and math.isfinite(far) and
          0<=near<=1e6 and 0<=far<=1e6):continue
  key,=struct.unpack_from("<Q",z,at+0x48)
  surf,mesh=struct.unpack_from("<QQ",z,at+0x68)
  if not valid_ptr(surf) or not valid_ptr(mesh):continue
  out.append({"offset":at,"count":n,"surface_base":z[at+0x3d],
              "original_flags":u,"near":near,"far":far,
              "lod_stream_key":f"0x{key:016x}",
              "surface_ref":f"0x{surf:016x}",
              "mesh_ref":f"0x{mesh:016x}"})
  if len(out)>=max_out:break
 return out
def main():
 root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
 root.mkdir(parents=True,exist_ok=True)
 zone_name="en_core_common.ff"
 with TemporaryDirectory(prefix="bo3-xmodel-lod-") as t:
  path=Path(t)/zone_name
  n,sha,_=download(BASE+zone_name,path)
  if n!=NAMES[zone_name]:raise ValueError(f"Original source length changed {n}")
  z,blocks=parse_zlib_zone(path)
  models=inspect(z)
  verified=[]
  for i,model in enumerate(models):
   name_end=model["source_header"]+0x188+len(model["model"])+1
   next_model=models[i+1]["source_header"] if i+1<len(models) else len(z)
   upper=min(next_model,name_end+8192)
   items=candidates(z,name_end,upper)
   # A T7 loader's first inline LOD body follows its source model name
   # within a small authored child prelude. Require full structural
   # validity and uniqueness; later LOD bodies are NOT inferred.
   first=[x for x in items if
          x["offset"]<name_end+128 and
          x["original_flags"]==0 and
          x["surface_base"]==0 and
          x["near"]<=x["far"] and
          x["surface_ref"]=="0xffffffffffffffff" and
          x["mesh_ref"]=="0xffffffffffffffff"]
   verified.append({
    "model":model["model"],
    "unique_first_original_lod":len(first)==1,
    "first_original_lod_source":first[0] if len(first)==1 else None,
    "name_end":name_end,"next_model_offset":next_model,
    "authored_num_lods":model["num_lods"],
    "candidate_original_lod_records":len(items),
    "lod_record_examples":items[:20],
   })
  report={"file":zone_name,"original_source_sha256":sha,
          "model_count":len(models),
          "candidates_total":sum(m["candidate_original_lod_records"] for m in verified),
          "unique_first_source_lod_records":sum(m["unique_first_original_lod"] for m in verified),
          "proven_first_source_surface_count":sum(
             m["first_original_lod_source"]["count"] for m in verified
             if m["unique_first_original_lod"]
          ),
          "parents":verified}
  print(json.dumps(report,sort_keys=True),flush=True)
  (root/"bo3_model_lod_child_structure_candidates.json").write_text(
   json.dumps(report,indent=2)+"\n")
if __name__=="__main__":
 try:main()
 except Exception as e:
  print(f"BO3 exact XModelLod child survey failed: {e}",file=sys.stderr)
  raise SystemExit(1)
