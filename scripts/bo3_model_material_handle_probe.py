#!/usr/bin/env python3
"""Diagnose native T7 XModel per-surface material-handle ownership in original FF.

Never infer a material from proximity to its name. This bounded source audit
finds valid XModel first LOD bodies and enumerates nearby tagged pointer
sequences and candidate (8-byte prefix, inline table ref, 8-byte suffix)
per-LOD material-owner layouts. Reports only source offsets, pointer tokens
and uniqueness counts, without copying retail asset bodies.
"""
from __future__ import annotations
import hashlib,json,os,struct,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from r2_download import download
from bo3_zone_decode import parse_zlib_zone,parse_directory
from bo3_model_material_fields import inspect,BASE,NAMES
from bo3_xmodel_lod_walk import candidates
ZONE="en_core_common.ff"
KNOWN_POINTERS={0,0xffffffffffffffff,0xfffffffffffffffe}
def kind(n):
 if n==0:return "zero"
 if n==0xffffffffffffffff:return "inline"
 if n==0xfffffffffffffffe:return "external"
 if n>>56==0x50:return "block5"
 if n>>56==0x60:return "block6"
 return "other"
def probe(z,name_end,lod,upper):
 end=min(len(z),upper,name_end+8192)
 lodend=lod["offset"]+0x78
 rows=[]
 for at in range(lodend,end-7):
  if z[at]&0xff not in (0,0x01,0xfe,0xff):continue
  ptr=struct.unpack_from("<Q",z,at)[0]
  if kind(ptr) not in ("inline","external","block5","block6"):continue
  rows.append((at,ptr,kind(ptr)))
 grouped=[]
 for at,ptr,typ in rows:
  if at<lodend or at+24>end:continue
  # Source XModel material table nested pointer pattern from native T7
  # runtime: 8 reserved, 8 array ptr, 8 reserved, then 8*N handles.
  entries=[struct.unpack_from("<Q",z,at+i*8)[0] for i in range(4)]
  if kind(entries[1]) not in ("inline","block5"):continue
  if kind(entries[0]) not in ("zero","external","inline","block5","block6"):continue
  if kind(entries[2]) not in ("zero","external","inline","block5","block6"):continue
  grouped.append({
   "source_offset":at,
   "distance_after_first_lod":at-lodend,
   "3x8_record":[kind(x) for x in entries[:3]],
   "first_entry_after_record":kind(entries[3]),
   "pointer_bits":["0x%016x"%x for x in entries[:3]],
  })
 return {"lod_end":lodend,"candidate_material_array_records":len(grouped),
         "first_candidate_records":grouped[:30],
         "first_40_tags":[{"at":p,"kind":k,"src":f"0x{x:016x}"} for p,x,k in rows[:40]],
         "pointer_tag_histogram":{k:sum(t[2]==k for t in rows) for k in ("inline","external","block5","block6")}}
def main():
 root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
 root.mkdir(parents=True,exist_ok=True)
 with TemporaryDirectory(prefix="bo3-handle-cursor-") as t:
  p=Path(t)/ZONE
  size,sha,_=download(BASE+ZONE,p)
  if size!=NAMES[ZONE]:raise ValueError("Source BO3 FF length changed")
  z,_=parse_zlib_zone(p)
  models=inspect(z)
  directory=parse_directory(bytearray(z))
  base=directory["asset_table"]["table_offset"]
  row_count=directory["asset_count"]
  material_headers=[ptr for kind,ptr in (struct.unpack_from("<QQ",z,base+16*i) for i in range(row_count)) if kind==6]
  material_ref_counts={f"0x{x:016x}":material_headers.count(x) for x in set(material_headers)}
  result=[]
  for i,m in enumerate(models):
   n=m["source_header"]+0x188+len(m["model"])+1
   next_model=models[i+1]["source_header"] if i+1<len(models) else len(z)
   lods=candidates(z,n,min(n+128+0x78,next_model))
   valid=[x for x in lods if
       x["surface_base"]==0 and x["original_flags"]==0 and
       x["near"]<=x["far"] and
       x["surface_ref"]=="0xffffffffffffffff" and
       x["mesh_ref"]=="0xffffffffffffffff"]
   if len(valid)!=1:raise ValueError("First T7 LOD ambiguous for "+m["model"])
   child=probe(z,n,valid[0],next_model)
   material_pointer_proofs=[]
   for candidate in child["first_candidate_records"]:
    if candidate["3x8_record"][:2]!=["inline","inline"]:
     continue
    at=candidate["source_offset"]
    count=valid[0]["count"]
    if at+16+count*8>next_model:continue
    ptrs=[struct.unpack_from("<Q",z,at+16+u*8)[0] for u in range(count)]
    rows=[]
    for ptr in ptrs:
     if (ptr>>56)!=0x50:break
     logical=(ptr&0x00ffffffffffffff)-1
     if logical%16 or logical//16>=row_count:break
     ty,marker=struct.unpack_from("<QQ",z,base+logical)
     rows.append({"model_material_pointer":f"0x{ptr:016x}",
                  "asset_row_index":logical//16,
                  "typed_asset_kind":ty,"asset_header_ref":f"0x{marker:016x}"})
    if len(rows)==count:
     material_pointer_proofs.append({
       "source_array_offset":at+16,
       "declared_surface_count":count,
       "all_source_asset_rows_are_materials":all(r["typed_asset_kind"]==6 for r in rows),
       "original_asset_row_joins":rows,
     })
   first_candidate=next((c for c in child["first_candidate_records"]
                         if c["3x8_record"][:2]==["inline","inline"]),None)
   first_raw_handles=[]
   if first_candidate is not None:
    offset=first_candidate["source_offset"]+16
    for surface in range(valid[0]["count"]):
     word=struct.unpack_from("<Q",z,offset+surface*8)[0]
     first_raw_handles.append({
      "original_surface_ordinal":surface,
      "source_pointer":f"0x{word:016x}",
      "pointer_kind":kind(word),
     })
   result.append({
     "model":m["model"],
     "source_model_header":m["source_header"],
     "first_lod_surface_count":valid[0]["count"],
     "material_owner_ptr":m["material_handle_source_pointer"],
     "source_model_material_array_candidates":material_pointer_proofs,
     "first_source_owner_candidate_handles":first_raw_handles,
     "child":child,
   })
  report={"zone":ZONE,"original_sha256":sha,"total_models":len(result),
          "typed_source_material_xasset_pointers":material_ref_counts,
          "typed_source_material_xasset_count":len(material_headers),
          "data":result}
  print(json.dumps(report,sort_keys=True),flush=True)
  (root/"bo3_xmodel_material_handles_source_probe.json").write_text(
      json.dumps(report,indent=2)+"\n")
if __name__=="__main__":
 try:main()
 except Exception as e:
  print(f"BO3 original XModel material pointer probe failed: {e}",file=sys.stderr)
  sys.exit(1)
