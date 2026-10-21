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
from bo3_material_binding_probe import analyze as source_material_tables
from bo3_first_mesh_walk import valid_mesh,decode_authentic_rigid_geometry
from bo3_base_index import read_base_index
from bo3_all_xpak_indices import read_index as read_one_kapi_index
from bo3_material_image_links import source_links
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
  # T7 ZoneFormat source contract: 0x30-byte XAssetList is raw-read,
  # then block-5 cursor begins at zero. With zero dependent-package
  # entries, the original stream runs from 0x30 to this physical XAsset
  # table and is 8-byte aligned before table allocation.
  dependency_count=struct.unpack_from("<I",z,0x10)[0]
  logical_asset_table_start=((base-0x30+7)//8)*8 if dependency_count==0 else None
  type6_rows=[i for i in range(row_count)
     if struct.unpack_from("<Q",z,base+16*i)[0]==6]
  typed_materials=source_material_tables(z)["material_source_records"]
  if len(typed_materials)!=len(type6_rows) or len(type6_rows)!=12:
   raise ValueError("Cannot establish one source material name per original inline XAsset row")
  if any(m["all_arrays_count"]!=1 for m in typed_materials):
   raise ValueError("Original T7 material source names lack unique complete texture tables")
  typed_names={row:m["name"] for row,m in zip(type6_rows,typed_materials)}

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
     if (ptr>>56)!=0x50 or logical_asset_table_start is None:break
     logical=(ptr&0x00ffffffffffffff)-1
     # Each root row contains the 8-byte XAssetType then its
     # 8-byte source header pointer. A Material* points to the
     # pointer field (+8), NOT the start of its 16-byte row.
     relative=logical-logical_asset_table_start-8
     if relative<0 or relative%16 or relative//16>=row_count:break
     ty,marker=struct.unpack_from("<QQ",z,base+relative)
     rows.append({"model_material_pointer":f"0x{ptr:016x}",
                  "asset_row_index":relative//16,
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
   complete_owners=[]
   # The only admissible contiguous first-LOD handles are a two-qword
   # inline owner marker followed by exactly one block-5 material handle
   # per source-authored XSurface. One missing handle rejects the group.
   for candidate in child["first_candidate_records"]:
    if candidate["3x8_record"][:2]!=["inline","inline"]:continue
    src=candidate["source_offset"]
    cnt=valid[0]["count"]
    if src+16+cnt*8>next_model:continue
    handles=[struct.unpack_from("<Q",z,src+16+i*8)[0] for i in range(cnt)]
    typed=[]
    for ordinal,h in enumerate(handles):
     if (h>>56)!=0x50 or logical_asset_table_start is None:break
     pointer_field_offset=(h&0x00ffffffffffffff)-1
     relative=pointer_field_offset-logical_asset_table_start-8
     if relative<0 or relative%16:break
     row=relative//16
     if row not in typed_names:break
     ty,marker=struct.unpack_from("<QQ",z,base+16*row)
     if ty!=6 or marker!=0xffffffffffffffff:break
     typed.append({"ordinal":ordinal,"material_xasset_row":row,
                   "material_name":typed_names[row],
                   "source_pointer":f"0x{h:016x}"})
    if len(typed)==cnt:
     complete_owners.append({
      "original_owner_source_offset":src,
      "first_material_token_source_offset":src+16,
      "per_surface_source_handles":[f"0x{h:016x}" for h in handles],
      "resolved_original_material_names":typed,
     })
   # The first LOD's +0x70 mesh owner is inline. Search only the
   # owning XModel's physical child region, demand the exact original
   # XModelMesh name with _lod0, and verify surface cardinality. This
   # reports possible nested mesh bodies; only actual geometry bytes
   # that pass source bounds can be called decoded.
   nested_meshes=[]
   begin=valid[0]["offset"]+0x78
   end=min(next_model,begin+65536)
   at=begin
   while at<end:
    p=z.find(b"\\xff"*8,at,end)
    if p<0:break
    at=p+1
    info=valid_mesh(z,p)
    if info is None:continue
    if info["name"]!=m["model"]+"_lod0":continue
    nested_meshes.append({
      "original_mesh_header_offset":p,
      "mesh_name":info["name"],
      "surface_count":info["surface_count"],
      "matches_model_first_lod_surface_count":info["surface_count"]==valid[0]["count"],
      "surface_pointer":f"0x{info['source_surface_pointer']:016x}",
    })
   result.append({
     "model":m["model"],
     "source_model_header":m["source_header"],
     "first_lod_surface_count":valid[0]["count"],
     "material_owner_ptr":m["material_handle_source_pointer"],
     "nested_first_lod_mesh_candidates":nested_meshes,
     "source_model_material_array_candidates":material_pointer_proofs,
     "first_source_owner_candidate_handles":first_raw_handles,
     "complete_first_lod_material_handle_arrays":complete_owners,
     "unique_complete_first_lod_handle_owner":len(complete_owners)==1,
     "child":child,
   })
  # Full original material dependency closure: model -> typed Material
  # XAsset row -> unique source MaterialImage semantic slots -> authentic
  # GfxImage source ownership. No material/texture names are guessed.
  base_index,keys=read_base_index()
  keys=set(keys)
  for pkg in ("en_initial.xpak","en_base.xpak","base_patch_tu32.xpak"):
   meta,extra=read_one_kapi_index(pkg)
   keys.update(extra)
  images=source_links(z,keys)
  linked_by_name={m["material"]:m for m in images["linked_materials"]}
  source_mats={m["name"]:m for m in typed_materials}
  all_plans=[]
  failed_plans=[]
  for record in result:
   if not record["unique_complete_first_lod_handle_owner"]:
    failed_plans.append({"model":record["model"],"reason":"first_lod_material_handles_ambiguous_or_missing"})
    continue
   owner=record["complete_first_lod_material_handle_arrays"][0]
   surface_plans=[]
   error=None
   for surface in owner["resolved_original_material_names"]:
    mat_name=surface["material_name"]
    mat=source_mats.get(mat_name)
    image_info=linked_by_name.get(mat_name)
    if mat is None or image_info is None or mat["all_arrays_count"]!=1:
     error=f"Material {mat_name} not resolved through unique image source table"
     break
    original_slots=mat["complete_consecutive_slot_arrays"][0]["slots"]
    image_edges={e["material_slot"]:e for e in image_info["ordered_material_edges"]}
    if len(original_slots)!=mat["reported_slots"]:
     error=f"Incomplete MaterialImage count: {mat_name}"
     break
    textures=[]
    for index,slot in enumerate(original_slots):
     is_inline=slot["source_pointer"]=="0xffffffffffffffff"
     edge=image_edges.get(index)
     if is_inline and (edge is None or edge["source_hash"]!=slot["raw_semantic_hash"]):
      error=f"Unresolved original source image for {mat_name} slot {index}"
      break
     if not is_inline and edge is not None:
      error=f"Image edge unexpectedly claims nonresident {mat_name} slot {index}"
      break
     textures.append({
       "index":index,"original_semantic":slot["raw_semantic_hash"],
       "source_image_ptr":slot["source_pointer"],
       "source_image_name":edge["image_name"] if edge else None,
     })
    if error:break
    surface_plans.append({
      "ordinal":surface["ordinal"],
      "source_material_xasset_row":surface["material_xasset_row"],
      "source_material_name":mat_name,
      "material_texture_bindings":textures,
    })
   if error:
    failed_plans.append({"model":record["model"],"reason":error})
   else:
    all_plans.append({"model":record["model"],
                      "original_first_lod_surfaces":record["first_lod_surface_count"],
                      "source_material_surfaces":surface_plans})
  verified_surface_count=sum(len(x["source_material_surfaces"]) for x in all_plans)
  verified_texture_slots=sum(len(surf["material_texture_bindings"]) for x in all_plans
                            for surf in x["source_material_surfaces"])
  confirmed_image_edges=sum(t["source_image_name"] is not None for x in all_plans
                      for surf in x["source_material_surfaces"]
                      for t in surf["material_texture_bindings"])
  unresolved_image_backrefs=verified_texture_slots-confirmed_image_edges
  report={"zone":ZONE,"original_sha256":sha,"total_models":len(result),
          "source_model_material_plan_count":len(all_plans),
          "source_model_material_plans":all_plans,
          "source_material_plan_unresolved":failed_plans,
          "verified_model_surface_materials":verified_surface_count,
          "source_texture_slots_across_model_surfaces":verified_texture_slots,
          "original_named_gfximage_edges_across_model_surfaces":confirmed_image_edges,
          "unresolved_source_image_block_backrefs":unresolved_image_backrefs,
          "models_with_unique_complete_first_lod_handles":sum(m["unique_complete_first_lod_handle_owner"] for m in result),
          "surface_tokens_in_unique_complete_owners":sum(
             len(m["complete_first_lod_material_handle_arrays"][0]["per_surface_source_handles"])
             for m in result if m["unique_complete_first_lod_handle_owner"]),
          "models_with_one_named_local_first_lod_mesh":sum(
              len(m["nested_first_lod_mesh_candidates"])==1 and
              m["nested_first_lod_mesh_candidates"][0]["matches_model_first_lod_surface_count"]
              for m in result),
          "source_dependency_count":dependency_count,
          "logical_block5_asset_table_start":logical_asset_table_start,
          "source_typed_material_row_indices":type6_rows,
          "source_typed_material_names_by_row":typed_names,
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
