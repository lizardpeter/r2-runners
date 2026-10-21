#!/usr/bin/env python3
"""Source-authenticated full T7 XAsset type coverage census.

Records ALL original typed asset rows per FF, not false claims of decoded
models/animations/maps. Original FastFiles download to disposable runner
storage and decoded bytes stay in memory. JSON includes per-type counts,
body-stage honesty, SHA256 row identity, source family and missing features,
never retail payloads, script strings, asset names or executable bytes.
"""
from __future__ import annotations
from collections import Counter,defaultdict
import hashlib,json,os,struct,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import BASE,PREFIX,SOURCES,PRESETS,parse_zlib_zone,parse_directory

T7_KINDS=["physpreset","physconstraints","destructibledef","xanim","xmodel","xmodelmesh","material","computeshaderset","techset","image","sound","sound_patch","col_map","com_map","game_map","map_ents","gfx_map","lightdef","lensflaredef","ui_map","font","fonticon","localize","weapon","weapondef","weaponvariant","weaponfull","cgmediatable","playersoundstable","playerfxtable","sharedweaponsounds","attachment","attachmentunique","weaponcamo","customizationtable","customizationtable_feimages","customizationtablecolor","snddriverglobals","fx","tagfx","klf","impactsfxtable","impactsoundstable","player_character","aitype","character","xmodelalias","rawfile","stringtable","structuredtable","leaderboarddef","ddl","glasses","texturelist","scriptparsetree","keyvaluepairs","vehicle","addon_map_ents","tracer","slug","surfacefxtable","surfacesounddef","footsteptable","entityfximpacts","entitysoundimpacts","zbarrier","vehiclefxdef","vehiclesounddef","typeinfo","scriptbundle","scriptbundlelist","rumble","bulletpenetration","locdmgtable","aimtable","animselectortable","animmappingtable","animstatemachine","behaviortree","behaviorstatemachine","ttf","sanim","lightdescription","shellshock","xcam","bgcache","texturecombo","flametable","bitfield","attachmentcosmeticvariant","maptable","maptableloadingimages","medal","medaltable","objective","objectivelist","umbra_tome","navmesh","navvolume","binaryhtml","laser","beam","streamerhint","string"]
GROUPS={
    "animation":{3,75,76,77,78,79,81,84},
    "models_characters":{4,5,43,44,45,46,34,35,36,89},
    "materials_shaders_textures":{6,7,8,9,53,86},
    "worlds_maps_physics":{0,1,2,12,13,14,15,16,19,57,90,91,96,97,98},
    "weapons_camos_attachments":{23,24,25,26,30,31,32,33,56,58,59,66,67,72,73,74,100,101},
    "audio":{10,11,28,30,37,42,61,62,64,67,71},
    "fx_lighting":{17,18,29,38,39,41,58,60,63,82,83,87,100,101},
    "ui_scripts_metadata":{20,21,22,27,40,47,48,49,50,51,52,54,55,65,68,69,70,80,85,88,92,93,94,95,99,102,103},
}
# All 104 kinds are represented; a kind may belong to several user-visible
# classes (e.g. weapon sound assets are audio and weapons).
BODY_STAGE={
    4:"partial_xmodel_lod_header_only",
    5:"partial_mesh_header_and_some_resident_rigid_surfaces",
    6:"partial_material_header_semantic_slot_and_some_images",
    9:"partial_image_descriptor_and_some_pixel_payloads",
}
def row_stage(t):
    return BODY_STAGE.get(t,"directory_only_body_unimplemented")
def group_names(t):
    v=[name for name,kinds in GROUPS.items() if t in kinds]
    return v if v else ["other_source_asset"]
def census(name):
    if name not in SOURCES:raise ValueError(f"Not allowlisted source FF: {name}")
    with TemporaryDirectory(prefix="t7-xasset-coverage-") as tmp:
        path=Path(tmp)/name
        original_size,sha,_=download(BASE+"/"+quote(PREFIX+name,safe="/"),path)
        if original_size!=SOURCES[name]:
            raise ValueError(f"Original BO3 zone has unexpected size {name}")
        decoded,blocks=parse_zlib_zone(path)
    if blocks["status"]!="end_marker":
        raise ValueError(f"Cannot call partial/limited decode exhaustive: {name}: {blocks['status']}")
    directory=parse_directory(decoded)
    if directory["status"]!="t7_asset_table_layout_verified":
        raise ValueError(f"BO3 typed XAsset directory not authenticated: {name}: {directory['status']}")
    table=directory["asset_table"]
    if table["layout"]!="type_then_header":
        raise ValueError("XAsset directory unexpected pointer layout")
    offset=table["table_offset"]
    count=directory["asset_count"]
    typed={i:{"asset_type":i,"asset_type_name":T7_KINDS[i],
            "classifications":group_names(i),"body_stage":row_stage(i),
            "directory_rows":0,"inline_header_roots":0,"block5_refs":0,
            "absent_headers":0,"external_headers":0} for i in range(104)}
    sha_rows=hashlib.sha256()
    for j in range(count):
        raw=bytes(decoded[offset+j*16:offset+(j+1)*16])
        if len(raw)!=16:raise ValueError("Original source typed row out of bounds")
        type_id,ptr=struct.unpack("<QQ",raw)
        if type_id>=104:raise ValueError(f"Unsupported T7 source asset type {type_id}")
        sha_rows.update(raw)
        row=typed[type_id]
        row["directory_rows"]+=1
        if ptr==0xffffffffffffffff:row["inline_header_roots"]+=1
        elif (ptr>>56)==0x50:row["block5_refs"]+=1
        elif ptr==0:row["absent_headers"]+=1
        elif ptr==0xfffffffffffffffe:row["external_headers"]+=1
        else:raise ValueError("Unauthenticated root XAsset header pointer")
    if sum(x["directory_rows"] for x in typed.values())!=count:
        raise ValueError("Loss of BO3 original asset records")
    return {
        "source":name,"source_sha256":sha,"original_file_bytes":original_size,
        "decoded_zone_bytes":len(decoded),"decoded_blocks":blocks["block_count"],
        "verified_original_xasset_rows":count,
        "source_inline_roots":sum(x["inline_header_roots"] for x in typed.values()),
        "directory_rows_sha256":sha_rows.hexdigest(),
        "present_types":[x for x in typed.values() if x["directory_rows"]>0],
    }
def main():
    preset=os.environ.get("BO3_COVERAGE_PRESET","small")
    if preset not in PRESETS:raise ValueError("Unsupported asset coverage preset")
    records=[]
    counts=Counter()
    groups=Counter()
    categories=defaultdict(Counter)
    for name in PRESETS[preset]:
        sample=census(name)
        records.append(sample)
        for v in sample["present_types"]:
            counts[v["asset_type"]]+=v["directory_rows"]
            for group in v["classifications"]:
                groups[group]+=v["directory_rows"]
                categories[group][v["asset_type_name"]]+=v["directory_rows"]
        print(json.dumps({"source_result":sample},sort_keys=True),flush=True)
    summary={
        "preset":preset,"completed_original_zones":len(records),
        "directory_rows_total":sum(x["verified_original_xasset_rows"] for x in records),
        "present_type_ids":sum(counts[i]>0 for i in range(104)),
        "empty_or_absent_type_ids":sum(counts[i]==0 for i in range(104)),
        "per_type":[{"type_id":i,"type_name":T7_KINDS[i],
                     "directory_rows":counts[i],"classifications":group_names(i),
                     "body_stage":row_stage(i)} for i in range(104)],
        "group_rows":dict(sorted(groups.items())),
        "group_types":{k:dict(v.most_common()) for k,v in sorted(categories.items())},
        "critical_truth":"A typed XAsset row is NOT a decoded model, map, camo, audio sample, shader or animation.",
    }
    print(json.dumps({"summary":summary},sort_keys=True),flush=True)
    report=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    report.mkdir(parents=True,exist_ok=True)
    (report/f"bo3_asset_coverage_{preset}.json").write_text(
        json.dumps({"summary":summary,"zones":records},indent=2)+"\n",encoding="utf-8")
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 source XAsset coverage failed: {e}",file=sys.stderr)
        raise SystemExit(1)
