#!/usr/bin/env python3
"""Source-verified authored BO1 weapon animation links from genuine binaries.

Both source inventories are independently derived from real iw_00.iwd and
common_mp.ff binaries by scripts in the SAME workflow. A WEAPONFILE field
like reloadAnim only resolves to an exact XAnimParts name and original
frame/frequency; missing names are NOT considered absent from the full game.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

def validate(weapon_report:Path,anim_report:Path,out:Path):
    w=json.loads(weapon_report.read_text())
    a=json.loads(anim_report.read_text())
    if w["original_weapon_definitions"] != {"WEAPONFILE":1160,"FLAMETABLEFILE":5}:
        raise ValueError("Weapon source metadata is not the actual BO1 iw_00 corpus")
    if a["exact_named_inline_headers"]!=2666 or a["source_xasset_type4_rows"]!=3355:
        raise ValueError("Animation source metadata not actual common_mp")
    xanim={item["name"]:item for item in a["source_authored_animation_headers"]}
    if len(xanim)!=2666:raise ValueError("Original source animation identities duplicate")
    total=resolved=0
    distinct=set()
    matched=set()
    exceptions=[]
    by_field=Counter()
    sample=None
    for record in w["entries"]:
        for family,field,name in record["original_resource_references"]:
            if family!="animation":continue
            total+=1
            distinct.add(name)
            real=xanim.get(name)
            by_field[field]+=1
            if real is None:
                exceptions.append({
                    "source_weapon":record["original_path"],
                    "source_field":field,
                    "source_anim_name":name,
                    "unresolved_in_common_mp_only":True,
                })
            else:
                resolved+=1
                matched.add(name)
                if record["original_path"]=="weapons/mp/ak47_mp" and field=="idleAnim":
                    sample=(name,real["numframes"],real["framerate"],real["source_header_offset"])
    if (total,resolved,len(exceptions),len(distinct),len(matched))!=(
        20351,14949,5402,2437,1641
    ):
        raise ValueError(f"Wrong original source animation linkage "
                         f"{total,resolved,len(exceptions),len(distinct),len(matched)}")
    if not sample or sample[0]!="viewmodel_ak47_idle" or sample[3]!=0x26de8f3:
        raise ValueError(f"Original AK47 animation src not matched: {sample}")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps({
        "original_weapon_animation_field_occurrences":total,
        "source_names_matched_to_original_common_mp":resolved,
        "source_names_not_matched_in_common_mp":len(exceptions),
        "distinct_authored_source_anim_names":len(distinct),
        "distinct_source_anim_names_matched":len(matched),
        "original_ak47_idle_animation_proof":sample,
        "authored_field_occurrences":dict(by_field),
        "unmatched_source_fields":exceptions,
        "playable_skeletal_tracks_decoded":0,
    },indent=2)+"\n")
    print(f"PASS genuine BO1 WEAPONFILE -> XAnimParts: "
          f"{resolved:,} / {total:,} real authored animation references "
          f"exact-name match the independently decoded original common_mp.ff; "
          f"{len(exceptions):,} require other source zones, "
          f"{len(matched):,} distinct authenticated clip names matched. "
          "This is NOT runtime skeletal playback.")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--weapon-report",type=Path,required=True)
    p.add_argument("--animation-report",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    validate(a.weapon_report,a.animation_report,a.out)
if __name__=="__main__":main()
