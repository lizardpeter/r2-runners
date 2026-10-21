#!/usr/bin/env python3
"""Check actual BO1 retail WEAPONFILE records and attachment/streak relations.

The authentic original main/iw_00.iwd is fetched as a REAL binary from the
client-source artifact. Every exact original weapon-path ZIP member is
decoded in-memory, preserving 2010 T5 CP1252 weapon text rather than dropping
legitimate non-UTF8 source fields. No synthetic weapons or placeholder guns.
"""
from __future__ import annotations
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import zipfile

ORIGINAL_IWD_SHA256="aa35643afbf2eff48f6d73c3633481cae4af00fe96a6ceb5154bdd59bff164ff"
EXPECTED_BYTES=3471624
EXPECTED_WEAPON_PATHS=1165
EXPECTED_WEAPONFILES=1160
EXPECTED_FLAMETABLES=5

def original_weapon_fields(data:bytes,filename:str):
    # BO1 PC weaponfiles are Windows-1252; at least two original turret
    # weapons contain a multiplication sign 0xD7 in ammunition names.
    body=data.removesuffix(b"\0").decode("cp1252")
    fields=body.split("\\")
    kind=fields[0]
    if kind not in ("WEAPONFILE","FLAMETABLEFILE"):
        raise ValueError(f"Original weapon {filename} unexpected type {kind}")
    if (len(fields)-1)%2!=0:
        raise ValueError(f"Original weapon {filename} has incomplete key/value tokens")
    pairs=list(zip(fields[1::2],fields[2::2]))
    if len(pairs)>4096 or any(not key for key,_ in pairs):
        raise ValueError(f"Original weapon {filename} has invalid original field count/names")
    return kind,pairs

def source_weapon_references(pairs):
    out=[]
    for key,value in pairs:
        if not value:continue
        low=key.lower()
        if low in ("altweapon","dualwieldweapon"):
            family="alternate_weapon"
        elif low.endswith(("sound","soundplayer")):
            family="sound"
        elif low.endswith("anim") or "animation" in low:
            family="animation"
        elif low.endswith(("model","model2")):
            family="model"
        elif low.endswith(("effect","fx")):
            family="fx"
        elif low.endswith(("icon","reticle","reticlematerial")):
            family="ui_image"
        else:continue
        out.append((family,key,value))
    return out

def verify(original_iwd:Path,report:Path):
    if original_iwd.stat().st_size!=EXPECTED_BYTES:
        raise ValueError("Original iw_00 archive length differs from retail source")
    if hashlib.sha256(original_iwd.read_bytes()).hexdigest()!=ORIGINAL_IWD_SHA256:
        raise ValueError("Original iw_00 source SHA256 mismatch")
    with zipfile.ZipFile(original_iwd) as game:
        original_paths=[x for x in game.infolist()
            if not x.is_dir() and x.filename.replace("\\","/").lower().startswith("weapons/")]
        if len(original_paths)!=EXPECTED_WEAPON_PATHS:
            raise ValueError(f"Original weapon path count unexpected: {len(original_paths)}")
        entries=[]
        by_kind=Counter();by_mode=Counter();parents=defaultdict(list)
        references=Counter();codepages=Counter()
        for info in original_paths:
            raw=game.read(info)
            if len(raw)!=info.file_size:
                raise ValueError(f"Truncated original weapon resource {info.filename}")
            if any(b>=128 for b in raw):codepages["non_ascii_original_files"]+=1
            kind,fields=original_weapon_fields(raw,info.filename)
            if kind=="WEAPONFILE":
                keys=dict(fields)
                for k in ("weaponType","weaponClass","inventoryType","parentWeaponName"):
                    if k not in keys:
                        raise ValueError(f"Original {info.filename} has no {k}")
            else:keys=dict(fields)
            by_kind[kind]+=1
            mode=info.filename.split("/")[1].lower()
            by_mode[mode]+=1
            parent=keys.get("parentWeaponName","")
            if parent:parents[parent].append(info.filename)
            refs=source_weapon_references(fields)
            references.update(family for family,key,value in refs)
            entries.append({
                "original_path":info.filename,
                "sha256":hashlib.sha256(raw).hexdigest(),
                "original_crc32":info.CRC,
                "original_bytes":info.file_size,
                "kind":kind,
                "mode":mode,
                "parent_weapon_name":parent or None,
                "original_fields":len(fields),
                "original_resource_references":refs,
                "source_field_order_preserved":True,
                "xasset_target_decoded":False,
            })
        if by_kind["WEAPONFILE"]!=EXPECTED_WEAPONFILES or by_kind["FLAMETABLEFILE"]!=EXPECTED_FLAMETABLES:
            raise ValueError(f"Source weapon type counts unexpectedly changed: {by_kind}")
        if by_mode!=Counter({"mp":409,"sp":756}):
            raise ValueError(f"Source original modes unexpectedly changed: {by_mode}")
        if sum(map(len,parents.values()))!=751:
            raise ValueError("Source original parentWeaponName relation count changed")
        if codepages["non_ascii_original_files"]!=2:
            raise ValueError("Original non-UTF8 CP1252 source weapon count unexpected")
        lookup={r["original_path"]:r for r in entries}
        # Independently authenticate selected native weapon gameplay
        # parameters against complete original WEAPONFILE source bytes.
        for source,expected in [
            ("weapons/mp/ak47_mp",{
                "damage":"40","minDamage":"30","clipSize":"30",
                "fireTime":"0.08","reloadTime":"2.5","adsTransInTime":"0.25",
            }),
            ("weapons/mp/ak47_acog_mp",{
                "damage":"40","clipSize":"30","fireTime":"0.08",
                "adsTransInTime":"0.35",
            }),
            ("weapons/sp/ray_gun_upgraded_zm",{
                "damage":"1000","clipSize":"40","maxAmmo":"200",
                "fireTime":"0.33",
            }),
            ("weapons/mp/dogs_mp",{
                "damage":"0","fireTime":"0.8",
            }),
        ]:
            actual=dict(original_weapon_fields(game.read(source),source)[1])
            for field,wanted in expected.items():
                if actual.get(field)!=wanted:
                    raise ValueError(f"Original source weapon {source} {field} mismatched {wanted}")
        for name,parent,kind in [
            ("weapons/mp/ak47_mp","ak47","WEAPONFILE"),
            ("weapons/mp/ak47_acog_mp","ak47","WEAPONFILE"),
            ("weapons/mp/ak47_gl_mp","ak47","WEAPONFILE"),
            ("weapons/mp/dogs_mp","killstreak_dogs","WEAPONFILE"),
            ("weapons/sp/ray_gun_upgraded_zm","ray_gun","WEAPONFILE"),
        ]:
            record=lookup[name]
            if record["kind"]!=kind or record["parent_weapon_name"]!=parent:
                raise ValueError(f"Authentic BO1 source weapon linkage wrong: {name}")
    report.parent.mkdir(parents=True,exist_ok=True)
    result={
        "original_verified_iwd_sha256":ORIGINAL_IWD_SHA256,
        "original_weapon_definitions":dict(by_kind),
        "original_source_paths":len(entries),
        "original_mode_groups":dict(by_mode),
        "original_parent_relationships":sum(map(len,parents.values())),
        "distinct_authored_parent_names":len(parents),
        "killstreak_named_parent_groups":{k:len(v) for k,v in parents.items() if k.startswith("killstreak_")},
        "original_non_utf8_cp1252_files":codepages["non_ascii_original_files"],
        "source_resource_reference_counts":dict(references),
        "source_weapon_asset_decoded_not_runtime_spawned":True,
        "entries":entries,
    }
    report.write_text(json.dumps(result,indent=2)+"\n")
    print(f"PASS ORIGINAL BO1 WEAPONS: {len(entries)} complete source files, "
          f"{by_kind['WEAPONFILE']} WEAPONFILE, {by_kind['FLAMETABLEFILE']} FLAMETABLEFILE; "
          f"MP={by_mode['mp']}, SP/Zombies={by_mode['sp']}; "
          f"{sum(map(len,parents.values()))} real parent relationships; "
          f"{len(result['killstreak_named_parent_groups'])} authored killstreak parent groups; "
          f"source asset refs={dict(references)}.")
    print("Decoded all original weapon source text; runtime XModel/XAnim/Sound content NOT yet decoded.")
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iwd",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args();verify(a.iwd,a.report)
if __name__=="__main__":main()
