#!/usr/bin/env python3
"""Count original UE4.21 Athena actors and identity-bearing exports by category.

Not a substitute for geometry, light parameter or shader execution. Both the
exact UWorld/UExp asset and a per-world actor census are retained for engine
import. Records come only from authenticated original file bytes, never guessed
POI labels. No fake display names are created from map file identifiers.
"""
from __future__ import annotations
from collections import Counter
import argparse
import json
from pathlib import Path
import struct

MAGIC=0x9E2A83C1
CATEGORY_TOKENS={
    "lighting":("directionallight","pointlight","spotlight","rectlight","skylight","lightcomponent"),
    "fog":("exponentialheightfog","atmosphericfog","fogcomponent","fogvolume"),
    "sky":("skydome","skyatmosphere","skybox","skylight","cloud","sun"),
    "vegetation":("foliage","grass","tree","bush","plant","shrub"),
    "terrain":("landscape","terrain","heightfield"),
    "postprocess":("postprocess","colorgrading","tonemap","exposure"),
    "poi_identity":("poi","location","landmark","athenamapinfo","locationvolume"),
}

def inspect_world(source:bytes)->dict:
    size=len(source)
    def read(pos:int,fmt:str):
        length=struct.calcsize(fmt)
        if pos<0 or pos+length>size:
            raise ValueError("original UE4 header has truncated field")
        values=struct.unpack_from(fmt,source,pos)
        return values[0] if len(values)==1 else values
    def u32(pos:int):return read(pos,"<I")
    def i32(pos:int):return read(pos,"<i")
    def fullname(pos:int,names:list[str]):
        idx,instance=read(pos,"<II")
        if idx>=len(names):raise ValueError("source FName index outside original NameMap")
        return names[idx] + (f"#{instance}" if instance else "")
    def fstring(pos:int):
        n=i32(pos);pos+=4
        octets=abs(n)*(2 if n<0 else 1)
        if octets>131072 or pos+octets>size:
            raise ValueError("source FName serialized text invalid")
        data=source[pos:pos+octets]
        pos+=octets
        if n>0:
            if not data.endswith(b"\0"):raise ValueError("missing ASCII FName terminator")
            return data[:-1].decode("utf8"),pos
        if n<0:
            if not data.endswith(b"\0\0"):raise ValueError("missing UTF16 FName terminator")
            return data[:-2].decode("utf-16le"),pos
        return "",pos
    if u32(0)!=MAGIC or i32(4)!=-7:
        raise ValueError("not original Fortnite UE4.21 cooked map")
    pos=24
    header_size=u32(pos);pos+=4
    _,pos=fstring(pos)
    pos+=4
    name_count,name_offset=read(pos,"<II")
    pos+=16
    export_count,export_offset=read(pos,"<II")
    pos+=8
    import_count,import_offset=read(pos,"<II")
    pos+=8
    depends_offset=u32(pos)
    if (header_size>size or name_count>250_000 or
        import_count>250_000 or export_count>250_000 or
        import_offset+import_count*28 !=export_offset or
        export_offset+export_count*104!=depends_offset or depends_offset>size):
        raise ValueError("original UE4.21 UObject table not bounded")
    names=[]
    pos=name_offset
    for _ in range(name_count):
        n,pos=fstring(pos)
        names.append(n)
        pos+=4
    imports=[]
    for i in range(import_count):
        p=import_offset+i*28
        imports.append((fullname(p+20,names),i32(p+16)))
    exports=[]
    for i in range(export_count):
        p=export_offset+i*104
        exports.append((fullname(p+16,names),i32(p+12),i32(p)))
    def identity(ref:int)->str:
        visited=set()
        chain=[]
        while ref:
            if ref in visited or len(chain)>=1024:
                raise ValueError("original UObject Outer graph cyclic")
            visited.add(ref)
            if ref<0:
                idx=-ref-1
                if idx>=len(imports):raise ValueError("source import reference outside table")
                name,ref=imports[idx]
            else:
                idx=ref-1
                if idx>=len(exports):raise ValueError("source export reference outside table")
                name,ref,_=exports[idx]
            chain.append(name)
        return "::".join(reversed(chain))
    class_totals=Counter()
    categories={category:[] for category in CATEGORY_TOKENS}
    actor_count=0
    for i,(name,outer,class_ref) in enumerate(exports):
        source_class=identity(class_ref) if class_ref else ""
        class_totals[source_class]+=1
        if source_class.endswith("Component"):
            continue
        actor_count+=1
        actor_path=identity(i+1)
        class_lc=source_class.lower()
        for category,patterns in CATEGORY_TOKENS.items():
            if any(token in class_lc for token in patterns):
                categories[category].append({
                    "source_actor":actor_path,
                    "source_class":source_class,
                })
    return {
        "source_name_count":len(names),
        "original_imports":len(imports),
        "original_exports":len(exports),
        "noncomponent_exports":actor_count,
        "source_class_counts":dict(class_totals.most_common()),
        "category_actor_exports":categories,
        "category_counts":{k:len(v) for k,v in categories.items()},
        "source_classification_only":True,
    }

def run(root:Path,reports:Path):
    base=root/"FortniteGame"/"Content"
    candidates=sorted(base.rglob("*.umap"))
    worlds=[]
    errors=[]
    totals=Counter()
    for source in candidates:
        rel=source.relative_to(root).as_posix()
        companion=source.with_suffix(".uexp")
        if not companion.is_file():
            errors.append({"source":rel,"error":"companion .uexp absent"})
            continue
        try:
            data=inspect_world(source.read_bytes())
            data["source_path"]=rel
            data["companion_path"]=companion.relative_to(root).as_posix()
            totals.update(data["category_counts"])
            worlds.append(data)
            print("ATHENA_SOURCE_WORLD_ACTOR_CENSUS",rel,"exports",data["original_exports"],
                  "lighting",data["category_counts"]["lighting"],
                  "foliage",data["category_counts"]["vegetation"],
                  "fog",data["category_counts"]["fog"],
                  "sky",data["category_counts"]["sky"],flush=True)
        except Exception as exc:
            errors.append({"source":rel,"error":str(exc)[:250]})
    report={
        "authenticated_original_world_packages":len(candidates),
        "parsed_original_worlds":len(worlds),
        "authored_classified_actor_exports":dict(totals),
        "worlds":worlds,
        "errors":errors,
        "limitations":"Names are source UObject identities, not translated retail POI display labels. Actor class identity alone is not decoded material, dynamic lighting or atmospheric shading.",
    }
    reports.mkdir(parents=True,exist_ok=True)
    (reports/"athena-original-world-actor-census.json").write_text(
        json.dumps(report,indent=2)+"\n",encoding="utf8")
    print("ATHENA_AUTHENTIC_WORLD_ACTOR_SUMMARY","parsed",len(worlds),
          "errors",len(errors),"categories",dict(totals),flush=True)
    if not worlds or errors:
        raise RuntimeError("Athena source world actor census incomplete")

def test():
    for category in ("lighting","fog","sky","vegetation","terrain","poi_identity","postprocess"):
        assert category in CATEGORY_TOKENS
    try:
        inspect_world(b"\x00"*256)
    except ValueError:
        pass
    else:
        raise AssertionError("forged UE4 map accepted")
    print("ATHENA_WORLD_ACTOR_CENSUS_SELFTEST_PASS",flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path)
    p.add_argument("--reports",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    test()
    if not a.self_test:
        if not a.root or not a.reports:p.error("--root and --reports required")
        run(a.root,a.reports)
