#!/usr/bin/env python3
"""Verify the first TWO genuine BO1 world texture alias tables from original FFs.

This test consumes the actual retail client FastFiles, never generated
materials or JSON stand-ins. Material-memory physical offsets and SHA256
are known *test fixtures*, not hardcoded importer rules. It computes virtual
image-pointer fields from the original source strings, constants and states
and requires every first/second handle to have type-correct source owners.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import struct
from pathlib import Path
import zlib

SOURCES={
 "mp_nuked.ff": {
  "sha256":"34a1f7f2eff32cd9c40e8b760e6388979121e8735b2738d3a242c19bd0728a60",
  "material_offset":0x3578A12,"materials":182,"memory_start":0x2B05CDC,
  "tables":(0x2B062C8,0x2B06498),"aliases":(43,35),"pointer_fields":(4,5),
 },
 "mp_firingrange.ff":{
  "sha256":"24be19d5251342c0de51f704b554ed6991ae0bfab940f0d7495fbd5f96cc23d8",
  "material_offset":0x34E0502,"materials":407,"memory_start":0x2F6ABB8,
  "tables":(0x2F6B8B8,0x2F6BB40),"aliases":(10,117),"pointer_fields":(6,6),
 },
}
MAX_ZONE=200*1024*1024

def word(blob:bytes,at:int)->int:
    if at<0 or at+4>len(blob):raise ValueError("truncated original T5 32-bit field")
    return struct.unpack_from("<I",blob,at)[0]

def read_name(zone:bytes,at:int):
    end=zone.find(b"\0",at,at+261)
    if end<0 or end==at:raise ValueError("missing original inline material/image name")
    return zone[at:end].decode("ascii"),end+1

def align4(at:int)->int:return (at+3)&~3

def recover(zone:bytes,spec:dict):
    count=spec["materials"]
    base=spec["material_offset"]
    for row in range(count):
        at=base+8*row
        if word(zone,at)!=0xffffffff or word(zone,at+4)<256:
            raise ValueError("original GfxWorld MaterialMemory array mismatch")
    cursor=base+count*8
    materials=[]
    for ordinal in range(count):
        h=zone[cursor:cursor+192]
        if len(h)!=192 or word(h,0)!=0xffffffff:
            raise ValueError(f"source material {ordinal} has invalid 192-byte struct")
        tex_count,const_count,state_count=h[170],h[171],h[172]
        tex_ptr,const_ptr,state_ptr=struct.unpack_from("<III",h,180)
        cursor+=192
        name,cursor=read_name(zone,cursor)
        texture=[]
        if tex_ptr==0xffffffff:
            for j in range(tex_count):
                tex=zone[cursor+16*j:cursor+16*j+16]
                if len(tex)!=16:raise ValueError("truncated original MaterialTextureDef")
                texture.append({
                    "semantic":tex[7],"pointer":word(tex,12),"name":None,
                    "name_hash":word(tex,0),"name_start":tex[4],"name_end":tex[5],
                })
            cursor+=16*tex_count
            for t in texture:
                if t["pointer"]!=0xffffffff:continue
                img=zone[cursor:cursor+52]
                if len(img)!=52:raise ValueError("truncated original GfxImage")
                img_pointer=word(img,0)
                img_name_ptr=word(img,44)
                if img_name_ptr==0xffffffff:
                    t["name"],cursor=read_name(zone,cursor+52)
                elif img_name_ptr==0:cursor+=52
                else:raise ValueError("GfxImage name requires source relocations")
                t["image_semantic"]=img[5]
                if img_pointer==0xfffffffe:
                    bytes_count=word(zone,cursor+8)
                    cursor+=12+bytes_count
                elif img_pointer!=0:
                    raise ValueError("source GfxImage texture resource not handled")
        elif tex_ptr!=0 or tex_count!=0:
            raise ValueError("T5 material texture array nonfollowing or missing")
        if const_ptr==0xffffffff:cursor+=32*const_count
        elif const_ptr!=0 or const_count!=0:raise ValueError("T5 material constants need relocation")
        if state_ptr==0xffffffff:cursor+=8*state_count
        elif state_ptr!=0 or state_count!=0:raise ValueError("T5 material render states need relocation")
        if cursor>len(zone):raise ValueError("original source material stream truncated")
        materials.append({"name":name,"textures":texture,"constant_count":const_count,"state_count":state_count})
    return materials

def original_material_sampler_hash(text:str)->int:
    # Source T5 R_HashString(name,0), wrapping u32 and ASCII case folding.
    value=0
    for char in text.encode("ascii"):
        value=((value*33)^(char|0x20))&0xffffffff
    return value

def verify_original_shader_material_sampler_names(zone:bytes,materials:list[dict],mapname:str)->int:
    source_vocabulary={
        "colorMap":2, "colorMap1":2, "colorMap2":2, "colorMap3":2,
        "normalMap":5, "normalMap1":5, "normalMap2":5,
        "specularMap":8, "specularMap1":8, "specularMap2":8,
    }
    lookup={original_material_sampler_hash(n):(n,sem) for n,sem in source_vocabulary.items()}
    assert len(lookup)==len(source_vocabulary)
    ctab_source_names={}
    for name in source_vocabulary:
        root=name.rstrip("0123456789")
        number=name[len(root):]
        ctab_name=f"{root}Sampler{number}".encode()+bytes([0])
        ctab_source_names[name]=ctab_name in zone
    mapped=0
    missing={}
    for material in materials:
        for slot in material["textures"]:
            h=slot["name_hash"]
            if h in lookup:
                name,semantic=lookup[h]
                if slot["semantic"]!=semantic:
                    raise ValueError(f"source sampler {name} has unexpected semantic {slot['semantic']}")
                if (slot["name_start"],slot["name_end"]) != (ord(name[0]),ord(name[-1])):
                    raise ValueError(f"source sampler {name} original first/last bytes do not match")
                if not ctab_source_names[name]:
                    raise ValueError(f"original SM3 CTAB sampler for {name} not found in source")
                mapped+=1
            else:
                missing[h]=missing.get(h,0)+1
    expected=707 if mapname=="mp_nuked.ff" else 1883
    if mapped!=expected or sum(missing.values())!= (4 if expected==707 else 6):
        raise ValueError(f"{mapname}: unexpected source sampler hash coverage {mapped}, unresolved={missing}")
    print(f"VERIFIED {mapname}: {mapped} original named MaterialTextureDef slots "
          f"identified by exact R_HashString + source SM3 shader sampler strings; "
          f"{sum(missing.values())} special source slots unresolved")
    return mapped

def verify_map(original_file:Path,source:dict):
    size=original_file.stat().st_size
    digest=hashlib.sha256(original_file.read_bytes()).hexdigest()
    if digest!=source["sha256"]:raise ValueError(f"unexpected client FF sha256 for {original_file.name}")
    raw=original_file.read_bytes()
    if raw[:8]!=b"IWffu100" or word(raw,8)!=0x1d9:
        raise ValueError("expected original BO1 T5 FastFile")
    zone=zlib.decompress(raw[12:])
    if len(zone)>MAX_ZONE:raise ValueError("expanded original source unexpectedly large")
    materials=recover(zone,source)
    verify_original_shader_material_sampler_names(zone,materials,original_file.name)
    owners=defaultdict(list)
    for i,m in enumerate(materials):
        for j,t in enumerate(m["textures"]):
            ptr=t["pointer"]
            if ptr not in (0,0xffffffff,0xfffffffe):
                owners[ptr].append((i,j,t["semantic"]))
    first,second=materials[:2]
    first_table=align4(source["memory_start"]+source["materials"]*8+len(first["name"])+1)
    cursor=first_table+16*len(first["textures"])
    for t in first["textures"]:
        if t["pointer"]!=0xffffffff or not t["name"]:
            raise ValueError("first original GfxImage is not inline")
        cursor=align4(cursor+len(t["name"])+1)+4
    cursor=align4(cursor)+32*first["constant_count"]
    cursor=align4(cursor)+8*first["state_count"]
    second_table=align4(cursor+len(second["name"])+1)
    if (first_table,second_table)!=source["tables"]:
        raise ValueError(f"source T5 virtual replay mismatch: {(hex(first_table),hex(second_table))}")
    alias_count=[]
    for ordinal,(material,table) in enumerate([(first,first_table),(second,second_table)]):
        found=0
        for j,texture in enumerate(material["textures"]):
            if texture["pointer"]!=0xffffffff or not texture["name"]:
                raise ValueError("original first/second inline GfxImage identity absent")
            packed=0x80000001+table+j*16+12
            if packed not in owners:
                raise ValueError(f"source texture field {ordinal}.{j} at 0x{packed:08x} unreferenced")
            if any(semantic!=texture["semantic"] for _,_,semantic in owners[packed]):
                raise ValueError(f"source texture field {ordinal}.{j} semantic conflict")
            found+=len(owners[packed])
        alias_count.append(found)
    if tuple(alias_count)!=source["aliases"]:
        raise ValueError(f"original alias source counts changed: {alias_count}")
    if tuple(map(lambda m:len(m["textures"]),materials[:2]))!=source["pointer_fields"]:
        raise ValueError("original source first two texture-field counts changed")
    print(f"VERIFIED {original_file.name}: {size:,} original bytes; "
          f"{len(materials)} world materials, source tables "
          f"0x{first_table:X} and 0x{second_table:X}; "
          f"{alias_count[0]}+{alias_count[1]} exact packed slot image owners")
    return sum(alias_count)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path,required=True)
    args=p.parse_args()
    total=0
    for name,spec in SOURCES.items():
        path=args.source_root/"zone"/"common"/name
        total+=verify_map(path,spec)
    if total!=205:raise ValueError("first two source image alias closures changed")
    print(f"PASS: 205 original packed texture slots mapped to first/second material image fields; "
          "later virtual allocation events deliberately not guessed.")

if __name__=="__main__":
    main()
