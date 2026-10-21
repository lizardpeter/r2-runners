#!/usr/bin/env python3
"""Verify ACTUAL BO1 original XAnimParts headers and bone IDs from FastFile.

Uses complete original retail common_mp.ff (no stand-in JSON). Retains real
names/physical locations and original 104-byte source header fields.
Decoding of transform/time channels is NOT implied by a header parse.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import zlib
import math

def u32(b,off):return struct.unpack_from("<I",b,off)[0]
def source_zone(original:bytes):
    if original[:8]!=b"IWffu100" or u32(original,8)!=0x1d9:
        raise ValueError("wrong original BO1 PC source FastFile version")
    return zlib.decompress(original[12:])

def original_script_strings(zone):
    n,ptr=struct.unpack_from("<II",zone,36)
    if not n or ptr!=0xffffffff:raise ValueError("unsupported original script string layout")
    cursor=52+4*n
    names=[]
    for i in range(n):
        ref=u32(zone,52+4*i)
        if ref==0:names.append(None)
        elif ref==0xffffffff:
            e=zone.index(b"\0",cursor)
            names.append(zone[cursor:e].decode("utf-8"))
            cursor=e+1
        else:raise ValueError(f"original source script string {i} uses nonfollowing")
    return names,cursor

def verify(path:Path,out:Path):
    original=path.read_bytes()
    zone=source_zone(original)
    scripts,start=original_script_strings(zone)
    n=u32(zone,44)
    if n!=7199:raise ValueError(f"Original common_mp XAsset count changed: {n}")
    xasset_count=Counter()
    for ordinal in range(n):
        xasset_type=u32(zone,start+8*ordinal)
        xasset_count[xasset_type]+=1
    if xasset_count[4]!=3355:raise ValueError("Original 3355 XANIMPARTS source row count changed")
    first=start+8*n
    entries=[]
    names=set()
    counters=Counter()
    pos=first
    while True:
        pos=zone.find(b"\xff\xff\xff\xff",pos)
        if pos<0 or pos+224>len(zone):break
        numframes=struct.unpack_from("<H",zone,pos+14)[0]
        if not 1<=numframes<=2000 or any(value>1 for value in zone[pos+16:pos+20]) or zone[pos+36]>1:
            pos+=4;continue
        fr,frequency=struct.unpack_from("<ff",zone,pos+48)
        if not (5<=fr<=240 and math.isfinite(frequency) and abs(frequency-fr/numframes)<0.0002):
            pos+=4;continue
        en=zone.find(b"\0",pos+104,pos+224)
        if en<=pos+105 or any(not 32<=v<=126 or v in b"{}\\/%" for v in zone[pos+104:en]):
            pos+=4;continue
        name=zone[pos+104:en].decode("ascii")
        if name in names:raise ValueError(f"duplicate original XAnimParts inline name {name}")
        names.add(name)
        parts=zone[pos+24:pos+34]
        bones=parts[9]
        pointers=struct.unpack_from("<10I",zone,pos+64)
        values=struct.unpack_from("<5H",zone,pos+4)
        if pointers[0]==0xffffffff:
            indices=struct.unpack_from(f"<{bones}H",zone,en+1) if bones else ()
            if not all(i<len(scripts) and scripts[i] for i in indices):
                raise ValueError(f"Original {name} has unresolved bone ScriptString ID")
            actual_bones=[scripts[i] for i in indices]
            counters["fully_named_skeletons"]+=1
            counters["bone_name_references"]+=len(actual_bones)
        elif pointers[0]==0 and bones==0:
            indices=()
            actual_bones=[]
            counters["no_bones"]+=1
        else:raise ValueError(f"Original {name} has unknown bone pointer kind")
        # Real T5 XAnimNotifyInfo array follows the original bone-name
        # script indices, each source row exactly 8 bytes: u16 script name,
        # u16 padding, f32 normalized time. Do not align physical file bytes.
        notify_count=zone[pos+34]
        notify_pointer=pointers[8]
        after_bones=en+1+(bones*2 if pointers[0]==0xffffffff else 0)
        events=[]
        if notify_count:
            if notify_pointer!=0xffffffff:
                raise ValueError(f"Original {name} has a notify table without FOLLOWING pointer")
            for ordinal in range(notify_count):
                script_index,time=struct.unpack_from("<Hxxf",zone,after_bones+ordinal*8)
                if script_index>=len(scripts) or not math.isfinite(time) or not 0<=time<=1.001:
                    raise ValueError(f"Original {name} notify {ordinal} invalid")
                raw_name=scripts[script_index]
                if not raw_name:counters["empty_source_notetrack_names"]+=1
                events.append({
                    "source_script_id":script_index,
                    "source_name":raw_name or None,
                    "normalized_time":time,
                })
                counters["original_notetrack_events"]+=1
        elif notify_pointer!=0:
            raise ValueError(f"Original {name} has zero notify events but non-null source pointer")
        counters["inline_animation_headers"]+=1
        if name.startswith("viewmodel_"):counters["viewmodel_headers"]+=1
        entries.append({
            "source_header_offset":pos,
            "name":name,
            "numframes":numframes,
            "framerate":fr,
            "frequency":frequency,
            "loop":bool(zone[pos+16]),
            "delta":bool(zone[pos+17]),
            "bone_count":bones,
            "source_script_indices":list(indices),
            "source_bone_names":actual_bones,
            "source_notetrack_events":events,
            "source_array_pointers":list(pointers),
            "keyframes_decoded":False,
        })
        pos+=4
    if counters["inline_animation_headers"]!=2666 or counters["fully_named_skeletons"]!=2661 or counters["no_bones"]!=5 or counters["original_notetrack_events"]!=5735 or counters["empty_source_notetrack_names"]!=2:
        raise ValueError(f"Original common_mp inline XAnimParts evidence disagrees: {counters}")
    found={x["name"]:x for x in entries}
    test=found["pb_stand_bombplant"]
    if test["source_header_offset"]!=0x46e156 or test["numframes"]!=76 or test["framerate"]!=30:
        raise ValueError("Original bombplant XAnimParts source header differs")
    if test["source_bone_names"][:5]!=["j_mainroot","j_hip_le","j_hip_ri","torso_stabilizer","j_spinelower"]:
        raise ValueError("Original bombplant ScriptString bone names differ")
    if len(test["source_notetrack_events"])!=10 or test["source_notetrack_events"][0]["source_name"]!="sndnt#fly_bomb_buttons_npc" or test["source_notetrack_events"][-1]["source_name"]!="end":
        raise ValueError("Original bombplant XAnim sound/end notetrack IDs differ")
    result={
        "original_fastfile_sha256":hashlib.sha256(original).hexdigest(),
        "source_expanded_bytes":len(zone),
        "source_xasset_type4_rows":3355,
        "source_script_string_count":len(scripts),
        "exact_named_inline_headers":2666,
        "exact_original_bone_tables":2661,
        "no_bones_headers":5,
        "remaining_type4_rows_not_yet_linked":689,
        "original_bone_name_occurrences":counters["bone_name_references"],
        "source_notetrack_events":counters["original_notetrack_events"],
        "blank_source_notetrack_names":counters["empty_source_notetrack_names"],
        "source_authored_animation_headers":entries,
        "transform_samples_decoded":0,
    }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print(f"PASS source BO1 XAnimParts: {n:,} XAsset rows, 3,355 animations, "
          f"{len(entries):,} named x86 animation headers, "
          f"{counters['fully_named_skeletons']:,} fully resolved bone name tables, "
          f"{counters['bone_name_references']:,} authentic bone ScriptString references, "
          f"{counters['original_notetrack_events']:,} original sound/FX/end notetrack events, "
          f"{counters['no_bones']} bone-free clips; 689 remaining animation XAsset rows.")
    print("Original XAnimParts timing and joints VERIFIED; actual compressed keyframe arrays are NOT decoded yet.")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-ff",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args()
    verify(a.original_ff,a.report)
if __name__=="__main__":main()
