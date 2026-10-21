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

def verify_original_compressed_payloads(zone:bytes,entries:list[dict]):
    # T5 original zonecode serialization is:
    # name,boneIDs,notetracks,deltaPart,dataByte,dataShort,dataInt,
    # randomShort,randomByte,randomInt,frameIndices.
    # Only an independently verified NEXT inline XAnimParts source header
    # certifies a terminal offset. Do not stop at arbitrary FF FF FF FF.
    verified_source_positions={entry["source_header_offset"] for entry in entries}
    recovered=0
    payload_bytes=0
    refused=Counter()
    first_bomb=None
    for entry in entries:
        h=entry["source_header_offset"]
        counts=struct.unpack_from("<5H",zone,h+4)
        randshort=u32(zone,h+40)
        indexcount=u32(zone,h+44)
        frames=entry["numframes"]
        ptrs=entry["source_array_pointers"]
        start=(h+104+len(entry["name"])+1
               +2*len(entry["source_script_indices"])
               +8*len(entry["source_notetrack_events"]))
        if ptrs[9]==0xffffffff:
            if start+8>len(zone):raise ValueError("Original XAnimDeltaPart truncated")
            delta_pair=struct.unpack_from("<II",zone,start)
            start+=8
        elif ptrs[9]==0:delta_pair=(0,0)
        else:
            refused["unresolved_packed_delta_pointer"]+=1
            continue
        if delta_pair!=(0,0):
            refused["nested_delta_trans_or_quat"]+=1
            continue
        stream_start=start
        sizes=[
            counts[0],counts[1]*2,counts[2]*4,
            randshort*2,counts[3],counts[4]*4,
            indexcount*(1 if frames<256 else 2),
        ]
        channels={}
        for key,pointer,size in zip(
                ("byte","short","int","randomShort","randomByte","randomInt","indices"),
                ptrs[1:8],sizes):
            if pointer==0 and size==0:
                channels[key]={"source_offset":None,"source_bytes":0,"sha256":None}
            elif pointer==0xffffffff and size<=64*1024*1024:
                end=start+size
                if end>len(zone):raise ValueError("Original T5 channel extends past source FF")
                payload=zone[start:end]
                channels[key]={
                    "source_offset":start,"source_bytes":size,
                    "sha256":hashlib.sha256(payload).hexdigest(),
                }
                start=end
            else:
                refused["missing_or_unverified_source_channel_pointer"]+=1
                break
        else:
            if start not in verified_source_positions:
                refused["terminal_not_verified_original_header"]+=1
                continue
            if sum(sizes)!=start-stream_start:
                raise ValueError("Original channel source-length closure failed")
            recovered+=1
            payload_bytes+=sum(sizes)
            entry["original_raw_compressed_channels"]={
                "start":stream_start,"end":start,
                "raw_bytes":sum(sizes),"channels":channels,
                "delta_children":[0,0],
                "per_bone_transform_keyframes_decoded":False,
            }
            if entry["name"]=="pb_stand_bombplant":
                first_bomb=entry["original_raw_compressed_channels"]
    if recovered!=1686 or payload_bytes!=13468886:
        raise ValueError(f"Original source compressed arrays changed: {recovered} clips, {payload_bytes} bytes, reasons={refused}")
    if first_bomb is None or first_bomb["start"]!=0x46e2b1 or first_bomb["end"]!=0x471abe:
        raise ValueError("Original bombplant compressed stream source range does not match retail client")
    print(f"PASS authentic T5 source compressed data arrays: "
          f"{recovered} complete XAnim payloads, {payload_bytes:,} raw channel bytes, "
          f"original named bone/script/notify and six typed raw stream families validated. "
          f"Not pose-track reconstructed; {len(entries)-recovered} require nested delta or allocator replay.")
    return recovered,payload_bytes,refused

def verify_original_static_delta_translations(zone:bytes,entries:list[dict]):
    # T5 source XAnimDeltaPart: (u32 trans,u32 quat) pointers.
    # Original XAnimPartTrans size==0 has source-authored float[3] frame0.
    recovered=[]
    for entry in entries:
        pointers=entry["source_array_pointers"]
        if pointers[9]!=0xffffffff:continue
        offset=(entry["source_header_offset"]+104+len(entry["name"])+1
                +len(entry["source_script_indices"])*2
                +len(entry["source_notetrack_events"])*8)
        trans,quat=struct.unpack_from("<II",zone,offset)
        if trans!=0xffffffff:continue
        trans_at=offset+8
        size=struct.unpack_from("<H",zone,trans_at)[0]
        if size:continue
        small=zone[trans_at+2]
        if small not in (0,1):
            raise ValueError(f"Invalid source delta smallTrans for {entry['name']}")
        xyz=list(struct.unpack_from("<3f",zone,trans_at+4))
        if not all(math.isfinite(v) and abs(v)<100000 for v in xyz):
            raise ValueError(f"Original {entry['name']} nonfinite/out of source bounds delta frame0")
        # The original source-following static XAnimPartTrans is 16 bytes.
        # If a following quaternion exists, the next XAnimDeltaPartQuat
        # size==0 contains the genuine signed XQuat2 frame0 at offset +4.
        quat_pair=None
        quat_struct=None
        if quat==0xffffffff:
            quat_struct=trans_at+16
            quat_size=struct.unpack_from("<H",zone,quat_struct)[0]
            if quat_size==0:
                quat_pair=list(struct.unpack_from("<2h",zone,quat_struct+4))
        recovered.append({
            "original_static_root_quat2":quat_pair,
            "source_static_quat_struct_at":quat_struct if quat_pair is not None else None,
            "name":entry["name"],
            "source_xanim_offset":entry["source_header_offset"],
            "source_delta_at":offset,
            "source_trans_struct_at":trans_at,
            "constant_root_translation_xyz":xyz,
            "original_delta_quat_pointer":quat,
            "fully_decoded_animated_root_transform":False,
        })
    if len(recovered)!=52:raise ValueError(
        f"Original static root delta source layout changed: {len(recovered)} != 52"
    )
    known=next(x for x in recovered if
        x["name"]=="pb_standmg42gunner_aim_45right_15up")
    if known["source_trans_struct_at"]!=0xdf3d0f or any(
        abs(a-b)>0.0001 for a,b in zip(
            known["constant_root_translation_xyz"],
            (-14.1801138,2.6242592,-55.41215))
    ):
        raise ValueError("Original MG42 aim source root motion vec3 changed")
    recovered_quats=sum(x["original_static_root_quat2"] is not None for x in recovered)
    if recovered_quats!=45:
        raise ValueError(f"Original static source XQuat2 count changed: {recovered_quats}")
    if known["original_static_root_quat2"]!=[-12539,30273] or known["source_static_quat_struct_at"]!=0xdf3d1f:
        raise ValueError("Original MG42 aim source signed XQuat2 bits changed")
    print("PASS 52 exact original XAnimPartTrans size=0 frame0 root vectors, "
          "45 original signed source XQuat2 frame0 pairs, verified against "
          "authentic T5 compressed source bytes. Animated root tracks and "
          "quat axis interpretation remain unresolved.")
    return recovered

def verify_original_animated_delta_source(zone:bytes,entries:list[dict]):
    """Exact T5 source XAnimPartTrans/XAnimDeltaPartQuat inline-array layout.

    The crucial fix: XAnimPartTrans.frames.indices and
    XAnimDeltaPartQuat.frames.indices are VARIABLE-SIZE INLINED arrays.
    They are NOT second virtual pointers. Prove the full original source
    records against a separate verified next XAnimParts header.
    """
    known={entry["source_header_offset"] for entry in entries}
    real=0;animated_trans=0;animated_quat=0
    trans_small=trans_large=0
    unresolved=0;records=[]
    for item in entries:
        ptr=item["source_array_pointers"]
        if ptr[9]!=0xffffffff:continue
        h=item["source_header_offset"]
        cursor=(h+104+len(item["name"])+1
            +2*len(item["source_script_indices"])
            +8*len(item["source_notetrack_events"]))
        trans,quat=struct.unpack_from("<II",zone,cursor)
        cursor+=8
        if trans!=0xffffffff and quat!=0xffffffff:continue
        result={"name":item["name"],"header_offset":h,
                "source_delta_pointer_pair":[trans,quat],
                "source_quantized_root_translation":None,
                "source_signed_root_quat2":None}
        good=True
        for typ,pointer in (("trans",trans),("quat",quat)):
            if pointer==0:continue
            if pointer!=0xffffffff:
                good=False;break
            offset=cursor
            size=struct.unpack_from("<H",zone,cursor)[0]
            if size==0:
                cursor+=16 if typ=="trans" else 8
                continue
            if size>4095:
                good=False;break
            count=size+1
            small=zone[cursor+2] if typ=="trans" else 0
            if typ=="trans":
                if small not in (0,1) or struct.unpack_from("<I",zone,cursor+28)[0]!=0xffffffff:
                    good=False;break
                mins=struct.unpack_from("<3f",zone,cursor+4)
                scales=struct.unpack_from("<3f",zone,cursor+16)
                if not all(math.isfinite(v) for v in mins+scales):
                    good=False;break
                cursor+=32
            else:
                if struct.unpack_from("<I",zone,cursor+4)[0]!=0xffffffff:
                    good=False;break
                cursor+=8
            width=1 if item["numframes"]<256 else 2
            fmt="<"+("B" if width==1 else "H")*count
            indices=list(struct.unpack_from(fmt,zone,cursor))
            cursor+=count*width
            if max(indices)>item["numframes"] or indices!=sorted(indices):
                good=False;break
            if typ=="trans":
                nbytes=count*(3 if small else 6)
                frames=zone[cursor:cursor+nbytes]
                cursor+=nbytes
                values=[list(frames[i:i+3]) if small
                         else list(struct.unpack_from("<3H",frames,i))
                        for i in range(0,nbytes,3 if small else 6)]
                decoded=[[mins[j]+scales[j]*frame[j] for j in range(3)]
                         for frame in values]
                if not all(math.isfinite(v) for frame in decoded for v in frame):
                    raise ValueError(f"{item['name']} has nonfinite decoded source XYZ")
                result["source_quantized_root_translation"]={
                    "original_struct_offset":offset,
                    "source_min_xyz":mins,"source_scale_xyz":scales,
                    "source_frame_numbers":indices,
                    "original_small_encoding":bool(small),
                    "source_quantized_xyz":values,
                    "source_decoded_xyz":decoded,
                    "original_frame_bytes_sha256":hashlib.sha256(frames).hexdigest(),
                }
            else:
                nbytes=count*4
                frames=zone[cursor:cursor+nbytes]
                cursor+=nbytes
                result["source_signed_root_quat2"]={
                    "original_struct_offset":offset,
                    "source_frame_numbers":indices,
                    "original_signed_quat_pairs":[list(struct.unpack_from("<2h",frames,i))
                                                  for i in range(0,nbytes,4)],
                    "original_frame_bytes_sha256":hashlib.sha256(frames).hexdigest(),
                }
        if not good:
            unresolved+=1
            continue
        counts=struct.unpack_from("<5H",zone,h+4)
        shortcount=u32(zone,h+40);indexcount=u32(zone,h+44)
        sizes=[counts[0],counts[1]*2,counts[2]*4,shortcount*2,
               counts[3],counts[4]*4,indexcount*(1 if item["numframes"]<256 else 2)]
        ranges=[]
        for pointer,amount in zip(ptr[1:8],sizes):
            if pointer==0 and amount==0:
                ranges.append([cursor,0])
            elif pointer==0xffffffff and amount<=64*1024*1024:
                ranges.append([cursor,amount]);cursor+=amount
            else:
                good=False;break
        if not good or cursor not in known:
            unresolved+=1
            continue
        result["original_other_channel_ranges"]=ranges
        result["exact_next_header_offset"]=cursor
        records.append(result);real+=1
        if result["source_quantized_root_translation"]:
            animated_trans+=1
            if result["source_quantized_root_translation"]["original_small_encoding"]:
                trans_small+=1
            else:trans_large+=1
        if result["source_signed_root_quat2"]:
            animated_quat+=1
    if (real,animated_trans,animated_quat,unresolved)!=(365,265,96,18):
        raise ValueError("Original animated delta closure differs: "
                         f"{real} complete, {animated_trans} trans, {animated_quat} quat, "
                         f"{unresolved} partial")
    sample=next(x for x in records if x["name"]=="p_handheldradio_idle")
    expected=sample["source_quantized_root_translation"]
    if sample["header_offset"]!=0x4ae8e2 or expected["source_frame_numbers"]!=[0,17,133] or \
       expected["source_quantized_xyz"]!=[[251,255,0],[0,19,0],[0,19,0]] or \
       abs(expected["source_decoded_xyz"][0][0]+0.00002810717)>1e-6 or \
       abs(expected["source_decoded_xyz"][1][0]+0.096187487)>1e-6 or \
       sample["exact_next_header_offset"]!=0x4b6e7f:
        raise ValueError("Authentic p_handheldradio_idle compact root track bytes differ")
    print(f"PASS original BO1 nested root deltas: {real} fully source-closed clips, "
          f"{animated_trans} animated translated XYZ tracks ({trans_small} small, "
          f"{trans_large} large), {animated_quat} animated signed XQuat2 tracks; "
          f"{unresolved} still unclosed. The inline original frame indices are "
          "NOT wrongly treated as virtual pointers.")
    return records

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
    decoded_streams,decoded_bytes,stream_limitations=verify_original_compressed_payloads(zone,entries)
    static_root_deltas=verify_original_static_delta_translations(zone,entries)
    nested_delta_clips=verify_original_animated_delta_source(zone,entries)
    result={
        "original_fully_closed_nested_delta_clips":len(nested_delta_clips),
        "original_animated_delta_clip_evidence":nested_delta_clips,
        "original_total_source_closed_animation_streams":decoded_streams+len(nested_delta_clips),
        "original_constant_root_translations":static_root_deltas,
        "original_static_root_vector_count":len(static_root_deltas),
        "original_source_compressed_streams_decoded":decoded_streams,
        "original_source_compressed_stream_bytes":decoded_bytes,
        "original_source_stream_replay_limitations":dict(stream_limitations),
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
