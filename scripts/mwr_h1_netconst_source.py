"""Walk authentic H1 XAssetList type-59 NetConstStrings bodies in order.

This is a source-cursor proof experiment, not a hardcoded map offset.
Starts at the end of a fully verified XAsset directory, reads native 32-byte
NetConstStrings records, inline original XStrings and indexed string arrays.
Stops without guessing whenever a different pointer format is encountered.
"""
import struct
from mwr_h1_comworld_probe import inspect_comworld_after_prefix

INLINE=0xFDFDFDFFFFFFFFFF
MAX_TEXT=4096
MAX_STRINGS=4096
MAX_ASSETS=100000

def cstring(raw,at):
    if at<0 or at>=len(raw):
        raise ValueError("original H1 inline string outside decompressed prefix")
    end=raw.find(b"\x00",at,min(len(raw),at+MAX_TEXT+1))
    if end<0:
        raise ValueError("original H1 source string has no bounded terminator")
    value=raw[at:end].decode("utf-8")
    if not value or any(ord(c)<32 for c in value):
        raise ValueError("H1 NetConstStrings inline name not valid printable source UTF-8")
    return value,end+1

def inspect_ordered_netconst_bodies(raw,verified):
    source=verified.get("validated_tables") or []
    if verified.get("status")!="fully_verified" or len(source)!=1:
        return {"status":"no_single_verified_source_xasset_array"}
    record=source[0]
    cursor=record["end_offset"]
    types=record.get("asset_type_runs") or []
    if not types or types[0]["type_id"]!=59:
        return {"status":"first_source_asset_not_netconststrings"}
    wanted=types[0]["count"]
    if not 1<=wanted<=MAX_ASSETS:
        return {"status":"invalid_original_type59_run_count"}
    records=[]
    for i in range(wanted):
        before=cursor
        try:
            if cursor+32>len(raw):
                raise ValueError("H1 NetConstStrings root outside decoded source")
            name_ptr,string_type,source_type,count,pad,list_ptr=struct.unpack_from(
                "<QIIIIQ",raw,cursor)
            if name_ptr!=INLINE or pad!=0 or count>MAX_STRINGS:
                raise ValueError("H1 source NetConstStrings header tag/count/padding unsupported")
            cursor+=32
            name,cursor=cstring(raw,cursor)
            strings=[]
            if count:
                if list_ptr!=INLINE:
                    raise ValueError("H1 original NetConstStrings entry array is not inline")
                end=cursor+count*8
                if end>len(raw):
                    raise ValueError("H1 original NetConstStrings source string array truncated")
                pointers=struct.unpack_from("<"+"Q"*count,raw,cursor)
                cursor=end
                for j,ptr in enumerate(pointers):
                    if ptr==0:
                        strings.append(None)
                    elif ptr==INLINE:
                        value,cursor=cstring(raw,cursor)
                        strings.append(value)
                    else:
                        raise ValueError(f"unsupported H1 source string list pointer {j}:{ptr:#x}")
            elif list_ptr!=0:
                raise ValueError("H1 NetConstStrings zero-count list pointer not null")
            records.append({"original_asset_index":i,
                            "source_offset":before,
                            "name":name,
                            "string_type":string_type,
                            "source_type":source_type,
                            "entry_count":count,
                            "source_strings_seen":len(strings),
                            "first_5_source_values":strings[:5],
                            "source_end":cursor})
        except (ValueError,UnicodeError,struct.error) as exc:
            return {"status":"stopped_on_unresolved_source_asset_body",
                    "verified_bodies":len(records),"expected_first_run":wanted,
                    "failed_asset_index":i,"failed_cursor":before,
                    "reason":str(exc),
                    "first_source_bodies":records[:8]}
    next_asset=root_next=types[1]["type_id"] if len(types)>1 else None
    next_header=None
    if next_asset==25 and cursor+40<=len(raw):
        try:
            # Native H1 ComWorld (0x28) is the next XAsset after this
            # original source-driven NetConstStrings run.
            ptr,is_in_use,light_count,lights_ptr,env_count,pad,env_ptr=struct.unpack_from(
                "<QIIQIIQ",raw,cursor)
            name=None
            if ptr==INLINE:
                name,_=cstring(raw,cursor+40)
            next_header={
                "nested_light_source_probe":inspect_comworld_after_prefix(raw,cursor),
                "next_type":25,"decoded_source_offset":cursor,
                "header_name_inline":ptr==INLINE,"name":name,
                "is_in_use":is_in_use,"light_count":light_count,
                "light_array_ptr":f"{lights_ptr:016x}",
                "light_env_count":env_count,"padding":pad,
                "light_env_ptr":f"{env_ptr:016x}",
                "status":"fixed_header_candidate_only_no_nested_array_walk",
            }
        except (ValueError,UnicodeError,struct.error) as e:
            next_header={"status":"unsupported_authored_comworld_header","reason":str(e)}
    return {"status":"complete_authored_netconststrings_run",
            "next_asset_source_header":next_header,
            "original_record_count":wanted,
            "start":record["end_offset"],"source_body_end":cursor,
            "source_bodies":records[:24],
            "other_asset_bodies_not_claimed":True}
