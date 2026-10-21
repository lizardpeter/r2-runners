"""Source-verified H1 RawFile and ScriptFile byte decoding (not synthetic).

Decodes exact retail inline source bytes in memory. Reports authenticated
names, original/decompressed lengths, and SHA-256 values only. Raw scripts,
bytecode, and proprietary source files stay in runner-local memory.
"""
import hashlib
import struct
import zlib
MARKER=0xFDFDFDFFFFFFFFFF
MAX_PAYLOAD_BYTES=128*1024*1024
MAX_SOURCE_NAME_BYTES=2048


def inline_name(data:bytes,at:int):
    end=data.find(b"\0",at,min(len(data),at+MAX_SOURCE_NAME_BYTES+1))
    if end<0:
        raise ValueError(f"unterminated H1 asset name at decoded offset {at}")
    return data[at:end].decode("utf-8"),end+1


def u64(data,at):
    return struct.unpack_from("<Q",data,at)[0]


def bounded_slice(data:bytes,start:int,length:int,what:str):
    if length<0 or length>MAX_PAYLOAD_BYTES or start<0 or start+length>len(data):
        raise ValueError(f"{what} does not fit retained authentic decoded source")
    return data[start:start+length]


def zlib_source(packed:bytes,expected:int):
    raw=zlib.decompress(packed)
    if len(raw)!=expected:
        raise ValueError(f"zlib size {len(raw)} != H1 source-declared {expected}")
    return raw


def read_source_payload(data:bytes,kind:int,at:int):
    if kind==59:
        # H1 NetConstStrings: ptr name, u32 stringType, u32 sourceType,
        # u32 entryCount, u32 native padding, ptr stringList = 0x20.
        if at+32>len(data):raise ValueError("truncated H1 NetConstStrings")
        ptr,kind_id,source_id,count,pad,names_ptr=struct.unpack_from("<QIIIIQ",data,at)
        if ptr!=MARKER or pad!=0:
            raise ValueError("invalid H1 NetConstStrings source name/padding")
        name,cursor=inline_name(data,at+32)
        names=[]
        if count:
            if count>32768 or names_ptr!=MARKER:
                raise ValueError(f"H1 NetConstStrings invalid source pointer/count: {name} ({count} entries)")
            if cursor+8*count>len(data):
                raise ValueError(f"H1 NetConstStrings source list truncated: {name}")
            slots=[u64(data,cursor+8*i) for i in range(count)]
            cursor+=8*count
            for index,pointer in enumerate(slots):
                if pointer==0:
                    names.append(None)
                elif pointer==MARKER:
                    value,cursor=inline_name(data,cursor)
                    names.append(value)
                else:
                    raise ValueError(f"H1 NetConstStrings unsupported string slot {index} {pointer:#x}")
        elif names_ptr!=0:
            raise ValueError(f"H1 NetConstStrings empty list has non-null pointer: {name}")
        return cursor,{
            "kind":"NetConstStrings","name":name,
            "source_type":source_id,"string_type":kind_id,
            "entry_count":count,"recovered_strings":len(names),
            "inline_strings_sha256":hashlib.sha256(
                b"".join((x.encode("utf-8")+b"\0") if x is not None else b"\xff" for x in names)
            ).hexdigest(),
            "first_strings":names[:8],
        }
    if kind==49:
        # Original H1 ScriptFile: name, compressedLen, len, bytecodeLen,
        # native padding, char* source buffer, char* compiled bytecode
        if at+40>len(data):
            raise ValueError("truncated H1 ScriptFile structure")
        name_ptr,compressed,original,bytecode_len,pad,buffer_ptr,code_ptr=struct.unpack_from("<QIIIIQQ",data,at)
        if name_ptr!=MARKER:
            raise ValueError("H1 ScriptFile name pointer not inline")
        if pad!=0:
            raise ValueError(f"H1 ScriptFile nonzero padding {pad:#x}")
        if compressed>MAX_PAYLOAD_BYTES or original>MAX_PAYLOAD_BYTES or bytecode_len>MAX_PAYLOAD_BYTES:
            raise ValueError("unbounded H1 ScriptFile payload length")
        cursor=at+40
        name,cursor=inline_name(data,cursor)
        source=b""
        if buffer_ptr==MARKER:
            count=compressed if compressed else original
            packed=bounded_slice(data,cursor,count,"H1 ScriptFile source buffer")
            source=zlib_source(packed,original) if compressed else packed
            cursor+=count
        elif buffer_ptr!=0:
            raise ValueError(f"H1 ScriptFile unsupported source buffer tag {buffer_ptr:#x}")
        bytecode=b""
        if code_ptr==MARKER:
            bytecode=bounded_slice(data,cursor,bytecode_len,"H1 ScriptFile bytecode")
            cursor+=bytecode_len
        elif code_ptr!=0:
            raise ValueError(f"H1 ScriptFile unsupported bytecode pointer tag {code_ptr:#x}")
        return cursor,{
            "kind":"ScriptFile","name":name,"source_length":len(source),
            "original_length_field":original,"compressed_length_field":compressed,
            "bytecode_length_field":bytecode_len,
            "zlib_verified":bool(compressed),
            "source_sha256":hashlib.sha256(source).hexdigest(),
            "bytecode_sha256":hashlib.sha256(bytecode).hexdigest(),
        }
    if kind==48:
        # Original H1 RawFile: name, compressedLen, len, source buffer
        if at+24>len(data):
            raise ValueError("truncated H1 RawFile structure")
        name_ptr,compressed,original,buffer_ptr=struct.unpack_from("<QIIQ",data,at)
        if name_ptr!=MARKER:
            raise ValueError("H1 RawFile name pointer not inline")
        if compressed>MAX_PAYLOAD_BYTES or original>MAX_PAYLOAD_BYTES:
            raise ValueError("unbounded H1 RawFile payload")
        name,cursor=inline_name(data,at+24)
        raw=b""
        if buffer_ptr==MARKER:
            count=compressed if compressed else original
            packed=bounded_slice(data,cursor,count,"H1 RawFile buffer")
            raw=zlib_source(packed,original) if compressed else packed
            cursor+=count
        elif buffer_ptr!=0:
            raise ValueError(f"H1 RawFile source pointer unsupported: {buffer_ptr:#x}")
        return cursor,{
            "kind":"RawFile","name":name,"source_length":len(raw),
            "original_length_field":original,"compressed_length_field":compressed,
            "source_sha256":hashlib.sha256(raw).hexdigest(),
        }
    raise ValueError(f"body decoder for H1 source asset type {kind} is not implemented")


def analyze_first_source_body(data:bytes,verified:dict):
    types=verified.get("first_16_asset_types",[])
    if not types or types[0] not in (48,49):
        return {"status":"not_supported_first_type","first_type_id":types[0] if types else None}
    cursor=verified["end_offset"]
    try:
        end,entry=read_source_payload(data,types[0],cursor)
        return {"status":"first_body_verified","start":cursor,"end":end,"entry":entry,
                "next_32_hex":data[end:end+32].hex(" ")}
    except Exception as exc:
        return {"status":"failure","reason":str(exc)}




def inspect_addon_map_ents_prefix(data:bytes,at:int)->dict:
    """Read only source-verified fixed AddonMapEnts header/name/entity text.

    The 0x88-byte C++ struct has nested trigger, brush and collision arrays.
    Those arrays have NOT been relocated by this function. Consequently the
    returned entity-text end is not claimed to be the next asset boundary.
    """
    size=0x88
    if at+size>len(data):
        raise ValueError("H1 AddonMapEnts fixed header truncated")
    name_ptr,entity_ptr,declared=struct.unpack_from("<QQI",data,at)
    if name_ptr!=MARKER or entity_ptr not in (0,MARKER):
        raise ValueError("unsupported original AddonMapEnts pointer tags")
    if declared>MAX_PAYLOAD_BYTES:
        raise ValueError("oversized H1 AddonMapEnts source entity text")
    name,cursor=inline_name(data,at+size)
    entity=b""
    if entity_ptr==MARKER:
        entity=bounded_slice(data,cursor,declared,"H1 authored map entity bytes")
        cursor+=declared
    # Report nonsemantic string structure only, not interpretations of
    # numeric entity keys (which require the H1 key-to-name dictionary).
    return {
        "status":"entity_text_verified_nested_payload_not_yet_followed",
        "name":name,"declared_entity_bytes":declared,"extracted_entity_bytes":len(entity),
        "entity_sha256":hashlib.sha256(entity).hexdigest(),
        "worldspawn_ascii_occurrences":entity.count(b"worldspawn"),
        "open_brace_count":entity.count(b"{"),
        "close_brace_count":entity.count(b"}"),
        "entity_text_end_offset":cursor,
        "nested_trigger_and_collision_data_decoded":False,
        "next_bytes_hex":data[cursor:cursor+64].hex(" "),
    }

def inspect_sequential_source_files(data:bytes,verified:dict):
    """Walk original source bodies until the first unsupported H1 asset type."""
    start=verified["start_offset"]
    count=verified["verified_records"]
    cursor=verified["end_offset"]
    records=[]
    for index in range(count):
        kind=struct.unpack_from("<I",data,start+16*index)[0]
        if kind not in (48,49,59):
            addon=inspect_addon_map_ents_prefix(data,cursor) if kind==58 else None
            return {"status":"stopped_at_other_asset_type","decoded_source_files":len(records),
                    "addon_map_ents_preview":addon,
                    "next_type":kind,"next_index":index,"next_decoded_offset":cursor,
                    "next_body_prefix_hex":data[cursor:cursor+240].hex(" "),
                    "next_body_u64":[f"{u64(data,off):016x}" for off in
                      range(cursor,min(cursor+8*22,len(data)-7),8)],
                    "verified_files":records}
        try:
            end,decoded=read_source_payload(data,kind,cursor)
            if end<=cursor:
                raise ValueError("source decoder did not advance")
            records.append({"record_index":index,"decoded_start":cursor,"decoded_end":end,**decoded})
            cursor=end
        except Exception as exc:
            return {"status":"failed","decoded_source_files":len(records),
                    "failed_type":kind,"failed_index":index,"failed_offset":cursor,
                    "reason":str(exc),"verified_files":records}
    return {"status":"all_source_files_decoded","decoded_source_files":len(records),
            "verified_files":records,"next_decoded_offset":cursor}
