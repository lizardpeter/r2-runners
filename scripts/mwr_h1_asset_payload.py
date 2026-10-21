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


def inspect_sequential_source_files(data:bytes,verified:dict):
    """Walk original source bodies until the first unsupported H1 asset type."""
    start=verified["start_offset"]
    count=verified["verified_records"]
    cursor=verified["end_offset"]
    records=[]
    for index in range(count):
        kind=struct.unpack_from("<I",data,start+16*index)[0]
        if kind not in (48,49):
            return {"status":"stopped_at_other_asset_type","decoded_source_files":len(records),
                    "next_type":kind,"next_index":index,"next_decoded_offset":cursor,
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
