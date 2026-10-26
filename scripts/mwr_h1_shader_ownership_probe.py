"""Correlate real DXBC program bytes to original H1 shader asset headers.

Candidates are anchored by FULL source-verified DXBC bytecode bodies, then
checked backwards for a native 0x20 MaterialVertex/PixelShader header,
its own inline source name and exactly matching native program byte count.
No map-specific shader names/offsets. Never dump original program bytes.
"""
import struct
from mwr_h1_world_vertex_verify import extract_source_window
from mwr_h1_dxbc_verify import verify_dxbc_container
from mwr_h1_material_window_probe import pointer_kind

INLINE=0xFDFDFDFFFFFFFFFF
MAX_LOOKBACK=8192
MAX_SAMPLES=4
MAX_NAME=1024

def source_owned_shader_candidate(blob,header_at,program_at,program_len):
    if header_at<0 or header_at+32>program_at:return None
    name_ptr,runtime_ptr,program_ptr,nbytes,crc=struct.unpack_from(
        "<QQQII",blob,header_at)
    if name_ptr!=INLINE or nbytes!=program_len:
        return None
    if pointer_kind(program_ptr)=="unknown" or program_ptr==0:
        return None
    name_bytes=blob[header_at+32:program_at]
    end=name_bytes.find(bytes([0]))
    if not 1<=end<=MAX_NAME:
        return None
    if not all(32<=v<127 for v in name_bytes[:end]):
        return None
    remaining=name_bytes[end+1:]
    if len(remaining)>16 or any(remaining):
        return None
    return {"original_shader_struct_relative":header_at,
            "original_name_candidate":name_bytes[:end].decode("ascii"),
            "source_program_pointer_form":pointer_kind(program_ptr),
            "runtime_shader_ptr":f"{runtime_ptr:016x}",
            "original_microcode_crc":f"{crc:08x}",
            "intervening_source_padding_bytes":len(remaining),
            "program_length_matches_exact_original_header":True}

def verify_dxbc_shader_ownership_windows(ff,hdr,stream_class,dxbc_scan):
    out=[]
    for entry in dxbc_scan.get("first_24_source_headers",[])[:MAX_SAMPLES]:
        offset=entry["source_offset"]
        count=entry["declared_shader_container_bytes"]
        start=max(0,offset-MAX_LOOKBACK)
        end=offset+count
        data=extract_source_window(ff,hdr,stream_class,start,end)
        base=offset-start
        dxbc=verify_dxbc_container(data[base:])
        if dxbc.get("status")!="complete_original_DXBC_container_source_verified":
            out.append({"status":"original_DXBC_container_not_source_verified",
                        "source_program_offset":offset})
            continue
        found=[]
        for at in range(max(0,base-MAX_LOOKBACK),base-31):
            candidate=source_owned_shader_candidate(data,at,base,count)
            if candidate:
                found.append({"source_shader_header_offset":start+at,
                              **{k:v for k,v in candidate.items()
                                 if k!="original_shader_struct_relative"}})
                if len(found)>=8:break
        out.append({"original_source_program_offset":offset,
                    "verified_program_bytes":count,
                    "source_header_linked_candidate_count":len(found),
                    "source_header_linked_candidates":found,
                    "source_program_digest":dxbc.get("original_program_sha256"),
                    "not_yet_MaterialPass_bound":True})
    return {"status":"real_DXBC_to_native_shader_header_source_windows",
            "source_program_samples":out}
