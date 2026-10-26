"""Source-order H1 ComWorld light-array research after authenticated asset 59.

Only inspect exact source-owned counts/pointers and typed 144-byte
ComPrimaryLight / 10-byte ComPrimaryLightEnv records. Report continuation
boundaries as candidates until next XAsset is independently authenticated.
"""
import math
import struct
from collections import Counter

INLINE=0xFDFDFDFFFFFFFFFF
LIGHT_BYTES=144
ENV_BYTES=10

def inline_name(raw,at):
    if at<0 or at>=len(raw):raise ValueError("H1 ComWorld name out of source")
    last=raw.find(b"\0",at,min(at+4097,len(raw)))
    if last<at+1:raise ValueError("H1 ComWorld name missing bounded source UTF-8")
    return raw[at:last].decode("utf-8"),last+1

def inspect_next_gfximage_at_cursor(raw,at):
    """Type-16 source-body candidate at the proven ComWorld end, no scanning."""
    if at<0 or at+0x68>len(raw):
        return {"status":"truncated_exact_source_cursor"}
    b=raw[at:at+0x68]
    name_ptr=struct.unpack_from("<Q",b,96)[0]
    format=struct.unpack_from("<I",b,24)[0]
    width,height,depth,elements=struct.unpack_from("<4H",b,44)
    mips,streamed=b[52],b[53]
    first_name=raw.find(b"\\x00",at+0x68,min(len(raw),at+0x68+257))
    name=None
    if name_ptr==INLINE and first_name>=at+0x68+1:
        candidate=raw[at+0x68:first_name]
        if all(32<=v<127 for v in candidate):
            name=candidate.decode("ascii")
    return {
        "status":"source_cursor_candidate_not_yet_asset_body_owned",
        "decoded_source_offset":at,
        "dxgi_format":format,"map_type":b[28],
        "dimensions":[width,height,depth,elements],
        "mip_levels":mips,"streamed":streamed,
        "name_ptr":f"{name_ptr:016x}",
        "inline_name_candidate":name,
        "fixed_header_hex":b[:0x68].hex(),
    }


def inspect_comworld_after_prefix(raw,decoded_cursor):
    at=decoded_cursor
    if at+40>len(raw):
        return {"status":"H1_original_ComWorld_header_truncated"}
    name_ptr,in_use,lights_count,lights_ptr,env_count,reserved,env_ptr=struct.unpack_from(
        "<QIIQIIQ",raw,at)
    if name_ptr!=INLINE or lights_count>8192 or env_count>65536 or reserved!=0:
        return {"status":"H1_original_ComWorld_source_header_not_supported"}
    try:
        name,cursor=inline_name(raw,at+40)
    except (UnicodeError,ValueError) as exc:
        return {"status":"H1_original_ComWorld_name_not_decoded","error":str(exc)}
    report={"status":"H1_original_ComWorld_header_verified_lights_unresolved",
            "source_root":at,"original_name":name,
            "is_in_use":in_use,"source_primary_light_count":lights_count,
            "source_light_env_count":env_count,"source_after_name":cursor,
            "light_array_pointer":f"{lights_ptr:016x}",
            "light_env_array_pointer":f"{env_ptr:016x}"}
    if lights_count==0:
        return report
    if lights_ptr!=INLINE:
        report["light_status"]="light_source_array_not_inline"
        return report
    end=cursor+lights_count*LIGHT_BYTES
    if end>len(raw):
        report["light_status"]="original_light_records_outside_source_prefix"
        return report
    kind=Counter()
    names=Counter()
    bad=[]
    candidates=[]
    for i in range(lights_count):
        off=cursor+i*LIGHT_BYTES
        light_type=raw[off]
        color=struct.unpack_from("<3f",raw,off+8)
        direction=struct.unpack_from("<3f",raw,off+20)
        origin=struct.unpack_from("<3f",raw,off+44)
        ptr=struct.unpack_from("<Q",raw,off+136)[0]
        light_valid=(light_type<=8 and all(math.isfinite(x) and abs(x)<2_000_000
                     for x in (*color,*direction,*origin)))
        if not light_valid:
            if len(bad)<8:bad.append(i)
        kind[light_type]+=1
        names["null" if ptr==0 else "inline" if ptr==INLINE else
              "tagged" if ptr>>48==0xFDFD else "unsupported"]+=1
        if i<4:
            candidates.append({"source_light_ordinal":i,"type":light_type,
                               "original_color":color,
                               "original_origin":origin,
                               "def_name_pointer":f"{ptr:016x}"})
    report.update({"light_status":"all_source_light_record_fields_structural"
                       if not bad else "some_light_source_fields_invalid",
                   "typed_light_array_end":end,
                   "typed_light_status_counts":dict(kind),
                   "original_light_name_pointer_forms":dict(names),
                   "first_invalid_light_ordinals":bad,
                   "bounded_original_light_samples":candidates})
    # H1 serializers may emit light names after the array, but preserve the
    # distinction between known tagged references and actual inline strings.
    cursor=end
    for i in range(lights_count):
        ptr=struct.unpack_from("<Q",raw,report["source_after_name"]+
                               i*LIGHT_BYTES+136)[0]
        if ptr==INLINE:
            try:
                _,cursor=inline_name(raw,cursor)
            except (UnicodeError,ValueError) as exc:
                report["light_name_decode_error"]=str(exc)
                return report
        elif ptr not in (0,) and ptr>>48!=0xFDFD:
            report["light_name_decode_error"]="unsupported source defName tag"
            return report
    report["light_after_name_candidate"]=cursor
    if env_ptr!=INLINE:
        report["env_status"]="original_light_env_array_not_inline"
        return report
    final=cursor+env_count*ENV_BYTES
    if final>len(raw):
        report["env_status"]="original_light_env_records_truncated"
        return report
    valid=0
    problems=[]
    for i in range(env_count):
        at=cursor+i*ENV_BYTES
        indices=struct.unpack_from("<4H",raw,at)
        n=raw[at+8]
        if n<=4 and all(ind<lights_count for ind in indices[:n]):
            valid+=1
        elif len(problems)<8:problems.append({
            "original_light_environment":i,"num_indices":n,
            "source_indices":indices})
    report["env_status"]=("complete_original_light_environment_records"
                          if valid==env_count else "invalid_light_environment_reference_indices")
    report["light_env_records_verified"]=valid
    report["next_source_asset_candidate_cursor"]=final
    # The original XAssetList says the next body is type 16 GfxImage.
    # Inspect its exact source-order cursor rather than a signature hit.
    # Do not advance past any nested records unless the loader confirms it.
    report["next_image_source_order_probe"]=inspect_next_gfximage_at_cursor(raw,final)
    report["invalid_light_environment_samples"]=problems
    return report
