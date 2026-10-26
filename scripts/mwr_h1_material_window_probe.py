"""Research original H1 material-to-texture record serialization using real FF.

Source offsets are selected from the stream's structural Material scanner;
never hardcode map offsets, asset names, or inferred image bindings. Inspect
the immediate bytes after fixed 0x250 Material + authored inline name and
classify exact 16B MaterialTextureDef candidates conservatively.
"""
import struct
from mwr_h1_world_vertex_verify import extract_source_window
from mwr_h1_asset_body_probe import inline_xstring_candidate

INLINE=0xFDFDFDFFFFFFFFFF
MAX_PROBES=4

def pointer_kind(v):
    if v==INLINE:return "inline_owned"
    if v==0xFDFDFDFFFFFFFFFE:return "inline_shared"
    if v==0:return "null"
    if 0xFDFDFDF0<=(v>>32)<0xFDFDFDF7:return "virtual_block"
    return "unknown"

def texture_at(blob,at):
    if at<0 or at+16>len(blob):return None
    hash_value,start,end,sampler,semantic,ptr=struct.unpack_from("<IBBBBQ",blob,at)
    # A valid original semantic is a native 8-bit field; upper bytes alone
    # do not prove meaning. Require a known original source pointer form,
    # and nonzero hash, without pretending to decode a GfxImage alias.
    kind=pointer_kind(ptr)
    if kind=="unknown" or hash_value==0:return None
    return {"hash":f"{hash_value:08x}","name_first":start,
            "name_last":end,"sampler":sampler,"semantic":semantic,
            "image_or_water_source_ptr":f"{ptr:016x}","pointer_kind":kind}

def inspect_material_source_windows(ff_file,ff_header,stream_class,candidates):
    out=[]
    eligible=[
        x for x in candidates if x.get("inline_source_name_candidate") and
        x.get("texture_slots",0)>0 and
        x.get("texture_slots",0)<=32 and
        x.get("texture_table_ptr")==f"{INLINE:016x}"
    ][:MAX_PROBES]
    for entry in eligible:
        base=entry["decoded_source_offset"]
        raw=extract_source_window(ff_file,ff_header,stream_class,base,base+8192)
        source_name=inline_xstring_candidate(raw,0x250)
        if not source_name:
            out.append({"status":"no_original_material_name_after_fixed_root","source_offset":base})
            continue
        cursor=0x250+len(source_name.encode("ascii"))+1
        slots=entry["texture_slots"]
        samples=[]
        for stride_offset in range(0,513):
            current=cursor+stride_offset
            parsed=[texture_at(raw,current+16*i) for i in range(slots)]
            if all(x is not None for x in parsed):
                samples.append({"after_name_delta":stride_offset,
                    "source_texture_array_offset":base+current,
                    "texture_slots":slots,
                    "first_texture_refs":parsed[:min(slots,6)]})
                if len(samples)>=5:break
        out.append({
            "status":"source_window_structural_candidates_not_asset_relocation",
            "source_material_root":base,
            "source_material_name":source_name,
            "native_declared_texture_slots":slots,
            "source_after_inline_name":base+cursor,
            "first_48_after_material_name_hex":raw[cursor:cursor+48].hex(),
            "candidate_source_texture_table_spans":samples,
        })
    return {"status":"bounded_original_material_source_window_evidence",
            "sampled_original_material_candidates":len(eligible),
            "examples":out,
            "original_asset_name_and_image_identity_not_yet_proven":True}
