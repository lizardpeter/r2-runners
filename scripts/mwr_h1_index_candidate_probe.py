"""Probe the candidate H1 GfxWorldDraw index stream after verified vertices.

The GfxWorldDraw layout serializes vertex data, vertex-layer bytes and
u16 indices in that order. Their physical source offsets still require
loader confirmation. We check source-derived candidate offsets with
bounded samples. This reports a HYPOTHESIS until indexed GfxSurface
ranges can validate every triangle.
"""
from mwr_h1_world_vertex_verify import extract_source_window
import struct
MiB=1024*1024

def probe_original_index_array(ff_path,ff_header,stream_class,vertex_verified,world_root):
    if vertex_verified.get("status")!="complete":
        return {"status":"source_vertex_array_incomplete"}
    indices=int(world_root["index_count"])
    layer_bytes=int(world_root.get("vertex_layer_bytes",0))
    vertex_end=int(vertex_verified["complete_source_array_end"])
    guess=vertex_end+layer_bytes
    byte_count=indices*2
    if byte_count<=0 or byte_count>128*MiB:
        return {"status":"invalid_original_index_count"}
    begin=max(0,guess-4096)
    end=guess+byte_count+4096
    decoded=extract_source_window(ff_path,ff_header,stream_class,begin,end)
    # For a source-local triangle-index array, low 10-bit values should be
    # common. Check at the beginning, middle and end; other byte content,
    # including zero padding, should not automatically be accepted.
    scans=[]
    for delta in range(-256,257,2):
        at=guess+delta
        vals=[]
        for relative in (0,byte_count//2,byte_count-16384):
            local=(at+relative)-begin
            if local<0 or local+8192>len(decoded):
                continue
            vals.extend(struct.unpack_from("<4096H",decoded,local))
        if not vals:continue
        low1024=sum(x<1024 for x in vals)/len(vals)
        low4096=sum(x<4096 for x in vals)/len(vals)
        zero=sum(x==0 for x in vals)/len(vals)
        diverse=len(set(vals))
        score=low1024+0.2*low4096-0.05*zero
        scans.append((score,{
            "candidate_original_index_byte_start":at,
            "candidate_delta_from_vertex_plus_layer":delta,
            "sample_u16_count":len(vals),
            "sample_less_than_1024":round(low1024,5),
            "sample_less_than_4096":round(low4096,5),
            "sample_zero":round(zero,5),
            "sample_unique_values":diverse,
        }))
    scans.sort(key=lambda x:x[0],reverse=True)
    return {
        "status":"source_order_candidate_only_not_index_buffer_certification",
        "world_index_count_source_header":indices,
        "expected_u16_bytes":byte_count,
        "verified_vertex_array_end":vertex_end,
        "original_vertex_layer_bytes":layer_bytes,
        "candidate_byte_offset_before_padding":guess,
        "top_candidate_scores":[entry for _,entry in scans[:10]],
        "exact_source_surface_index_linkage_verified":False,
    }
