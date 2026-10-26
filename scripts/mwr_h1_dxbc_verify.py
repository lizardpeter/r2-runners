"""Full source-window verification of sampled original H1 DXBC programs.

Unlike a four-byte signature count, this checks the exact declared container
length, complete chunk table and EVERY declared FourCC chunk inside original
LZ4-decoded retail bytes, and hashes only metadata/digest, not program bytes.
No patching, rendering, shader extraction or asset-alias shortcut.
"""
import hashlib
import struct
from mwr_h1_world_vertex_verify import extract_source_window
from mwr_h1_dxbc_probe import H1DXBCSourceScanner

MAX_PROBES=4

def verify_dxbc_container(blob):
    top=H1DXBCSourceScanner.probe(blob,0)
    if top is None:return {"status":"invalid_DXBC_header"}
    count=top["source_chunk_count"]
    size=top["declared_shader_container_bytes"]
    if len(blob)!=size:
        return {"status":"DXBC_source_body_length_mismatch"}
    offsets=struct.unpack_from("<"+str(count)+"I",blob,32)
    covered=[]
    chunk_types=[]
    for index,at in enumerate(offsets):
        if at+8>len(blob):
            return {"status":"DXBC_source_chunk_truncated","chunk_ordinal":index}
        fourcc,declared=struct.unpack_from("<4sI",blob,at)
        end=at+8+declared
        if end>len(blob) or not all(32<=v<127 for v in fourcc):
            return {"status":"DXBC_source_chunk_size_or_fourcc_invalid","chunk_ordinal":index}
        covered.append((at,end))
        chunk_types.append(fourcc.decode("ascii"))
    ordered=sorted(covered)
    for a,b in zip(ordered,ordered[1:]):
        if a[1]>b[0]:
            return {"status":"DXBC_source_chunks_overlap"}
    return {"status":"complete_original_DXBC_container_source_verified",
            "declared_container_bytes":size,
            "chunks_checked":count,
            "authored_chunk_types":chunk_types,
            "original_program_sha256":hashlib.sha256(blob).hexdigest()}

def verify_retail_dxbc_samples(ff_file,ff_header,stream_class,scan):
    candidates=scan.get("first_24_source_headers",[])
    out=[]
    for c in candidates[:MAX_PROBES]:
        at=c["source_offset"]
        size=c["declared_shader_container_bytes"]
        binary=extract_source_window(ff_file,ff_header,stream_class,at,at+size)
        record=verify_dxbc_container(binary)
        out.append({"original_source_offset":at,**record})
    return {"status":"original_source_DXBC_full_body_samples_checked",
            "sample_count":len(out),
            "sampled_full_original_shader_source_bodies":out,
            "not_a_MaterialPass_or_shader_stage_binding":True}
