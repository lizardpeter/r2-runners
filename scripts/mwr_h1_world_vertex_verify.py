"""Bounded exact source-window verification of H1 44-byte world vertices.

Re-decompress the original signed H1 LZ4 stream into a <=128MiB RAM window,
check every 44-byte record in the same original source stride/phase, and
report complete only when consecutive records match GfxWorld.vertexCount.
"""
import math
import struct
import hashlib
import lz4.block

STRIDE=44
MiB=1024*1024
MAX_WINDOW=128*MiB

def extract_source_window(ff_file,header,stream_class,start,end):
    if not (0<=start<end and end-start<=MAX_WINDOW):
        raise ValueError("H1 source verification window exceeds 128 MiB")
    result=bytearray()
    with ff_file.open("rb") as f:
        stream=stream_class(f,header["candidate_stream_offset"])
        expected,flags=struct.unpack("<QI",stream.read(12))
        if flags!=0x04010000 or end>expected:
            raise ValueError("H1 source verification window outside signed map")
        decoded_at=0
        while decoded_at<end:
            compressed,rawlen=struct.unpack("<II",stream.read(8))
            if compressed<1 or compressed>8*MiB or rawlen<1 or rawlen>MiB:
                raise ValueError("H1 second-pass source block length invalid")
            data=lz4.block.decompress(stream.read(compressed),uncompressed_size=rawlen)
            if len(data)!=rawlen:raise ValueError("original H1 second-pass LZ4 size mismatch")
            block_end=decoded_at+rawlen
            if block_end>start and decoded_at<end:
                lo=max(start,decoded_at)-decoded_at
                hi=min(end,block_end)-decoded_at
                result.extend(data[lo:hi])
            decoded_at=block_end
            stream.align4()
    if len(result)!=end-start:
        raise ValueError(f"original source window truncated {len(result)}/{end-start}")
    return bytes(result)

def classify_original_vertex(data,at):
    if at<0 or at+STRIDE>len(data):return "outside_original_source_window"
    x,y,z,sign=struct.unpack_from("<ffff",data,at)
    if not all(math.isfinite(x) and abs(x)<2_000_000 for x in (x,y,z)):
        return "position_nonfinite_or_out_of_range"
    if not math.isfinite(sign) or abs(sign)>1.1:
        return "binormal_nonfinite_or_magnitude_gt_1.1"
    uv=struct.unpack_from("<ffff",data,at+20)
    if not all(math.isfinite(v) and abs(v)<100_000 for v in uv):
        return "uv_nonfinite_or_out_of_range"
    n,t=struct.unpack_from("<II",data,at+36)
    if n==0 and t==0:return "both_packed_normal_and_tangent_zero"
    return None

def verify_source_vertex_array(ff_file,header,stream_class,report,expected_vertices):
    candidates=report.get("longest_clusters",[])
    if not candidates or not expected_vertices:return {"status":"no_candidate"}
    selected=min(candidates,key=lambda c:abs(c["potential_vertices"]-expected_vertices))
    if selected["potential_vertices"]<expected_vertices*0.85:
        return {"status":"no_near_full_world_vertex_candidate",
                "largest_source_candidate_vertices":candidates[0]["potential_vertices"],
                "declared_world_vertices":expected_vertices}
    start=selected["start_offset"]
    end=selected["end_offset"]
    begin=max(0,start-2*MiB)
    stop=min(report["source_bytes_scanned"],end+2*MiB)
    data=extract_source_window(ff_file,header,stream_class,begin,stop)
    first=start-begin
    first_phase=first%STRIDE
    active=None
    runs=[]
    failures={}
    samples=[]
    for at in range(first_phase,len(data)-STRIDE+1,STRIDE):
        problem=classify_original_vertex(data,at)
        if problem is None:
            if active is None:active=at
        else:
            failures[problem]=failures.get(problem,0)+1
            if len(samples)<32 and start-150_000<=begin+at<=end+150_000:
                samples.append({"decoded_offset":begin+at,"reason":problem})
            if active is not None:
                runs.append((active,at))
                active=None
    if active is not None:
        end_valid=first_phase+((len(data)-STRIDE-first_phase)//STRIDE+1)*STRIDE
        runs.append((active,end_valid))
    runs.sort(key=lambda r:r[1]-r[0],reverse=True)
    major=[{"start_offset":begin+lo,"end_offset":begin+hi,
            "verified_vertex_records":(hi-lo)//STRIDE} for lo,hi in runs[:15]]
    max_records=major[0]["verified_vertex_records"] if major else 0
    exact=next((entry for entry in major if entry["verified_vertex_records"]>=expected_vertices),None)
    signature=None
    authentic_bounds=None
    if exact:
        pos=exact["start_offset"]-begin
        original=data[pos:pos+expected_vertices*STRIDE]
        if len(original)!=expected_vertices*STRIDE:
            raise ValueError("H1 complete source vertex span truncated in proof window")
        signature=hashlib.sha256(original).hexdigest()
        bounds_lo=[float("inf")]*3
        bounds_hi=[float("-inf")]*3
        for at in range(0,len(original),STRIDE):
            xyz=struct.unpack_from("<fff",original,at)
            for i,v in enumerate(xyz):
                bounds_lo[i]=min(bounds_lo[i],v)
                bounds_hi[i]=max(bounds_hi[i],v)
        authentic_bounds={"min_original_units":bounds_lo,
                           "max_original_units":bounds_hi}
    return {
        "status":"complete" if exact else "near_full_boundary_unresolved",
        "authored_gfxworld_vertex_count":expected_vertices,
        "verified_max_consecutive_records":max_records,
        "verified_fraction_of_authored":round(max_records/expected_vertices,7),
        "candidate_source_start":start,
        "candidate_source_end":end,
        "validation_window_start":begin,
        "validation_window_end":stop,
        "complete_original_vertex_sha256":signature,
        "complete_original_world_aabb":authentic_bounds,
        "complete_source_array_start":exact["start_offset"] if exact else None,
        "complete_source_array_end":exact["start_offset"]+expected_vertices*STRIDE if exact else None,
        "top_verified_contiguous_runs":major,
        "invalid_record_categories_in_phase":failures,
        "bounded_failure_samples":samples[:24],
    }
