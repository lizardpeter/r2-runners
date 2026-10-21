"""Resolve original H1 GfxWorld u16 index byte spans via EVERY GfxSurface.

The source world header supplies vertexCount/indexCount/surfaceCount. Two
independently certified arrays supply exact 44-byte vertices and 40-byte
GfxSurface records. The index buffer is ACCEPTED only if every surface's
triCount*3 u16 indices lies in that surface's original vertexCount, and
all source-authored baseIndex offsets cover the declared index count.
No game-map-specific byte positions or guessed triangles are used.
"""
import hashlib
import re
import struct
from mwr_h1_world_vertex_verify import extract_source_window

def parse_surface_constraints(b,at,count):
    constraints=[]
    expected=0
    for i in range(count):
        off=at+i*40
        first=struct.unpack_from("<I",b,off+4)[0]
        vcount,tri=struct.unpack_from("<HH",b,off+16)
        base=struct.unpack_from("<I",b,off+20)[0]
        constraints.append((base,tri*3,vcount,first))
        expected+=tri*3
    return constraints,expected

def inspect_candidate_indices(data,at,constraints,limit,full=False):
    if at<0 or at+limit*2>len(data):return None
    # H1 indices are LOCAL to their source GfxSurface, NOT globally
    # indexable world-vertex ordinals.
    nondegenerate=0
    inspected=0
    max_local=0
    seq=constraints if full else constraints[::max(1,len(constraints)//96)]
    if not full:
        seq=[*constraints[:4],*seq,*constraints[-4:]]
    for base,n,vertex_count,_ in seq:
        if n<=0 or vertex_count<=0:return None
        pos=at+base*2
        row=struct.unpack_from("<"+str(n if full else min(12,n))+"H",data,pos)
        if any(value>=vertex_count for value in row):return None
        if full:
            max_local=max(max_local,max(row))
            for i in range(0,n,3):
                a,b,c=row[i:i+3]
                if a!=b and b!=c and c!=a:nondegenerate+=1
                inspected+=1
    if full and inspected>0 and nondegenerate<inspected//2:return None
    return {"nondegenerate_triangles":nondegenerate,
            "total_triangles_checked":inspected,
            "maximum_local_index":max_local}

def verify_original_index_bytes(ff_file,ff_header,stream_class,world,verts,surfs):
    if verts.get("status")!="complete" or surfs.get("status")!="complete_original_surface_struct_array_verified":
        return {"status":"missing_full_verified_source_geometry"}
    source_begin=verts["complete_source_array_end"]
    surf_start=surfs["complete_source_surface_start"]
    surf_end=surfs["complete_source_surface_end"]
    index_count=world["index_count"]
    byte_count=index_count*2
    if not(source_begin+byte_count<=surf_start and surf_end-source_begin<=128*1024*1024):
        return {"status":"source_order_does_not_contain_complete_index_array"}
    # Retain original decompressed bytes in runner RAM ONLY (about 24MiB).
    data=extract_source_window(ff_file,ff_header,stream_class,source_begin,surf_end)
    surf_at=surf_start-source_begin
    constraints,total=parse_surface_constraints(data,surf_at,world["surface_count"])
    if total!=index_count:return {"status":"original_surface_index_sum_not_closed"}
    # Retail first surface: 56 local vertices, 51 triangles. Match SIX u16
    # entries below first surface's source vertexCount to seed a candidate,
    # then validate first/last surfaces and 100 distributed surfaces.
    base0,n0,vc0,_=constraints[0]
    seed_limit=min(vc0,256)
    max_start=surf_at-byte_count
    if seed_limit<3 or max_start<0:
        return {"status":"no_source_index_seed"}
    bounded=bytes(data[:max_start])
    # Little-endian small u16s: low byte under source vcount, high byte zero.
    pat=re.compile(b"(?:[\\x00-\\x"+f"{seed_limit-1:02x}".encode()+b"]\\x00){6}")
    checked=set()
    passed=[]
    seed_matches=0
    stage1=0
    stage2=0
    for hit in pat.finditer(bounded):
        seed_matches+=1
        # The C regex finds non-overlapping windows. Include earlier/later
        # local phases so the true original source starting byte is not lost.
        for delta in range(-12,13):
            at=hit.start()+delta-base0*2
            if at in checked or at<0 or at>max_start:continue
            checked.add(at)
            # First 3 authentic surface records have especially tight
            # vertexCount bounds and ordered baseIndex spans.
            good=True
            for base,n,vc,_ in constraints[:3]:
                if at+(base+n)*2>len(data):
                    good=False;break
                row=struct.unpack_from("<"+str(n)+"H",data,at+base*2)
                if any(x>=vc for x in row):
                    good=False;break
                if base==base0 and len(set(row))<min(3,vc):
                    good=False;break
            if not good:continue
            stage1+=1
            broad=inspect_candidate_indices(data,at,constraints,index_count,full=False)
            if broad is None:continue
            stage2+=1
            exact=inspect_candidate_indices(data,at,constraints,index_count,full=True)
            if exact is None:continue
            blob=data[at:at+byte_count]
            passed.append({
                "decoded_index_start":source_begin+at,
                "decoded_index_end":source_begin+at+byte_count,
                "authored_u16_indices_verified":index_count,
                "source_index_sha256":hashlib.sha256(blob).hexdigest(),
                **exact
            })
            if len(passed)>1:
                return {"status":"ambiguous_source_index_buffer","matches":passed[:2]}
        if len(checked)>1_500_000:
            return {"status":"too_many_unresolved_source_index_seeds",
                    "seed_matches":seed_matches,"positions_checked":len(checked)}
    return {
        "status":"complete_original_index_array_verified" if len(passed)==1 else "index_buffer_unresolved",
        "world_header_index_count":index_count,
        "source_surface_total_index_count":total,
        "source_range_scanned":[source_begin,surf_start],
        "seed_regex_matches":seed_matches,
        "candidate_positions_checked":len(checked),
        "first_surface_three_record_checks_passed":stage1,
        "distributed_surface_tests_passed":stage2,
        "fully_validated_candidates":passed,
    }
