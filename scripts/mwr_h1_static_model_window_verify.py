"""Audit the REST of an original H1 static draw array after a source seed.

A near-array seed comes from runtime H1 GfxWorld smodelCount and exact 80B
structure matches, not the fixture filename or fixed decoded byte offset.
Analyze the full requested count in the original LZ4 source stream and
explain breaks; DO NOT infer playable models from partially verified rows.
"""
import math
import struct
from collections import Counter
from mwr_h1_world_vertex_verify import extract_source_window
from mwr_h1_static_models_probe import STRIDE,plausible_draw_record

def inspect_retained_draw_window(ff_file,header,stream_class,world,scanned):
    seed=scanned.get("largest_provisional_run") or {}
    start=seed.get("start")
    count=world.get("static_model_count")
    if not isinstance(start,int) or not isinstance(count,int) or count<8:
        return {"status":"no_authored_static_draw_seed"}
    if seed.get("records",0)<8:
        return {"status":"no_source_structural_placement_anchor"}
    # The seed may sit inside a larger array. Audit nearby candidate start
    # shifts, then the declared count, without map-specific fixed addresses.
    before=min(32*STRIDE,start)
    length=count*STRIDE
    after=64*STRIDE
    begin=start-before
    end=start+length+after
    if end-begin>128*1024*1024:
        return {"status":"authored_draw_window_exceeds_source_cap"}
    raw=extract_source_window(ff_file,header,stream_class,begin,end)
    preview=[]
    best=None
    for shift in range(-32,33):
        candidate=start+shift*STRIDE
        rel=candidate-begin
        if rel<0 or rel+length>len(raw):continue
        categories=Counter()
        transforms=Counter()
        ptrs=Counter()
        failures=[]
        for i in range(count):
            at=rel+i*STRIDE
            ptr=struct.unpack_from("<Q",raw,at+56)[0]
            if ptr==0:ptype="null"
            elif ptr==0xFDFDFDFFFFFFFFFF:ptype="inline"
            elif ptr>>32==0xFDFDFDF3:ptype="block3"
            elif ptr>>48==0xFDFD:ptype="other_tagged"
            else:ptype="unsupported"
            ptrs[ptype]+=1
            xyz=struct.unpack_from("<13f",raw,at)
            positions=xyz[:3]
            axes=[xyz[3:6],xyz[6:9],xyz[9:12]]
            transform_ok=(all(math.isfinite(v) and abs(v)<2_000_000 for v in positions)
                          and all(math.isfinite(v) and abs(v)<=2 for row in axes for v in row)
                          and math.isfinite(xyz[12]) and 0.001<=abs(xyz[12])<=1000
                          and all(0.25<=sum(v*v for v in row)<=4 for row in axes))
            if transform_ok:transforms["sane"]+=1
            else:transforms["rejected"]+=1
            if transform_ok and ptype in ("block3","inline","other_tagged"):
                categories["valid"]+=1
            else:
                categories["not_fully_source_valid"]+=1
                if len(failures)<6:
                    failures.append({"record":i,"pointer_kind":ptype,
                                     "transform_looks_sane":transform_ok,
                                     "source_ptr":f"{ptr:016x}"})
        score=(categories["valid"],transforms["sane"])
        candidate_result={"seed_relative_record_shift":shift,
                         "source_start":candidate,
                         "expected_declared_records":count,
                         "validated_transform_and_pointer_records":categories["valid"],
                         "transforms_sane":transforms["sane"],
                         "pointer_kinds":dict(ptrs),
                         "first_failures":failures}
        if best is None or score>best[0]:
            best=(score,candidate_result)
        if shift in (-1,0,1):preview.append(candidate_result)
    return {"status":"source_window_discrimination_not_asset_ownership",
            "seed_provisional_records":seed.get("records"),
            "candidate_windows_checked":65,
            "best_source_alignment":best[1] if best else None,
            "near_seed_windows":preview,
            "no_instances_admitted":True}
