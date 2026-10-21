#!/usr/bin/env python3
"""Source-authenticated IW5 XAsset directory audit from transferred raw FFs.

Inputs are original bytes produced by the isolated R2 source runner. Reports
contain counts and only asset IDs, not serialized game assets or localization.
"""
from pathlib import Path
import argparse, json, struct, zlib
from collections import Counter

ENVELOPE_LEN=21
XFILE_HEADER_LEN=44
TABLE_AT=60
INLINE=0xffffffff
MAX_ZONE=64*1024*1024
MAX_ASSETS=2000000

def u32(b,offset):
    if offset+4 > len(b):
        raise ValueError("short source at offset %d" % offset)
    return struct.unpack_from("<I",b,offset)[0]

def scan_full_original_ff(path:Path):
    b=path.read_bytes()
    if b[:8]!=b"IWffu100" or u32(b,8)!=1:
        raise ValueError(f"{path.name}: unexpected IW5 original FastFile envelope")
    decoder=zlib.decompressobj()
    out=decoder.decompress(b[ENVELOPE_LEN:],MAX_ZONE+1)
    out+=decoder.flush()
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError(f"{path.name}: incomplete/unbounded/trailing zlib payload")
    if len(out)>MAX_ZONE:
        raise ValueError(f"{path.name}: decompressed source exceeded cap")
    if u32(out,0) != len(out)-XFILE_HEADER_LEN:
        raise ValueError(f"{path.name}: retail XFile length mismatch")
    string_count = u32(out,44)
    string_ptr = u32(out,48)
    count=u32(out,52)
    table_ptr=u32(out,56)
    if string_count or string_ptr or table_ptr != INLINE or count>MAX_ASSETS:
        raise ValueError(f"{path.name}: unexpected IW5 source XAssetList spelling")
    end=TABLE_AT+count*8
    if end>len(out):
        raise ValueError("source XAsset record table truncated")
    types=[]
    for n in range(count):
        kind,pointer=struct.unpack_from("<II",out,TABLE_AT+n*8)
        if kind>=46 or pointer!=INLINE:
            raise ValueError("unexpected asset type or pointer in source zone")
        types.append(kind)
    # Source-owned serialized localize entries appear first in these zones.
    offset=end
    localized=0
    packed_text=0
    names=[]
    for kind in types:
        if kind != 27:break
        ptrs=[u32(out,offset),u32(out,offset+4)]
        offset+=8
        vals=[]
        for ptr in ptrs:
            if ptr==INLINE:
                terminator=out.find(b"\0",offset,offset+8192)
                if terminator==-1:raise ValueError("unterminated source localization")
                # Latin-1 is a 1:1 byte mapping for source evidence, not
                # a claim that the game locale uses ISO-8859-1.
                vals.append(out[offset:terminator].decode("latin-1"))
                offset=terminator+1
            elif (ptr & 0xf0000000) == 0x30000000:
                vals.append(None)
                packed_text+=1
            elif ptr==0: vals.append(None)
            else: raise ValueError(f"unknown encoded IW5 localization pointer {ptr:08x}")
        localized+=1
        if not vals[1]:raise ValueError("source localization key missing")
        names.append(vals[1])
    counts=Counter(types)
    return {
        "fastfile":path.name,
        "compressed_bytes":len(b),
        "inflated_bytes":len(out),
        "xasset_count":count,
        "asset_type_counts":{str(k):v for k,v in sorted(counts.items())},
        "localized_count":localized,
        "packed_string_references":packed_text,
        "all_localization_keys_unique":len(set(names))==len(names),
    }

def main(input_dir:Path, output_dir:Path):
    output_dir.mkdir(parents=True,exist_ok=True)
    results=[]
    errors=[]
    for path in sorted(input_dir.glob("*.ff")):
        # The original artifact contains prefixes of several large zones;
        # inspect a member only when the entire zlib stream is available.
        try: results.append(scan_full_original_ff(path))
        except Exception as e:errors.append({"source":path.name, "reason":str(e)})
    tally=Counter()
    for result in results:
        for key,count in result["asset_type_counts"].items():
            tally[key]+=count
    report={"complete_ff_count":len(results),"source_only_prefix_count":len(errors),
            "aggregate_type_counts":dict(tally),"verified_localization_count":
            sum(x["localized_count"] for x in results),
            "verified_packed_string_reference_count":
            sum(x["packed_string_references"] for x in results),
            "per_fastfile":results,"unverified_prefixes":errors}
    (output_dir/"iw5_verified_xasset_report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    if len(results)!=7 or report["verified_localization_count"]!=662:
        raise RuntimeError("Unexpected source sample count or XAsset layout regression")
    if sum(tally.values())!=1044:
        raise RuntimeError("IW5 original source asset count regression")
    return report

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--samples",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    a=parser.parse_args()
    main(a.samples,a.out)
