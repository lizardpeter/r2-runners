#!/usr/bin/env python3
"""Independent, public-source physical census for all ten Fortnite 5.41 UE4 content PAKs.

Read only original R2 HEAD, v7 footer and AES/SHA1-authenticated index ranges.
Never confuse an authenticated index or complete physical partition with
individual payload authentication, interpreted game data or shader parity.
"""
from __future__ import annotations
import argparse, concurrent.futures, json, os, struct, sys
from collections import Counter
from pathlib import Path

# Complete Content/Paks/*.pak object identities and lengths from the
# actual Cloudflare R2 bucket census 2026-10-27 (not an Epic install manifest).
EXPECTED = {
    "pakchunk0-WindowsClient.pak":4813653874,
    "pakchunk0_s1-WindowsClient.pak":4302039491,
    "pakchunk0_s2-WindowsClient.pak":4312490818,
    "pakchunk0_s3-WindowsClient.pak":4335343268,
    "pakchunk0_s4-WindowsClient.pak":4353633176,
    "pakchunk0_s5-WindowsClient.pak":455994943,
    "pakchunk1-WindowsClient.pak":4318967799,
    "pakchunk1000-WindowsClient.pak":29767399,
    "pakchunk1_s1-WindowsClient.pak":290814129,
    "pakchunkEra541-WindowsClient.pak":3478157,
}
HISTORICAL_KEY="81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A"

def regions(data_end:int,index_len:int,total:int,offsets:list[int]):
    footer_start=total-61
    if not(0<=data_end<=data_end+index_len<=footer_start):
        raise ValueError("index/footer physical overlap")
    starts=sorted(set(offsets))
    if any(not(0<=x<data_end) for x in starts):
        raise ValueError("indexed local record starts beyond PAK data")
    out=[]
    def add(a,b,label):
        if a<b:out.append((a,b,label))
    cursor=0
    for i,start in enumerate(starts):
        add(cursor,start,"unattributed_data")
        end=starts[i+1] if i+1<len(starts) else data_end
        add(start,end,"indexed_entry_window_unresolved")
        cursor=end
    add(cursor,data_end,"unattributed_data")
    add(data_end,data_end+index_len,"authenticated_index")
    add(data_end+index_len,footer_start,"index_footer_gap_unresolved")
    add(footer_start,total,"structurally_parsed_footer")
    cursor=0
    for a,b,_ in out:
        if a!=cursor or b<=a:raise ValueError("gap/overlap in physical ledger")
        cursor=b
    if cursor!=total:raise ValueError("unaccounted physical tail")
    return out

def source_modules():
    directory=Path("source-decoder/crates/fortnite_541/tools")
    if not directory.is_dir():raise RuntimeError("missing pinned public original-source decoder")
    sys.path.insert(0,str(directory.resolve()))
    from probe_remote_541_paks import head, ranged, authenticated_index, BASE
    return head,ranged,authenticated_index,BASE

def scan(archive):
    head,ranged,authenticated_index,BASE=source_modules()
    expected=EXPECTED[archive]
    _,actual,status=head(archive)
    if actual!=expected:
        raise ValueError(f"{archive}: expected R2 object {expected} bytes, got {actual}, status={status}")
    records,proof=authenticated_index(archive,actual,os.getenv("RUST_TEST_FORTNITE_541_AES_KEY",HISTORICAL_KEY))
    if records is None:raise ValueError(f"{archive}: no authenticated original index: {proof}")
    tail=ranged(f"{BASE}/{archive}",actual-61,61)
    if struct.unpack_from("<II",tail,17)!=(0x5A6F12E1,7):
        raise ValueError(f"{archive}: original v7 footer mismatch")
    start,length=struct.unpack_from("<QQ",tail,25)
    spans=regions(start,length,actual,[v[0] for v in records.values()])
    categories=Counter()
    stored=unpacked=0
    for name,entry in records.items():
        offset,compressed,plain,method,digest,encrypted=entry
        if not name or min(offset,compressed,plain)<0 or len(digest)!=20:
            raise ValueError("malformed source PAK entry")
        if offset+compressed>start:
            raise ValueError("source entry compressed bytes extend into index")
        categories["compressed" if method else "uncompressed"]+=1
        categories["encrypted" if encrypted else "unencrypted"]+=1
        categories[name.rsplit(".",1)[-1].lower() if "." in name else "(noext)"]+=1
        stored+=compressed
        unpacked+=plain
    # Small deterministic original local-header sampling, with honest scope:
    # these checks do not authenticate payloads or uninspected local headers.
    candidates=sorted(((name,e) for name,e in records.items()
                       if e[3]==0 and not e[5] and e[1]==e[2]),key=lambda x:x[1][0])
    samples=[]
    for i in sorted({k*(len(candidates)-1)//7 for k in range(8)}) if candidates else []:
        name,e=candidates[i]
        offset,compressed,plain,method,digest,encrypted=e
        local=ranged(f"{BASE}/{archive}",offset,53)
        off,stored_local,plain_local,method_local=struct.unpack_from("<QQQI",local,0)
        valid=(off in (0,offset) and stored_local==compressed and plain_local==plain
               and method_local==0 and local[28:48]==digest and not(local[48]&1))
        samples.append({"source_path":name,"local_offset":offset,"consistent":valid})
        if not valid:raise ValueError(f"{archive}: sampled source local header disagrees: {name}")
    return {
        "kind":"pak","archive":archive,"physical_bytes":actual,
        "source_index_sha1":tail[41:61].hex(),"index_authentication":proof,
        "indexed_entries":len(records),"indexed_compressed_bytes":stored,
        "indexed_uncompressed_bytes":unpacked,"index_bytes":length,
        "entry_class_counts":dict(categories),"sampled_local_headers":samples,
        "physical_byte_ranges":[{"begin":a,"end_exclusive":b,"bytes":b-a,"class":label}
                                for a,b,label in spans],
        "index_payload_sha1_verified":False,
        "all_entry_payload_sha1_verified":False,
        "semantically_understood_bytes":None,
        "retail_shader_execution_verified":None,
    }

def self_test():
    assert len(EXPECTED)==10
    assert sum(EXPECTED.values())==27216183054
    assert regions(100,20,200,[0,0,70])==[
        (0,70,"indexed_entry_window_unresolved"),
        (70,100,"indexed_entry_window_unresolved"),
        (100,120,"authenticated_index"),
        (120,139,"index_footer_gap_unresolved"),
        (139,200,"structurally_parsed_footer")]
    assert regions(100,20,200,[])[0]==(0,100,"unattributed_data")
    try:regions(150,20,200,[155])
    except ValueError:pass
    else:raise AssertionError("accepted source record outside PAK data")
    print("FORTNITE541_PUBLIC_SOURCE_BYTE_CENSUS_TEST_PASS",flush=True)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path)
    ap.add_argument("--self-test",action="store_true")
    args=ap.parse_args()
    self_test()
    if args.self_test:return
    if not args.output:ap.error("--output required")
    if not args.output.parent.is_dir():raise ValueError("output directory does not exist")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        pak_rows=list(pool.map(scan,EXPECTED))
    pak_rows.sort(key=lambda x:x["archive"])
    total=sum(x["physical_bytes"] for x in pak_rows)
    summary={
        "kind":"summary","real_original_source":"houseofkublai/Fortnite/5.41",
        "archive_scope":"all 10 source-object Content/Paks/*.pak in the 2026-10-27 R2 inventory",
        "paks_verified":len(pak_rows),"physical_bytes_accounted":total,
        "authenticated_index_bytes":sum(x["index_bytes"] for x in pak_rows),
        "indexed_entry_records":sum(x["indexed_entries"] for x in pak_rows),
        "sampled_local_headers":sum(len(x["sampled_local_headers"]) for x in pak_rows),
        "physical_accounting_complete":total==sum(EXPECTED.values()),
        "semantic_coverage_bytes":None,"full_installation_byte_corpus":False,
        "entry_payload_hashes_fully_verified":False,"retail_renderer_parity":None}
    if not summary["physical_accounting_complete"]:raise ValueError("source corpus byte mismatch")
    with args.output.open("w",encoding="utf8") as out:
        for x in pak_rows:out.write(json.dumps(x,sort_keys=True)+"\n")
        out.write(json.dumps(summary,sort_keys=True)+"\n")
    print("FORTNITE541_REAL_SOURCE_ALL_PAK_CENSUS",json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
