#!/usr/bin/env python3
"""Source-only exact R2 footer identity audit of two exceptional Fortnite 5.41 PAKs.

Never guesses version, index crypto or material semantics. Captures bounded
original-byte evidence and actual source object SHA256, not source payloads.
"""
from __future__ import annotations
import argparse,hashlib,json,struct,subprocess,sys,tempfile
from pathlib import Path

FILES={
 "pakchunk1000-WindowsClient.pak":29767399,
 "pakchunkEra541-WindowsClient.pak":3478157,
}
MAGIC=b"\xe1\x12\x6f\x5a"
KEY="81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A"
BASE="https://r2.houseofkublai.com/Fortnite/5.41/FortniteGame/Content/Paks"

def src(url,offset,length):
    if length<1 or length>64*1024*1024:
        raise ValueError("exact R2 read beyond source bound")
    p=subprocess.run(["curl","--fail","--show-error","--silent","--location",
                     "--retry","4","--retry-delay","2","--range",
                     f"{offset}-{offset+length-1}",url],stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,timeout=180)
    if p.returncode or len(p.stdout)!=length:
        raise RuntimeError(f"exact source range {offset}+{length} unavailable")
    return p.stdout

def tail_candidates(tail,size):
    out=[]
    offset=0
    while True:
        i=tail.find(MAGIC,offset)
        if i<0:break
        offset=i+1
        absolute=size-len(tail)+i
        if i+44>len(tail):continue
        version=struct.unpack_from("<I",tail,i+4)[0]
        index_start,index_length=struct.unpack_from("<QQ",tail,i+8)
        sha=tail[i+24:i+44].hex()
        physical_tail=size-absolute
        candidate={"magic_offset":absolute,"bytes_from_magic_through_end":physical_tail,
                   "version":version,"index_start":index_start,"index_bytes":index_length,
                   "index_hash":sha,
                   "plausible_index_bounds":index_start+index_length<=absolute}
        out.append(candidate)
    return out

def check(name,bytes_expected):
    url=BASE+"/"+name
    # No source-size assumptions accepted beyond the R2-listed object length.
    whole=src(url,0,bytes_expected)
    digest=hashlib.sha256(whole).hexdigest()
    tail=whole[-min(len(whole),512):]
    candidates=tail_candidates(tail,bytes_expected)
    result={"original_archive":name,"source_bytes":len(whole),
            "original_object_sha256":digest,
            "original_footer_magic_candidates":candidates,
            "original_format_verified":False,
            "source_index_sha1_verified":False,
            "source_entry_semantics":None}
    for c in candidates:
        if c["version"]<1 or c["version"]>12 or not c["plausible_index_bounds"]:
            continue
        start,n=c["index_start"],c["index_bytes"]
        if start<0 or n<=0 or start+n>c["magic_offset"]:continue
        cipher=whole[start:start+n]
        c["raw_source_index_sha1_matches_footer"]=hashlib.sha1(cipher).hexdigest()==c["index_hash"]
        c["original_index_aes_deciphered_sha1_matches_footer"]=None
        if len(cipher)%16==0:
            p=subprocess.run(["openssl","enc","-aes-256-ecb","-d","-nopad","-K",KEY],
                             input=cipher,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if p.returncode==0:
                c["original_index_aes_deciphered_sha1_matches_footer"]=(hashlib.sha1(p.stdout).hexdigest()==c["index_hash"])
        if c["raw_source_index_sha1_matches_footer"] or c["original_index_aes_deciphered_sha1_matches_footer"]:
            result["source_index_sha1_verified"]=True
            result["original_format_verified"]=True
    # Original Era541 was observed to use the authenticated *clear* v3 index.
    # Use the pinned real UE4 index parser, never treat the filename's 541
    # suffix as evidence that its footer or entry format must be v7.
    for candidate in candidates:
        if candidate["version"] != 3 or not candidate.get("raw_source_index_sha1_matches_footer"):
            continue
        parser_dir=Path("source-decoder/crates/fortnite_541/tools")
        if not parser_dir.is_dir():
            raise RuntimeError("pinned source decoder required to interpret authentic v3 index")
        sys.path.insert(0,str(parser_dir.resolve()))
        from fetch_athena_541 import index_entries
        start,length=candidate["index_start"],candidate["index_bytes"]
        entries=index_entries(whole[start:start+length])
        ordered=sorted(entries.items(),key=lambda x:x[1][0])
        verified=0
        local_headers=0
        blocked=[]
        previous=0
        for i,(source_name,entry) in enumerate(ordered):
            off,stored,unpacked,method,sha,encrypted=entry
            next_start=ordered[i+1][1][0] if i+1<len(ordered) else start
            if not(previous<=off<next_start<=start):
                raise ValueError("v3 local source entry ordering or bounds invalid")
            previous=off
            if method or off+53+stored>next_start:
                blocked.append({"source_name":source_name,"reason":"compressed_or_unbounded_local_record"})
                continue
            local=whole[off:off+53]
            local_offset,local_stored,local_unpacked,local_method=struct.unpack_from("<QQQI",local)
            if local_offset not in (0,off) or (local_stored,local_unpacked,local_method)!=(stored,unpacked,0) or local[28:48]!=sha or bool(local[48]&1)!=bool(encrypted):
                raise ValueError("v3 source local FPakEntry does not match authenticated index")
            local_headers+=1
            original_stored=whole[off+53:off+53+stored]
            if hashlib.sha1(original_stored).digest()!=sha:
                raise ValueError("v3 original source payload SHA1 mismatch")
            verified+=1
        result["v3_source_records"]=len(entries)
        result["v3_local_headers_verified"]=local_headers
        result["v3_payload_source_sha1_verified"]=verified
        result["v3_entry_blockers"]=blocked
        result["v3_original_payload_storage_sha1_complete"]=verified==len(entries)
    return result

def test():
    b=b"*"*100+MAGIC+struct.pack("<IQQ",7,12,16)+bytes(range(20))
    assert tail_candidates(b,len(b))[0]["version"]==7
    print("FORTNITE541_EXCEPTIONAL_SOURCE_TEST_PASS",flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    test()
    if not a.self_test:
        if not a.output:p.error("--output required")
        rows=[check(n,v) for n,v in FILES.items()]
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(rows,indent=2,sort_keys=True)+"\n")
        print("FORTNITE541_ORIGINAL_EXCEPTIONAL_PAK_FOOTERS",json.dumps(rows,sort_keys=True),flush=True)
