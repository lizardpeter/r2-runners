#!/usr/bin/env python3
"""Full original 5.41 PAK entry SHA-1 / local-header audit.

This public-source runner streams one original complete R2 PAK to ephemeral
scratch, then verifies EVERY source-indexed plain, uncompressed payload byte
against its original decrypted-index SHA-1. Source bytes NEVER enter Git.
Encrypted payloads remain explicitly unresolved, not silently dropped.
"""
from __future__ import annotations
import argparse,hashlib,json,mmap,os,struct,subprocess,tempfile
from pathlib import Path
from fortnite541_all_pak_byte_census import EXPECTED,source_modules

def validate_span(local:bytes,offset:int,stored:int,unpacked:int,method:int,
                  digest:bytes,encrypted:bool,window_end:int):
    if offset+53+stored>window_end:
        raise ValueError("serialized local FPakEntry + advertised payload overlaps next source record")
    if len(local)!=53:raise ValueError("truncated original 53-byte FPakEntry")
    off,cs,us,cm=struct.unpack_from("<QQQI",local)
    if off not in (0,offset) or (cs,us,cm)!=(stored,unpacked,method) or local[28:48]!=digest:
        raise ValueError("original local FPakEntry does not match authenticated source index")
    if bool(local[48]&1)!=bool(encrypted):
        raise ValueError("local original source encryption flags differ from authenticated index")
    return (offset,offset+53,offset+53+stored)

def self_test():
    digest=bytes(range(20))
    local=struct.pack("<QQQI",0,4,4,0)+digest+b"\0"+struct.pack("<I",0)
    assert len(local)==53
    assert validate_span(local,100,4,4,0,digest,False,160)==(100,153,157)
    try:validate_span(local,100,4,4,0,digest,False,155)
    except ValueError:pass
    else:raise AssertionError("overlapping entry payload")
    try:validate_span(local,100,4,4,0,b"\x00"*20,False,160)
    except ValueError:pass
    else:raise AssertionError("incorrect original source digest accepted")
    print("FORTNITE541_FULL_PAYLOAD_AUDIT_SELF_TEST_PASS",flush=True)

def inspect(archive:str,destination:Path):
    if archive not in EXPECTED:raise ValueError("not a source-censused 5.41 archive")
    head,ranged,authenticated_index,base=source_modules()
    expected=EXPECTED[archive]
    _,remote_size,status=head(archive)
    if remote_size!=expected:raise ValueError(f"original remote size mismatch {remote_size}, {status}")
    index,proof=authenticated_index(archive,remote_size,
        os.getenv("RUST_TEST_FORTNITE_541_AES_KEY",
        "81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A"))
    if index is None:raise ValueError(f"unverified PAK index: {proof}")
    original_tail=ranged(f"{base}/{archive}",remote_size-61,61)
    index_offset,index_size=struct.unpack_from("<QQ",original_tail,25)
    destination.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="original-fortnite-541-") as tmp:
        source=Path(tmp)/archive
        # Entire ORIGINAL object; no capped handoff or missing large-file pieces.
        cmd=["curl","--fail","--show-error","--silent","--location",
             "--retry","5","--retry-all-errors","--retry-delay","3",
             "--connect-timeout","30","--max-time","5400",
             "--output",str(source),f"{base}/{archive}"]
        subprocess.run(cmd,check=True,timeout=5520)
        if source.stat().st_size!=expected:
            raise ValueError("original full PAK download is truncated or wrong-sized")
        records=sorted(index.items(),key=lambda e:(e[1][0],e[0]))
        offsets=sorted({e[1][0] for e in records})
        next_offset={o:(offsets[i+1] if i+1<len(offsets) else index_offset)
                     for i,o in enumerate(offsets)}
        seen=set()
        summary={"archive":archive,"full_original_pak_bytes":expected,
                 "authenticated_index":proof,"indexed_entries":len(records),
                 "validated_local_headers":0,"validated_local_header_bytes":0,
                 "payload_sha1_verified":0,"verified_plain_payload_bytes":0,
                 "encrypted_payloads_unresolved":0,"encrypted_payload_bytes":0,
                 "compressed_payloads_unresolved":0,"unresolved_data_gap_bytes":0,
                 "unknown_local_record_bytes":0,"failures":[],
                 "full_original_payload_coverage":False,
                 "semantic_coverage_bytes":None}
        out=destination/(archive+".entry-proofs.jsonl")
        with source.open("rb") as file, out.open("w",encoding="utf8") as stream:
            mm=mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ)
            try:
                first=offsets[0] if offsets else index_offset
                summary["unresolved_data_gap_bytes"]+=first
                for name,(offset,stored,unpacked,method,digest,encrypted) in records:
                    if offset in seen:
                        raise ValueError(f"duplicate physical local-record offset {offset}")
                    seen.add(offset)
                    limit=next_offset[offset]
                    local=mm[offset:offset+53]
                    try:
                        local_start,payload_start,payload_end=validate_span(
                            local,offset,stored,unpacked,method,digest,encrypted,limit)
                    except ValueError as exc:
                        summary["failures"].append({"path":name,"offset":offset,"reason":str(exc)})
                        raise
                    summary["validated_local_headers"]+=1
                    summary["validated_local_header_bytes"]+=53
                    summary["unresolved_data_gap_bytes"]+=limit-payload_end
                    record={"kind":"entry","indexed_path":name,"offset":offset,
                            "stored_bytes":stored,"unpacked_bytes":unpacked,
                            "original_index_sha1":digest.hex(),
                            "local_header_verified":True,
                            "payload_sha1_verified":False,
                            "semantic_status":"unassessed"}
                    if method:
                        summary["compressed_payloads_unresolved"]+=1
                        summary["unknown_local_record_bytes"]+=stored
                    elif encrypted:
                        summary["encrypted_payloads_unresolved"]+=1
                        summary["encrypted_payload_bytes"]+=stored
                    else:
                        view=memoryview(mm)[payload_start:payload_end]
                        try:
                            actual_digest=hashlib.sha1(view).digest()
                        finally:
                            view.release()
                        if actual_digest!=digest:
                            record["status"]="sha1_mismatch"
                            stream.write(json.dumps(record)+"\n")
                            raise ValueError(f"retail SHA1 payload mismatch: {name} at {offset}")
                        summary["payload_sha1_verified"]+=1
                        summary["verified_plain_payload_bytes"]+=stored
                        record["payload_sha1_verified"]=True
                    stream.write(json.dumps(record,sort_keys=True)+"\n")
                summary["full_original_payload_coverage"]=(summary["payload_sha1_verified"]==len(records))
            finally:
                mm.close()
        # Distinguish physical local headers and real byte-identical payloads
        # from unknown semantic contents; original retail material interpretation
        # remains a separate source-faithful runtime task.
        (destination/(archive+".summary.json")).write_text(
            json.dumps(summary,indent=2,sort_keys=True)+"\n",encoding="utf8")
        print("FORTNITE541_ALL_ENTRY_SHA1_SOURCE",json.dumps(summary,sort_keys=True),flush=True)
        return summary

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--archive",choices=sorted(EXPECTED))
    ap.add_argument("--destination",type=Path)
    ap.add_argument("--self-test",action="store_true")
    args=ap.parse_args()
    self_test()
    if not args.self_test:
        if not args.archive or not args.destination:ap.error("--archive and --destination required")
        inspect(args.archive,args.destination)
