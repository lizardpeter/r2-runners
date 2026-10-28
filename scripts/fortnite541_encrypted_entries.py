#!/usr/bin/env python3
"""Probe every 5.41 main-PAK encrypted source entry against exact R2 bytes.

The original index is independently AES-decrypted and SHA1 authenticated
before requesting indexed ciphertext. This reports *source-level* entry
SHA1, not cooked UObject semantics or original game behavior.
"""
from __future__ import annotations
import argparse, hashlib, json, os, struct, subprocess, sys
from pathlib import Path

KEY="81C42E03B21760A5C457C8DB7D52BA066F0633D0891FD9E37CF118F27687924A"
ARCHIVE="pakchunk0-WindowsClient.pak"
BYTES=4813653874

def modules():
    p=Path("source-decoder/crates/fortnite_541/tools")
    if not p.is_dir():raise RuntimeError("missing pinned public original-source verifier")
    sys.path.insert(0,str(p.resolve()))
    from probe_remote_541_paks import head,authenticated_index,ranged,BASE
    return head,authenticated_index,ranged,BASE

def decrypt(cipher:bytes,key:str)->bytes:
    if len(cipher)%16:raise ValueError("AES-ECB original ciphertext not 16-byte aligned")
    p=subprocess.run(["openssl","enc","-aes-256-ecb","-d","-nopad","-K",key],
                     input=cipher,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if p.returncode:raise ValueError("openssl rejected exact original encrypted bytes")
    return p.stdout

def test():
    pt=b"0000000000000000"
    p=subprocess.run(["openssl","enc","-aes-256-ecb","-e","-nopad","-K",KEY],
                     input=pt,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    assert decrypt(p.stdout,KEY)==pt
    print("FORTNITE541_ENCRYPTED_ENTRY_PROBE_TEST_PASS",flush=True)

def run(out:Path):
    head,auth,ranged,base=modules()
    _,size,state=head(ARCHIVE)
    if size!=BYTES:raise ValueError(f"main original source length mismatch: {size} / {state}")
    key=os.getenv("RUST_TEST_FORTNITE_541_AES_KEY",KEY)
    entries,proof=auth(ARCHIVE,size,key)
    if entries is None:raise ValueError(f"original encrypted index not verified: {proof}")
    tail=ranged(f"{base}/{ARCHIVE}",size-61,61)
    index_start, index_length=struct.unpack_from("<QQ",tail,25)
    ordered=sorted(entries.items(),key=lambda x:x[1][0])
    starts=[item[1][0] for item in ordered]
    rows=[]
    for i,(name,entry) in enumerate(ordered):
        off,stored,unpacked,method,digest,encrypted=entry
        if not encrypted:continue
        end=next((v for v in starts[i+1:] if v>off),index_start)
        row={"source_path":name,"indexed_offset":off,"indexed_bytes":stored,
             "original_index_sha1":digest.hex(),"compression_method":method,
             "source_encrypted":True,"payload_plaintext_sha1_verified":False}
        if method!=0:
            row["status"]="encrypted_compression_method_unsupported"
        else:
            aligned=(stored+15)//16*16
            if off+53+aligned>end:
                row["status"]="encrypted_source_range_escapes_local_entry"
            else:
                header=ranged(f"{base}/{ARCHIVE}",off,53)
                local=struct.unpack_from("<QQQI",header,0)
                if local[0] not in (0,off) or local[1:]!=(stored,unpacked,method) or header[28:48]!=digest or not(header[48]&1):
                    row["status"]="authenticated_index_local_FPakEntry_disagreement"
                else:
                    cipher=ranged(f"{base}/{ARCHIVE}",off+53,aligned)
                    decoded=decrypt(cipher,key)
                    if len(decoded)<unpacked:
                        row["status"]="decrypted_source_too_short"
                    else:
                        # UE4 may authenticate the stored encrypted bytes
                        # rather than the decrypted logical file. Do not guess
                        # a hash domain: verify every plausible exact interval.
                        candidates={
                            "stored_ciphertext":cipher[:stored],
                            "aes_aligned_ciphertext":cipher,
                            "decrypted_logical_file":decoded[:unpacked],
                            "decrypted_stored_extent":decoded[:stored],
                            "decrypted_aes_aligned":decoded,
                        }
                        matches=sorted(k for k,v in candidates.items()
                                       if hashlib.sha1(v).digest()==digest)
                        row["source_sha1_matching_domains"]=matches
                        row["payload_stored_source_sha1_verified"]=any(
                            x in matches for x in ("stored_ciphertext","aes_aligned_ciphertext"))
                        row["payload_plaintext_sha1_verified"]=any(
                            x in matches for x in ("decrypted_logical_file",
                                                  "decrypted_stored_extent",
                                                  "decrypted_aes_aligned"))
                        row["status"]="sha1_domain_"+matches[0] if matches else "original_source_sha1_unmatched"
                        if row["payload_stored_source_sha1_verified"]:
                            logical=decoded[:unpacked]
                            row["decrypted_logical_bytes"]=len(logical)
                            row["decrypted_plaintext_sha256"]=hashlib.sha256(logical).hexdigest()
                            row["decrypted_nul_bytes"]=logical.count(bytes((0,)))
                            row["decrypted_utf8_valid"]=False
                            try:
                                logical.decode("utf8")
                                row["decrypted_utf8_valid"]=True
                            except UnicodeDecodeError:
                                pass
                            row["decrypted_has_ini_section"]=any(
                                line.lstrip().startswith(b"[") and b"]" in line
                                for line in logical.splitlines())
        rows.append(row)
    ok=sum(bool(r.get("source_sha1_matching_domains")) for r in rows)
    result={"source":"actual main 5.41 original R2 retail PAK","index_proof":proof,
            "original_indexed_encrypted_entries":len(rows),
            "sha1_verified_encrypted_payloads":ok,
            "sha1_verified_plaintext_payloads":sum(r.get("payload_plaintext_sha1_verified",False) for r in rows),
            "sha1_verified_stored_ciphertexts":sum(r.get("payload_stored_source_sha1_verified",False) for r in rows),
            "verified_original_stored_encrypted_payload_bytes":sum(
                r["indexed_bytes"] for r in rows if r.get("payload_stored_source_sha1_verified",False)),
            "verified_encrypted_payload_bytes":sum(
                r["indexed_bytes"] for r in rows if r.get("source_sha1_matching_domains")),
            "unknown_encrypted_payloads":len(rows)-ok,
            "decrypted_utf8_valid_files":sum(bool(r.get("decrypted_utf8_valid")) for r in rows),
            "decrypted_ini_files_with_sections":sum(bool(r.get("decrypted_has_ini_section")) for r in rows),
            "complete_original_encrypted_payload_authentication":ok==len(rows),
            "retail_shader_semantics":None,"entries":rows}
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf8")
    print("FORTNITE541_REAL_ENCRYPTED_SOURCE_PROBE",json.dumps({k:v for k,v in result.items() if k!="entries"}),flush=True)
    if ok!=len(rows):raise RuntimeError(f"{len(rows)-ok} original encrypted entries not verified; see preserved evidence")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path)
    p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    test()
    if not a.self_test:
        if not a.output:p.error("--output required")
        run(a.output)
