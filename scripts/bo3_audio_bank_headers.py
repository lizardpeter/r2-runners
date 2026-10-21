#!/usr/bin/env python3
"""Inspect every original BO3 T7 SABL/SABS header using authenticated R2 ranges.

No audio payload is uploaded or extracted. Only byte-level header evidence,
archive inventory, and boundary checks. Empty 2048-byte SAB bank stubs are
recorded explicitly and never counted as sounds.
"""
from __future__ import annotations
import hashlib,json,os,struct,sys
from pathlib import Path
from urllib.request import urlopen,Request
from urllib.parse import quote

BASE="https://r2.houseofkublai.com/"
FOLDER="bo3/DUMP/zone/snd/"
SIZES={
"all/core_frontend.all.sabl":30677376,
"all/core_frontend_patch.all.sabl":2048,
"all/core_frontend_patch.all.sabs":2048,
"all/core_patch.all.sabl":8161024,
"all/core_patch.all.sabs":63224832,
"all/core_post_gfx.all.sabl":3773056,
"all/core_ui.all.sabl":16022016,
"all/core_ui.all.sabs":279878528,
"en/core_frontend.en.sabl":2048,
"en/core_frontend.en.sabs":84853888,
"en/core_frontend_patch.en.sabl":2048,
"en/core_frontend_patch.en.sabs":14434048,
"en/core_patch.en.sabl":2048,
"en/core_patch.en.sabs":2048,
"en/core_post_gfx.en.sabl":2048,
"en/core_ui.en.sabl":2048,
"en/core_ui.en.sabs":2048,
}
def prefix(name,length=608):
    total=SIZES[name]
    n=min(length,total)
    req=Request(BASE+quote(FOLDER+name,safe="/"),
        headers={"Range":f"bytes=0-{n-1}","Accept-Encoding":"identity",
                 "User-Agent":"bo3-t7-audio-source-evidence/1"})
    with urlopen(req,timeout=80) as response:
        expected=f"bytes 0-{n-1}/{total}"
        if response.status!=206 or response.headers.get("Content-Range")!=expected:
            raise ValueError(f"Original R2 audio range mismatch: {name}")
        data=response.read(n+1)
        if len(data)!=n:raise ValueError("Source audio prefix truncated")
    return data
def survey(name):
    data=prefix(name)
    magic=struct.unpack_from("<I",data,0)[0]
    version=struct.unpack_from("<I",data,4)[0]
    first_words=[f"0x{x:08x}" for x in struct.unpack_from("<16I",data,0)]
    name_offset=struct.unpack_from("<Q",data,0x250)[0] if len(data)>=0x258 else None
    return {"original_file":name,"original_bytes":SIZES[name],
            "kind":Path(name).suffix[1:],"locale":name.split("/")[0],
            "header_magic":f"0x{magic:08x}","raw_version_at_4":version,
            "is_t7_soundbank":magic==0x23585532 and version==15,
            "first_16_u32":first_words,
            "name_table_offset_at_0x250":name_offset,
            "name_table_offset_in_file":name_offset is not None and
                (name_offset==0 or 0<name_offset<SIZES[name]),
            "header_sha256":hashlib.sha256(data).hexdigest(),
            "raw_header_0x00_to_0x60":data[:96].hex()}
def main():
    results=[survey(name) for name in SIZES]
    summary={"source_sound_banks":len(results),
             "total_bytes":sum(x["original_bytes"] for x in results),
             "2048_byte_banks":sum(x["original_bytes"]==2048 for x in results),
             "t7_v15_identified":sum(x["is_t7_soundbank"] for x in results),
             "other_headers":sum(not x["is_t7_soundbank"] for x in results)}
    out={"summary":summary,"banks":results}
    print(json.dumps(out,sort_keys=True),flush=True)
    target=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));target.mkdir(parents=True,exist_ok=True)
    (target/"bo3_audio_bank_source_headers.json").write_text(json.dumps(out,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"Original BO3 sound bank source check failed: {e}",file=sys.stderr);raise SystemExit(1)
