#!/usr/bin/env python3
"""Read bounded *metadata windows* around a real T7 FastFile world name.

The same decoder works for any genuine original game-zone. No fabricated
world geometry, no source file extraction or game-specific renderer.
"""
import hashlib,json,os,struct,sys
from tempfile import TemporaryDirectory
from pathlib import Path
from urllib.parse import quote
from bo3_zone_decode import SOURCES,PREFIX,BASE,parse_zlib_zone,parse_directory
from r2_download import download
def around(data,needle,cap=90):
    hits=[];p=0
    while len(hits)<cap:
        a=data.find(needle,p)
        if a<0:break
        p=a+len(needle)
        near=data[max(0,a-80):a]
        tail=data[a+len(needle):a+len(needle)+24]
        preceding_qwords=[]
        for k in range(8,73,8):
            if len(near)>=k:preceding_qwords.append(f"0x{struct.unpack_from('<Q',near,len(near)-k)[0]:016x}")
        hits.append({"string_offset":a,"prior_80_bytes_sha256":hashlib.sha256(near).hexdigest(),
            "preceding_qwords_nearest_first":preceding_qwords,
            "name_has_trailing_NUL":data[a+len(needle):a+len(needle)+1]==b"\0",
            "next_24_hex":tail.hex(),
            "last_48_hex":near[-48:].hex()})
    return hits
def main():
    name=os.environ.get("BO3_WORLD_ZONE","core_frontend.ff")
    if name not in SOURCES:raise ValueError("Zone not in verified source manifest")
    with TemporaryDirectory(prefix="t7-world-name-root-") as td:
        filepath=Path(td)/name
        size,sha,_=download(BASE+"/"+quote(PREFIX+name,safe="/"),filepath)
        z,metadata=parse_zlib_zone(filepath)
    if metadata["status"]!="end_marker":raise ValueError("Source zone incompletely decoded")
    d=parse_directory(z)
    if d["status"]!="t7_asset_table_layout_verified":raise ValueError("Typed zone root not valid")
    offsets={}
    for string in ("core_frontend","maps/","maps\\\\","d3dbsp","mapents","front_end","frontend"):
        term=string.encode("ascii")
        offsets[string]=around(z,term,40 if string=="core_frontend" else 12)
    out={"source":name,"source_hash":sha,"decoded_bytes":len(z),
        "source_table_end":d["asset_table"]["table_offset"]+16*d["asset_count"],
        "name_occurrences":offsets,
        "note":"Raw windows are only evidence candidates. No physical XAsset owner is assigned by name proximity alone."}
    print(json.dumps(out,sort_keys=True),flush=True)
    folder=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));folder.mkdir(parents=True,exist_ok=True)
    (folder/"bo3_world_body_name_evidence.json").write_text(json.dumps(out,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"BO3 world name evidence probe blocked: {e}",file=sys.stderr);raise SystemExit(1)
