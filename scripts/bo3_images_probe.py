#!/usr/bin/env python3
"""Source-authenticated BO3 GfxImage scan + actual T7 XPAK mip-key linkage.

No game contents or pixel bytes are uploaded to GitHub. Retail archives are
staged fully in the runner's temporary directory, decoded in RAM and deleted.
"""
from __future__ import annotations
import json,os,struct,hashlib,sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import parse_zlib_zone
from bo3_xpak_decode import parse_index,probe_entry
from bo3_base_index import read_base_index
BASE="https://r2.houseofkublai.com/bo3/DUMP/zone/"
FILES={
    "core_ui.ff":25129024,
    "core_gfx.ff":6790208,
    "en_core_common.ff":545024,
    "en_core_frontend.ff":2977856,
    "core_pre_gfx.ff":22285376,
    "core_specialists.ff":51386816,
    "core_frontend_patch.ff":72319872,
    "core_patch.ff":44856320,
}
PACKAGES={"en_initial.xpak":13893632,"base_patch_tu32.xpak":1048576}
FF_PRESETS={
    "small":["en_core_common.ff","core_gfx.ff","core_ui.ff"],
    "expanded":list(FILES),
}
def source_inline_mip_chain(width:int,height:int,fmt:int,byte_len:int)->int|None:
    """Prove complete resident DXGI/BCn mip byte ownership without guesswork."""
    if fmt in (24,28,29): unit,compressed=4,False
    elif fmt==49:unit,compressed=2,False
    elif fmt in (61,62):unit,compressed=1,False
    elif fmt in (71,72,80,81):unit,compressed=8,True
    elif fmt in (74,75,77,78,83,84,95,96,98,99):unit,compressed=16,True
    else:return None
    done=0
    count=0
    w,h=width,height
    while True:
        size=((w+3)//4)*((h+3)//4)*unit if compressed else w*h*unit
        if size>byte_len-done:return None
        done+=size
        count+=1
        if done==byte_len:return count
        if w==1 and h==1:return None
        w,h=max(1,w//2),max(1,h//2)

def scan_images(zone:bytes,known_hashes:set[int])->dict:
    hits=[]
    without_pixels=Counter()
    bad=Counter()
    # The fastfile's embedded GfxImage is 0x108 bytes; the name pointer
    # at +0xf8 stores a full eight-byte 0xff marker, followed by a name
    # string at +0x108 (C++ T7 source-layout evidence).
    pos=248
    while True:
        marker=zone.find(b"\xff"*8,pos)
        if marker<0:break
        pos=marker+1
        start=marker-248
        if start<0 or start+264>=len(zone):continue
        name_start=start+264
        limit=min(name_start+160,len(zone))
        end=zone.find(b"\0",name_start,limit)
        if end<name_start+2:continue
        name_raw=zone[name_start:end]
        if any(c<32 or c>126 for c in name_raw):continue
        name=name_raw.decode("ascii")
        mip_records=[]
        matching=[]
        for mip in range(4):
            off=start+mip*40
            size,w,h,key=struct.unpack_from("<IHHQ",zone,off)
            if key and size and 0<w<=8192 and 0<h<=8192 and size<=128*1024*1024:
                mip_records.append({"level":mip,"size":size,"width":w,"height":h,"hash":f"0x{key:016x}","matched_xpak":key in known_hashes})
                if key in known_hashes:matching.append((size,w,h,key,mip))
        loaded_levels=zone[start+191]
        loaded_w,loaded_h=struct.unpack_from("<HH",zone,start+192)
        loaded=struct.unpack_from("<Q",zone,start+232)[0]
        pixel_ptr=struct.unpack_from("<Q",zone,start+216)[0]
        fmt=zone[start+240]
        inline=(pixel_ptr==0xffffffffffffffff and 0<loaded<=64*1024*1024 and
                0<loaded_w<=8192 and 0<loaded_h<=8192 and end+1+loaded<=len(zone))
        if not matching and not inline:
            without_pixels["unresolved_hash_or_inline"]+=1
            # Only keep strong candidate names when a real source image
            # description has plausible levels/formats; no false admission.
            continue
        kind="xpak" if matching else "inline"
        if matching:
            size,w,h,key,lev=max(matching)
        else:
            size,w,h,key,lev=loaded,loaded_w,loaded_h,None,None
        if fmt>255:continue
        info={"name":name,"source_offset":start,"source_format":fmt,
              "width":w,"height":h,"source_bytes":size,
              "loaded_levels":loaded_levels,"source_kind":kind,
              "source_key":f"0x{key:016x}" if key is not None else None,
              "matching_mip_index":lev,"known_mips":mip_records[:4]}
        if inline:
            raw=zone[end+1:end+1+loaded]
            info["inline_payload_sha256"]=hashlib.sha256(raw).hexdigest()
            info["inline_payload_bytes"]=len(raw)
            info["exact_mip_chain_levels"]=source_inline_mip_chain(w,h,fmt,len(raw))
        hits.append(info)
    duplicates=Counter(h["name"] for h in hits)
    return {"confirmed_image_descriptions":len(hits),
            "unique_names":len(duplicates),
            "duplicated_names":sum(1 for c in duplicates.values() if c>1),
            "source_kinds":dict(Counter(h["source_kind"] for h in hits)),
            "inline_exact_mip_chains":sum(1 for h in hits if h["source_kind"]=="inline" and h.get("exact_mip_chain_levels") is not None),
            "inline_unproven_mip_chains":sum(1 for h in hits if h["source_kind"]=="inline" and h.get("exact_mip_chain_levels") is None),
            "formats":dict(Counter(str(h["source_format"]) for h in hits)),
            "nonexact_inline_examples":[{"name":h["name"],"format":h["source_format"],"width":h["width"],"height":h["height"],"bytes":h["inline_payload_bytes"]} for h in hits if h["source_kind"]=="inline" and h.get("exact_mip_chain_levels") is None][:12],
            "source_size_total":sum(h["source_bytes"] for h in hits),
            "first_20":hits[:20],
            "unmatched_candidate_count":without_pixels["unresolved_hash_or_inline"],
            "all_name_hashes":[{"name":h["name"],"source_offset":h["source_offset"],"format":h["source_format"],"kind":h["source_kind"],
                                "source_key":h["source_key"],"width":h["width"],"height":h["height"],
                                "source_bytes":h["source_bytes"]} for h in hits[:2000]]}

def main():
    preset=os.environ.get("BO3_IMAGE_PRESET","small")
    if preset not in FF_PRESETS:raise ValueError("Unsupported BO3 image preset")
    root=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    root.mkdir(parents=True,exist_ok=True)
    reports=[]
    with TemporaryDirectory(prefix="real-bo3-images-") as td:
        tmp=Path(td)
        hashes=set()
        xpaks={}
        for name,size in PACKAGES.items():
            target=tmp/name
            n,digest,_=download(BASE+quote(name),target)
            if n!=size:raise ValueError(f"BO3 XPAK size changed: {name}")
            meta,entries=parse_index(target)
            xpaks[name]={"original_sha256":digest,"hash_count":len(entries)}
            hashes.update(x["key"] for x in entries)
        base_meta,base_entries=read_base_index()
        xpaks["base.xpak"]={"original_index_sha256":base_meta["hash_index_sha256"],
                            "hash_count":base_meta["hash_count"],"original_file_bytes":base_meta["file_bytes"]}
        hashes.update(base_entries.keys())
        print(f"Original base.xpak index added {len(base_entries)} authenticated source hash keys",flush=True)
        for name in FF_PRESETS[preset]:
            p=tmp/name
            n,digest,_=download(BASE+quote(name),p)
            if n!=FILES[name]:raise ValueError(f"BO3 FastFile size changed: {name}")
            decoded,blocks=parse_zlib_zone(p)
            images=scan_images(decoded,hashes)
            report={"source_file":name,"original_sha256":digest,
                    "original_bytes":n,"decoded_bytes":len(decoded),
                    "zlib_blocks":blocks["block_count"],**images}
            reports.append(report)
            print(json.dumps({k:v for k,v in report.items() if k!="all_name_hashes"},sort_keys=True),flush=True)
    output={"xpak_indexes":xpaks,"files":reports}
    (root/"bo3_t7_source_images.json").write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    print(f"Scanned {len(reports)} complete source zones against {len(hashes)} original XPAK hashes",flush=True)
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BO3 original GfxImage survey failed: {e}",file=sys.stderr)
        raise SystemExit(1)
