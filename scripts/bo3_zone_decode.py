#!/usr/bin/env python3
"""Decode *real* BO3/T7 PC FastFiles in runner scratch RAM, survey XAsset entries.

No unpacked asset body, original script strings, or retail file is uploaded.
Decoded asset IDs/types in the report are metadata, not visual importer coverage.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory
import zlib
from urllib.parse import quote

from r2_download import download

BASE = "https://r2.houseofkublai.com"
PREFIX = "bo3/DUMP/zone/"
SOURCES = {
    "core_all.ff": 704,
    "en_core_common.ff": 545024,
    "core_gfx.ff": 6790208,
    "core_pre_gfx.ff": 22285376,
    "core_ui.ff": 25129024,
    "en_core_frontend.ff": 2977856,
}
PRESETS = {
    "small": ["en_core_common.ff", "core_gfx.ff", "core_pre_gfx.ff"],
    "ui": ["core_ui.ff", "en_core_frontend.ff"],
    "all": list(SOURCES),
}
TYPE_NAMES = {
    0:"physpreset",1:"physconstraints",2:"destructibledef",3:"xanim",
    4:"xmodel",5:"xmodelmesh",6:"material",7:"computeshaderset",
    8:"techset",9:"image",10:"sound",11:"sound_patch",12:"col_map",
    13:"com_map",14:"game_map",15:"map_ents",16:"gfx_map",
    17:"lightdef",18:"lensflaredef",19:"ui_map",20:"font",
    21:"fonticon",22:"localize",23:"weapon",38:"fx",
    47:"rawfile",48:"stringtable",53:"texturelist",54:"scriptparsetree",
    69:"scriptbundle",82:"lightdescription",84:"xcam",96:"umbra_tome",
    97:"navmesh",98:"navvolume",
}
MAX_DECODED = 256 * 1024 * 1024
MAX_BLOCKS = 2048

def parse_zlib_zone(path: Path) -> tuple[bytearray, dict]:
    source_size = path.stat().st_size
    decoded = bytearray()
    blocks = []
    with path.open("rb") as reader:
        header = reader.read(0x248)
        if len(header) != 0x248 or header[:8] != b"TAff0000":
            raise ValueError("Unknown T7 FastFile magic or truncated header")
        version = struct.unpack_from("<I",header,8)[0]
        flags = list(header[12:16])
        if version != 0x251 or flags[1] != 1 or flags[2] != 0 or flags[3] != 0:
            raise ValueError(f"Unsupported T7 header version {version:#x} / codec/platform/encryption {flags}")
        pos = 0x248
        status = "block_limit_exhausted"
        for number in range(MAX_BLOCKS):
            if pos + 16 > source_size:
                raise ValueError(f"Block header beyond original FF at {pos:#x}")
            reader.seek(pos)
            row = reader.read(16)
            if len(row) != 16:
                raise ValueError("Truncated T7 block header")
            compressed, plain_len, span, stored_pos = struct.unpack("<IIII", row)
            if span == 0:
                status="end_marker"
                break
            if stored_pos != pos or not compressed or not plain_len or span < compressed:
                raise ValueError(f"Bad T7 block {number}: ({compressed},{plain_len},{span},{stored_pos}) at {pos:#x}")
            if compressed > 128 * 1024 * 1024 or plain_len > 128 * 1024 * 1024:
                raise ValueError("BO3 block expansion exceeds safety limit")
            if pos + 16 + span > source_size:
                raise ValueError("Block extends past original FF")
            if len(decoded) + plain_len > MAX_DECODED:
                status="decoded_budget_reached"
                break
            data = reader.read(compressed)
            obj = zlib.decompressobj()
            plain = obj.decompress(data, plain_len + 1)
            plain += obj.flush()
            if len(plain)!=plain_len or not obj.eof or obj.unconsumed_tail or obj.unused_data:
                raise ValueError(f"T7 zlib decode mismatch at block {number}")
            decoded.extend(plain)
            blocks.append({"source_offset":pos,"compressed_bytes":compressed,"decoded_bytes":plain_len,
                           "span_bytes":span,"decoded_sha256":hashlib.sha256(plain).hexdigest()})
            pos += 16 + span
    return decoded, {
        "status":status, "block_count":len(blocks),
        "decoded_bytes":len(decoded), "source_bytes":source_size,
        "first_blocks":blocks[:5], "last_block":blocks[-1] if blocks else None,
    }

def align8(n:int)->int:
    return (n+7)&~7

def parse_directory(data:bytearray)->dict:
    if len(data)<64:
        return {"status":"insufficient_zone_data"}
    string_count,asset_count=struct.unpack_from("<I",data,0)[0],struct.unpack_from("<I",data,32)[0]
    info={"script_string_count":string_count,"asset_count":asset_count,"decoded_header_hex_64":data[:64].hex()}
    if string_count>500000 or asset_count>2_000_000:
        return {**info,"status":"count_limit"}
    # Independent research reference: T7 has a 56-byte prelude followed by
    # (count-1)*8 bytes of source script-string pointer entries.
    string_start=56+(string_count-1)*8
    if string_count == 0:
        string_start=48
    if string_start >= len(data):
        return {**info,"status":"script_string_start_out_of_bounds"}
    strings=[]
    cursor=string_start
    for idx in range(string_count):
        end=data.find(b"\0",cursor, cursor+4096)
        if end < 0:
            return {**info,"status":"script_string_not_null_terminated","string_index":idx}
        value=bytes(data[cursor:end])
        if not value or any(c < 32 or c>=127 for c in value):
            return {**info,"status":"non_printable_script_string","string_index":idx,
                    "string_start":string_start}
        strings.append(value.decode("ascii"))
        cursor=end+1
    candidate=align8(cursor)
    # Inspect exactly the *record layout* used by T7, with header u64 + type
    # byte (remaining seven bytes padding). Do not infer asset body pointers.
    # Validate all entries, not one plausible-looking row.
    def inspect_at(start:int)->dict|None:
        end=start+asset_count*16
        if end>len(data):
            return None
        raw=memoryview(data)[start:end]
        types=[]
        invalid=[]
        header_kinds=Counter()
        for idx in range(asset_count):
            row=raw[idx*16:(idx+1)*16]
            ptr=int.from_bytes(row[:8],"little")
            typ=row[8]
            padding=bytes(row[9:16])
            types.append(typ)
            if typ>103 or padding!=b"\x00"*7:
                if len(invalid)<4:invalid.append({"index":idx,"type":typ,"padding_hex":padding.hex(),"header":f"0x{ptr:016x}"})
            header_kinds[f"0x{ptr:016x}"] += 1
        plausible=sum(1 for i in range(asset_count) if types[i]<=103 and bytes(raw[i*16+9:i*16+16]) == b"\0"*7)
        return {"table_offset":start,"candidate_records":asset_count,"plausible_records":plausible,
                "first_record_hex":bytes(raw[:16]).hex() if asset_count else None,
                "type_counts":{f"{t}:{TYPE_NAMES.get(t,'other')}":n for t,n in sorted(Counter(types).items())},
                "pointer_pattern_counts":dict(header_kinds.most_common(8)),
                "invalid_examples":invalid}
    options=[(candidate+i,inspect_at(candidate+i)) for i in (0,8,16,24,32)]
    options=[item for item in options if item[1] is not None]
    options.sort(key=lambda x:(x[1]["plausible_records"], -abs(x[0]-candidate)),reverse=True)
    if not options:
        return {**info,"status":"asset_table_out_of_bounds","string_start":string_start,"string_end":cursor}
    chosen_offset, best=options[0]
    credible=asset_count>0 and best["plausible_records"]==asset_count
    return {**info,
            "status":"plausible_t7_asset_table" if credible else "asset_table_not_verified",
            "script_strings_parsed":len(strings),
            "script_string_examples":strings[:8],
            "string_start":string_start,"string_end":cursor,"aligned_table_candidate":candidate,
            "asset_table":best,
            "candidate_offsets":[{"offset":k,"plausible":x["plausible_records"]} for k,x in options]}

def run():
    preset=os.environ.get("BO3_ZONE_PRESET","small")
    if preset not in PRESETS:
        raise ValueError("Invalid source preset")
    report_dir=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"))
    report_dir.mkdir(parents=True,exist_ok=True)
    reports=[]
    with TemporaryDirectory(prefix="bo3-authentic-") as temp:
        for filename in PRESETS[preset]:
            key=PREFIX+filename
            target=Path(temp)/filename
            if SOURCES[filename] > 40 * 1024 * 1024:
                raise ValueError("Refusing source larger than BO3 research budget")
            byte_count,digest,_type=download(BASE+"/"+quote(key,safe="/"),target)
            if byte_count != SOURCES[filename]:
                raise ValueError(f"Original R2 object length does not match authenticated listing: {key}")
            decoded,blocks=parse_zlib_zone(target)
            directory=parse_directory(decoded)
            report={"key":key,"original_sha256":digest,"original_file_bytes":byte_count,
                    "blocks":blocks,"xasset_directory":directory}
            reports.append(report)
            # Original retail data and script text are NOT saved in outputs.
            print(json.dumps(report,sort_keys=True),flush=True)
    (report_dir/"bo3_real_zone_inventory.json").write_text(
        json.dumps({"preset":preset,"samples":reports},indent=2)+"\n",encoding="utf-8")
    print(f"Validated {len(reports)} BO3 original FastFiles, metadata only",flush=True)

if __name__=="__main__":
    try:
        run()
    except Exception as error:
        print(f"BO3 original source zone decode failed: {error}",file=sys.stderr)
        raise SystemExit(1)
