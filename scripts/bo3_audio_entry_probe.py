#!/usr/bin/env python3
"""Examine the original T7/v15 SAB audio index at authentic source offsets.

No guessing codec or decoding from header-only byte sequences. Bank header
provides #entries at 0x14, record size at 0x08, entry table offset at 0x28,
and name table offset at 0x250. Read exact authenticated R2 ranges.
"""
from __future__ import annotations
import hashlib,json,os,struct,sys
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.parse import quote
from bo3_audio_bank_headers import SIZES,FOLDER,BASE,prefix

def original_range(name,start,amount):
    total=SIZES[name]
    if amount<=0 or amount>4*1024*1024 or start<0 or start+amount>total:
        raise ValueError("Original BO3 bank index range outside authenticated source")
    url=BASE+quote(FOLDER+name,safe="/")
    req=Request(url,headers={"Range":f"bytes={start}-{start+amount-1}",
      "Accept-Encoding":"identity","User-Agent":"bo3-source-sab-index/1"})
    with urlopen(req,timeout=90) as r:
        want=f"bytes {start}-{start+amount-1}/{total}"
        if r.status!=206 or r.headers.get("Content-Range")!=want:
            raise ValueError(f"Original SAB exact source range mismatch {name}")
        v=r.read(amount+1)
    if len(v)!=amount:raise ValueError("SAB index source data truncated")
    return v

def record_sample(raw):
    return {
      "entry_bytes":len(raw),
      "source_words_u32":[f"0x{v:08x}" for v in struct.unpack("<"+str(len(raw)//4)+"I",raw)],
      "source_sha256":hashlib.sha256(raw).hexdigest(),
    }

def inspect_bank(name):
    head=prefix(name)
    if len(head)<0x258 or struct.unpack_from("<II",head,0)!=(0x23585532,15):
        raise ValueError(f"BO3 bank not original v15 SAB {name}")
    entries=struct.unpack_from("<I",head,0x14)[0]
    stride=struct.unpack_from("<I",head,0x08)[0]
    table=struct.unpack_from("<Q",head,0x28)[0]
    name_table=struct.unpack_from("<Q",head,0x250)[0]
    alternative_table=struct.unpack_from("<Q",head,0x30)[0]
    if stride!=0x24 or entries>2_000_000:
        raise ValueError(f"Unsupported original SAB record stride or count {name}")
    span=entries*stride
    if table<608 or table+span>SIZES[name] :
        raise ValueError(f"Original SAB table bounds fail {name}: entries={entries}, stride={stride}, table={table}, end={table+span}, name_offset={name_table}, size={SIZES[name]}")
    out={
      "bank":name,"file_bytes":SIZES[name],"v15_records_declared":entries,
      "record_bytes":stride,"entry_table_offset":table,
      "entry_table_end":table+span,"names_table_offset":name_table,
      "table_in_original_source_bounds":True,
      "name_table_overlap_bytes":max(0,table+span-name_table) if name_table else 0,
      "name_table_may_not_follow_index":table+span>name_table if name_table else False,
      "secondary_header_table_pointer_at_0x30":alternative_table,
      "secondary_0x30_record_samples":[],
      "sampled_records":[],
    }
    if entries:
        start=original_range(name,table,min(8,entries)*stride)
        out["sampled_records"]=[
          {"index":i,"offset":table+i*stride,**record_sample(start[i*stride:(i+1)*stride])}
          for i in range(min(8,entries))
        ]
        out["first_entries_bytes_sha256"]=hashlib.sha256(start).hexdigest()
        if 608<=alternative_table and alternative_table+stride*3<=SIZES[name]:
            other=original_range(name,alternative_table,min(3,entries)*stride)
            out["secondary_0x30_record_samples"]=[record_sample(other[i*stride:(i+1)*stride]) for i in range(min(3,entries))]
    if entries:
        original=original_range(name,table,span)
        physical_bounds=0
        playable_audio=0
        rates={}
        channel_sizes={}
        flac_examples=[]
        bad=[]
        for i in range(entries):
            raw=original[i*stride:(i+1)*stride]
            key,size,frames,_reserved=struct.unpack_from("<IIII",raw,0)
            file_offset=struct.unpack_from("<Q",raw,0x10)[0]
            flags=struct.unpack_from("<I",raw,0x18)[0]
            rate=flags&0xff
            channels=(flags>>8)&0xff
            physical=(size==0 or (file_offset>=608 and file_offset+size<=table))
            if physical:
                physical_bounds+=1
            else:
                bad.append({"ordinal":i,"source_offset":file_offset,"source_size":size})
            if size and physical and 0<=rate<=8 and channels in (1,2,4,6,8):
                playable_audio+=1
            rates[str(rate)]=rates.get(str(rate),0)+1
            channel_sizes[str(channels)]=channel_sizes.get(str(channels),0)+1
            if size>=4 and physical and len(flac_examples)<3:
                source_magic=original_range(name,file_offset,4)
                flac_examples.append({"record":i,"magic_ascii":source_magic.decode("latin1"),
                    "is_fLaC":source_magic==b"fLaC","source_bytes":size,
                    "original_offset":file_offset,"frame_count":frames,
                    "source_key":f"0x{key:08x}"})
        out["original_entry_index_sha256"]=hashlib.sha256(original).hexdigest()
        out["full_source_audio_entry_bound_count"]=physical_bounds
        out["source_audio_entries_with_plausible_metadata"]=playable_audio
        out["sample_rate_index_histogram"]=rates
        out["channel_histogram"]=channel_sizes
        out["invalid_source_audio_byte_ranges"]=bad[:12]
        out["first_source_payload_flac_samples"]=flac_examples
    return out

def main():
    records=[inspect_bank(n) for n in SIZES]
    summary={
        "original_t7_sab_banks":len(records),
        "nonempty_index_banks":sum(x["v15_records_declared"]>0 for x in records),
        "zero_entry_banks":sum(x["v15_records_declared"]==0 for x in records),
        "source_audio_records_declared":sum(x["v15_records_declared"] for x in records),
        "source_entries_with_bounded_payloads":sum(x.get("full_source_audio_entry_bound_count",0) for x in records),
        "source_audio_entries_with_plausible_metadata":sum(x.get("source_audio_entries_with_plausible_metadata",0) for x in records),
        "sampled_first_audio_payload_flac_headers":sum(e["is_fLaC"] for x in records for e in x.get("first_source_payload_flac_samples",[])),
        "note":"Original source entry byte ranges/FLAC signatures verified; full decoded PCM playback and sound alias ownership remain separate.",
    }
    out={"summary":summary,"banks":records}
    print(json.dumps(out,sort_keys=True),flush=True)
    p=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));p.mkdir(parents=True,exist_ok=True)
    (p/"bo3_original_sound_index_probe.json").write_text(json.dumps(out,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"BO3 original SAB index check failed: {e}",file=sys.stderr);raise SystemExit(1)
