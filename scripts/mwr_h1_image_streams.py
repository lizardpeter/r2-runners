"""Inspect genuine MWR/H1 FastFile streamed-image header records.

Never assume which field identifies a texture PAK without source evidence. Return
candidate field statistics so the importer can discover exact dependencies
without uploading or extracting original texture bytes.
"""
from collections import Counter
import struct

MAX_ROWS = 262_144
ROW_BYTES = 24


def summarize_column(values):
    if not values:
        return {}
    uniques=len(set(values))
    counts=Counter(values)
    increasing=sum(values[i] >= values[i-1] for i in range(1,len(values)))
    return {
        "min":min(values),"max":max(values),"distinct":uniques,
        "zero_count":counts.get(0,0),
        "monotonic_nondecreasing_fraction":round(increasing/max(1,len(values)-1),5),
        "most_common":[[int(k),int(n)] for k,n in counts.most_common(8)],
    }


def analyze_stream_table(path):
    with open(path,"rb") as file:
        raw=file.read(28)
        if len(raw)!=28:
            raise ValueError("incomplete original H1 FastFile image-table prelude")
        row_count=struct.unpack_from("<I",raw,24)[0]
        if row_count>MAX_ROWS:
            raise ValueError("H1 image-table record limit exceeded")
        table=file.read(row_count*ROW_BYTES)
        if len(table)!=row_count*ROW_BYTES:
            raise ValueError("truncated original H1 streamed image record table")
    rows=[struct.unpack_from("<6I",table,index*ROW_BYTES) for index in range(row_count)]
    longrows=[struct.unpack_from("<3Q",table,index*ROW_BYTES) for index in range(row_count)]
    u16rows=[struct.unpack_from("<12H",table,index*ROW_BYTES) for index in range(row_count)]

    # This field grouping is a source-backed candidate: original row word0
    # consistently has zero low16 and varying upper16, while words2/3 and
    # words4/5 are 64-bit begin/end offsets. The eventual PAK filename
    # resolver remains separate until original retail names confirm it.
    archive_ids=Counter()
    archive_byte_spans={}
    invalid_spans=0
    raw_flags=Counter()
    for w in rows:
        source_id=w[0]>>16
        flags=w[0]&0xffff
        raw_flags[flags]+=1
        begin=w[2]|(w[3]<<32)
        end=w[4]|(w[5]<<32)
        if begin>end:
            invalid_spans+=1
        if source_id:
            archive_ids[source_id]+=1
            span=archive_byte_spans.setdefault(source_id,{
                "minimum_begin":begin,"maximum_end":end,"total_referenced_bytes":0
            })
            span["minimum_begin"]=min(span["minimum_begin"],begin)
            span["maximum_end"]=max(span["maximum_end"],end)
            span["total_referenced_bytes"]+=max(0,end-begin)
    archive_summary=[
        {"candidate_archive_id":source_id,"descriptor_count":count,
         **archive_byte_spans[source_id]}
        for source_id,count in sorted(archive_ids.items())
    ]
    return {
        "candidate_archive_id_field": "u32[0] upper16 (hypothesis pending PAK filename mapping)",
        "archive_ids":archive_summary,
        "raw_low16_flags":dict(raw_flags),
        "invalid_begin_end_spans":invalid_spans,
        "original_row_bytes":ROW_BYTES,"row_count":row_count,
        "u32_columns":[{"index":j,**summarize_column([r[j] for r in rows])} for j in range(6)],
        "u64_columns":[{"index":j,**summarize_column([r[j] for r in longrows])} for j in range(3)],
        "u16_columns":[{"index":j,**summarize_column([r[j] for r in u16rows])} for j in range(12)],
        "first_four_rows_u32":[list(r) for r in rows[:4]],
    }
