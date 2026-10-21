"""Inspect genuine MWR/H1 FastFile streamed-image header records.

Never assume which word is a pak index without source validation. Return
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
    return {
        "original_row_bytes":ROW_BYTES,"row_count":row_count,
        "u32_columns":[{"index":j,**summarize_column([r[j] for r in rows])} for j in range(6)],
        "u64_columns":[{"index":j,**summarize_column([r[j] for r in longrows])} for j in range(3)],
        "u16_columns":[{"index":j,**summarize_column([r[j] for r in u16rows])} for j in range(12)],
        "first_four_rows_u32":[list(r) for r in rows[:4]],
    }
