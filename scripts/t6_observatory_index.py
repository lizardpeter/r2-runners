#!/usr/bin/env python3
"""Index only successfully verified T6 observatory reports; refuse duplicates."""
import argparse,json
from pathlib import Path
def main():
    p=argparse.ArgumentParser()
    p.add_argument("reports",type=Path)
    a=p.parse_args()
    entries=[]
    for path in sorted(a.reports.glob("*.json")):
        if path.name=="index.json":continue
        report=json.loads(path.read_text())
        if report.get("schema")!="source-observatory/t6-expanded/v1": raise ValueError(f"bad schema {path}")
        if report["coverage"]["semantic_complete"] or report["coverage"]["byte_complete"]:
            raise ValueError("directory-only reports cannot claim full coverage")
        row={
           "source_key":report["source"]["r2_key"],"source_bytes":report["source"]["bytes"],
           "source_sha256":report["source"]["sha256"],
           "expanded_bytes":report["expanded"]["bytes"],"expanded_sha256":report["expanded"]["sha256"],
           "expanded_independently_pinned":report["expanded"]["independent_expected_sha256_matched"],
           "asset_count":report["xfile"]["asset_count"],
           "script_strings":report["xfile"]["script_strings"],
           "structural_bytes":report["coverage"]["known_structural_expanded_bytes"],
           "unknown_bytes":report["coverage"]["unclassified_expanded_bytes"],
           "type_counts":report["type_counts"],
           "report_file":path.name,
           "evidence":"pinned-retail-sha256 + exact FastFile decrypt/expand + directory walk",
           "semantic_complete":False,
           "byte_complete":False
        }
        if any(x["source_key"]==row["source_key"] for x in entries): raise ValueError("duplicate original source key")
        entries.append(row)
    if not entries:raise ValueError("no successful reports")
    index={"schema":"source-observatory/t6-index/v1",
           "corpus":"Selected original PC T6 FastFiles, not the full BO2 R2 corpus",
           "complete_corpus":False,
           "proof_boundary":"Asset body structures and semantic byte coverage are not demonstrated.",
           "files":entries}
    out=a.reports/"index.json"
    out.write_text(json.dumps(index,indent=2)+"\n")
    print(f"verified T6 report index: {len(entries)} exact-source FastFiles")
if __name__=="__main__": main()
