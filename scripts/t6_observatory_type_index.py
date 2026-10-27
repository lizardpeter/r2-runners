#!/usr/bin/env python3
"""Aggregate authenticated T6 source directory types across client/server."""
import argparse,importlib.util,json
from collections import Counter
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--client",type=Path,required=True)
    p.add_argument("--server",type=Path,required=True)
    p.add_argument("--parser",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    client=json.loads(a.client.read_text());server=json.loads(a.server.read_text())
    if client["schema"]!="source-observatory/t6-client-corpus/v1" or server["schema"]!="source-observatory/t6-server-corpus/v1":
        raise ValueError("Both complete original-corpus schema versions are required")
    if len(client["files"])!=215 or len(server["files"])!=356:
        raise ValueError("Refuse incomplete source fixture")
    spec=importlib.util.spec_from_file_location("original_t6_asset_names",a.parser)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    assert len(mod.ASSET_TYPES)==60
    index={t:{"type_id":i,"type":t,"entries":0,"files":0,"by_source_family":{}}
           for i,t in enumerate(mod.ASSET_TYPES)}
    seen_keys=set()
    by_family={}
    for family,source in (("client",client),("server",server)):
        for f in source["files"]:
            key=f["source_key"]
            if key in seen_keys:raise ValueError("Duplicate key in two corpora")
            seen_keys.add(key)
            if f["state"]!="xasset_directory_validated":
                raise ValueError("Do not pretend failed source is fully inventoried")
            group="client" if family=="client" else f["platform"]
            by_family[group]=by_family.get(group,0)+1
            if sum(f["type_counts"].values())!=f["xasset_count"]:
                raise ValueError("Per-file XAsset count corrupted")
            for typ,count in f["type_counts"].items():
                if typ not in index:raise ValueError("Undocumented asset type: "+typ)
                node=index[typ]
                node["entries"]+=count
                node["files"]+=1
                node["by_source_family"][group]=node["by_source_family"].get(group,0)+count
    present=[node for node in index.values() if node["entries"]]
    assert sum(x["entries"] for x in present)==client["asset_directory_entries"]+server["asset_directory_entries"]
    output={
       "schema":"source-observatory/t6-asset-types/v1",
       "files_with_eligible_directory_scan":len(seen_keys),
       "xasset_registry_types":len(index),
       "observed_types":len(present),
       "unobserved_registry_types":[x["type"] for x in index.values() if x["entries"]==0],
       "source_files_by_family":by_family,
       "total_directory_entries":sum(x["entries"] for x in present),
       "unique_logical_assets":"not_measured_patch_overrides_and_cross_zone_references",
       "semantic_complete":False,
       "proof_boundary":"XAsset directory ordinals and type counts only, across 571 original FastFiles. Duplicates, patches, per-type body semantics, references and runtime behavior not resolved.",
       "types":sorted(present,key=lambda node:(-node["entries"],node["type"]))
    }
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(output,indent=2)+"\n")
    print(json.dumps({k:v for k,v in output.items() if k not in ("types","unobserved_registry_types","proof_boundary")},indent=2))
if __name__=="__main__":main()
