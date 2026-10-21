#!/usr/bin/env python3
"""Recover original T7 MapEnts text identities + placements from a world FastFile.

Find authenticated source .d3dbsp names and exactly one NUL-delimited entity
string following a matching map name. Do not invent entity spawns, mesh model
mappings, or gameplay positions. This is a source body/loader-order candidate
until typed MapEnts pointer relocation independently closes.
"""
import collections,hashlib,json,os,re,struct,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from r2_download import download
from bo3_zone_decode import SOURCES,BASE,PREFIX,parse_zlib_zone,parse_directory

MAP_NAME=re.compile(rb"maps/[A-Za-z0-9_./-]{2,120}\.d3dbsp\x00")
PAIR=re.compile(r'"([^"\n]{1,160})"\s+"([^"\n]{0,8192})"')
def parse_entities(raw):
    text=raw.decode("utf-8","strict")
    objs=[];at=0
    while at<len(text):
        while at<len(text) and text[at].isspace():at+=1
        if at==len(text):break
        if text[at]!="{":raise ValueError(f"MapEnts entity {len(objs)} missing source open brace")
        at+=1
        record={}
        while True:
            while at<len(text) and text[at].isspace():at+=1
            if at>=len(text):raise ValueError("MapEnts entity unexpectedly ended")
            if text[at]=="}":at+=1;break
            m=PAIR.match(text,at)
            if m is None:raise ValueError(f"MapEnts key/value syntax fail at {at}")
            k,v=m.groups()
            if k in record:raise ValueError("MapEnts has repeated authored key in entity")
            record[k]=v
            at=m.end()
        objs.append(record)
        if len(objs)>500000:raise ValueError("BO3 entity count exceeds safety limit")
    return objs
def main():
    name=os.environ.get("BO3_WORLD_ZONE","core_frontend.ff")
    if name not in SOURCES:raise ValueError("Source not in original R2 manifest")
    with TemporaryDirectory(prefix="bo3-map-entity-") as td:
        p=Path(td)/name
        _,sha,_=download(BASE+"/"+quote(PREFIX+name,safe="/"),p)
        zone,meta=parse_zlib_zone(p)
    if meta["status"]!="end_marker":raise ValueError("T7 source decode incomplete")
    d=parse_directory(zone)
    if d["status"]!="t7_asset_table_layout_verified":raise ValueError("T7 source asset table unauthenticated")
    table=d["asset_table"]["table_offset"]
    types=[struct.unpack_from("<QQ",zone,table+i*16) for i in range(d["asset_count"])]
    mapents_rows=[i for i,(t,ptr) in enumerate(types) if t==15 and ptr==0xffffffffffffffff]
    if not mapents_rows:raise ValueError("Original typed MapEnts source root absent")
    candidates=[]
    for m in MAP_NAME.finditer(zone):
        start=m.end()
        if start>=len(zone) or zone[start:start+1]!=b"{":continue
        end=zone.find(b"\0",start,min(len(zone),start+32*1024*1024))
        if end<0:raise ValueError("Source MapEnts text lacks terminal zero")
        raw=bytes(zone[start:end])
        try:entities=parse_entities(raw)
        except Exception as err:
            candidates.append({"physical_source_name_offset":m.start(),
                 "original_map_identity":m.group()[:-1].decode(),
                 "map_entities_candidate":False,"failure":str(err)[:180]})
            continue
        classes=collections.Counter(e.get("classname","<absent>") for e in entities)
        key_counts=collections.Counter(k for e in entities for k in e)
        origin_list=[]
        for i,e in enumerate(entities):
            if "origin" not in e:continue
            try:
                xyz=[float(x) for x in e["origin"].split()]
                if len(xyz)!=3 or not all(-1e8<x<1e8 for x in xyz):continue
            except ValueError:continue
            origin_list.append((i,e.get("classname","<absent>"),xyz))
        spawn_labels=[{"entity_index":i,"classname":c,"original_origin":xyz}
           for i,c,xyz in origin_list if "spawn" in c.lower()][:12]
        candidates.append({
           "original_map_identity":m.group()[:-1].decode(),
           "physical_source_name_offset":m.start(),
           "physical_source_entity_text_start":start,
           "physical_source_entity_text_end":end,
           "entity_text_sha256":hashlib.sha256(raw).hexdigest(),
           "source_entity_bytes":len(raw),
           "map_entities_candidate":True,
           "parsed_entities":len(entities),
           "source_named_entity_classes":dict(classes.most_common(40)),
           "field_counts":dict(key_counts.most_common(25)),
           "entities_with_valid_origins":len(origin_list),
           "spawn_named_source_entities":spawn_labels,
           "first_entity_field_keys":list(entities[0])[:20] if entities else [],
        })
    out={"zone":name,"original_sha256":sha,"original_map_ents_root_rows":mapents_rows,
          "source_d3dbsp_name_candidates":len(candidates),
          "source_entity_candidates":candidates,
          "original_source_parity_limit":"Text after original map name may be entity data but full typed MapEnts struct/root ownership and game spawns are NOT admitted yet."}
    print(json.dumps(out,sort_keys=True),flush=True)
    folder=Path(os.environ.get("BO3_REPORT_DIR","reports/bo3"));folder.mkdir(parents=True,exist_ok=True)
    (folder/"bo3_original_map_entity_text_probe.json").write_text(json.dumps(out,indent=2)+"\n")
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"BO3 original MapEnts text probe blocked: {e}",file=sys.stderr);raise SystemExit(1)
