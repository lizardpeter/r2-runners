#!/usr/bin/env python3
"""Bounded R2 access diagnostics: GET only two bytes, never download original game."""
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import json

OBJECTS = [
 "https://r2.houseofkublai.com/downloads/games/pluto_iw5_full_game.zip",
 "https://r2.xeniea.com/downloads/games/pluto_iw5_full_game.zip",
 "https://r2.houseofkublai.com/downloads/games/pluto_t5_full_game.zip",
 "https://r2.houseofkublai.com/Downloads/HOK_Gamerpics/512_HK_Holder.png",
]
for url in OBJECTS:
 for method in ("HEAD", "GET"):
  headers = {"Accept-Encoding":"identity","User-Agent":"r2-runners-iw5-source-probe/1.0"}
  if method == "GET":
   headers["Range"]="bytes=0-1"
  try:
   with urlopen(Request(url,headers=headers,method=method), timeout=25) as r:
    payload = r.read(2) if method == "GET" else b""
    print(json.dumps({"url":url, "method":method,"status":r.status,
         "range":r.headers.get("Content-Range"),
         "size":r.headers.get("Content-Length"),"cf_ray":r.headers.get("cf-ray"),
         "content_type":r.headers.get("Content-Type"),
         "first_two_hex":payload.hex()}))
  except HTTPError as e:
   print(json.dumps({"url":url,"method":method,"status":e.code,
        "cf_ray":e.headers.get("cf-ray"),"content_type":e.headers.get("Content-Type"),
        "error_excerpt":e.read(160).decode("utf-8","replace")}))
  except Exception as e:
   print(json.dumps({"url":url,"method":method,"error":str(e)[:160]}))
