"""Bounded, source-independent H1 binary body candidate invariants."""
import math
import pathlib
import struct
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_asset_body_probe import H1TypedBodyScanner,INLINE,material,image,xmodel,clipmap,technique_set,shader

def candidate(kind):
    sizes={"material":0x250,"image":0x68,"xmodel":0x2a8,"clipmap":0x280,"technique_set":0x790,"shader":0x20}
    b=bytearray(sizes[kind])
    if kind=="material":
        b[0:8]=INLINE
        b[288]=2;b[289]=1;b[290]=1
        b[296:304]=INLINE;b[304:312]=INLINE
        b[312:320]=INLINE;b[320:328]=INLINE
    if kind=="image":
        b[96:104]=INLINE
        struct.pack_into("<I",b,24,71);b[28]=3
        struct.pack_into("<HHHH",b,44,256,128,1,1)
        b[52]=7;b[53]=1
    if kind=="xmodel":
        b[0:8]=INLINE
        b[8]=4;b[9]=1;b[10]=2
        struct.pack_into("<f",b,16,1.0)
        b[120:128]=INLINE
        b[512]=1
        b[136:144]=INLINE
    if kind=="technique_set":
        b[0:8]=INLINE;b[16+41*8:24+41*8]=INLINE
    if kind=="shader":
        b[0:8]=INLINE;b[16:24]=INLINE
        struct.pack_into("<II",b,24,1783,0x12345678)
    if kind=="clipmap":
        b[0:8]=INLINE
        for co,po,count in [(16,24,600),(32,40,5),
                            (272,280,100),(288,296,120),
                            (304,312,10),(144,152,42)]:
            struct.pack_into("<I",b,co,count);b[po:po+8]=INLINE
    return bytes(b)

class TestTypedSource(unittest.TestCase):
    def test_root_candidates_cross_block_boundaries(self):
        for kind,validator in [
            ("material",material),("image",image),
            ("xmodel",xmodel),("clipmap",clipmap),
            ("technique_set",technique_set),("shader",shader)
        ]:
            raw=candidate(kind)
            with self.subTest(kind=kind):
                self.assertIsNotNone(validator(raw,0))
                start=89
                zone=b"\xf6"*start+raw+b"\xf6"*19
                scan=H1TypedBodyScanner()
                for i in range(0,len(zone),67):scan.push(zone[i:i+67])
                report=scan.report()["candidates"][kind]
                self.assertEqual(report["count"],1)
                self.assertEqual(report["first_30"][0]["decoded_source_offset"],start)
    def test_truncated_and_invalid_records_fail_closed(self):
        raw=bytearray(candidate("material"))
        self.assertIsNone(material(raw[:-1],0))
        raw[304:312]=b"\0"*8
        self.assertIsNone(material(raw,0))
        raw=bytearray(candidate("image"))
        raw[52]=0
        self.assertIsNone(image(raw,0))
        raw=bytearray(candidate("xmodel"))
        raw[512]=7
        self.assertIsNone(xmodel(raw,0))
        raw=bytearray(candidate("clipmap"))
        raw[24:32]=b"\0"*8
        self.assertIsNone(clipmap(raw,0))
        raw=bytearray(candidate("technique_set"))
        raw[16+41*8:24+41*8]=bytes(8)
        self.assertIsNone(technique_set(raw,0))
        raw=bytearray(candidate("shader"))
        struct.pack_into("<I",raw,24,0)
        self.assertIsNone(shader(raw,0))

if __name__=="__main__":unittest.main()
