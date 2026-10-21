"""Synthetic invariants for the generic H1 44-byte source vertex scanner.

No retail content. Exercise fractional binormalSign and negative all-zero
memory to prevent a false source geometry win.
"""
import pathlib
import struct
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_world_vertex_probe import WorldVertexRunScanner

def source_vertex(index:int,sign:float):
    packed=bytearray(44)
    struct.pack_into("<ffff",packed,0,591.5+index,-607.,234.5,sign)
    struct.pack_into("<ffff",packed,20,-2.15527,-5.25391,0.07876,0.58632)
    struct.pack_into("<II",packed,36,0xDEADBEEF,0x12345678)
    return bytes(packed)

class SourceVertexScannerTests(unittest.TestCase):
    def test_fractional_binormal_preserved_across_blocks(self):
        authored=(b"\0"*7+
            b"".join(source_vertex(i,1.0 if i<20 else -0.0070553) for i in range(512))+
            b"END")
        p=WorldVertexRunScanner()
        for start in range(0,len(authored),65536):
            p.push(authored[start:start+65536])
        report=p.report()
        self.assertTrue(any(x["potential_vertices"]>=512
                            for x in report["longest_clusters"]),report)
    def test_zero_bytes_are_not_mesh_vertices(self):
        p=WorldVertexRunScanner()
        p.push(bytes(65536))
        report=p.report()
        self.assertEqual(report["source_run_clusters"],0,report)

if __name__=="__main__":
    unittest.main()
