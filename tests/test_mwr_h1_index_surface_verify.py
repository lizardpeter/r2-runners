"""Pure synthetic H1 per-surface u16 index validation regression."""
import pathlib
import struct
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_index_surface_verify import inspect_candidate_indices

class H1IndexLinkageTests(unittest.TestCase):
    def test_original_surface_local_indices_are_not_global_world_indices(self):
        source=[0,1,2,1,2,0,0,1,2,0,1,2,2,3,4]
        data=struct.pack("<"+str(len(source))+"H",*source)
        constraints=[
            (0,6,3,0),
            (6,3,4,10),
            (9,6,5,40),
        ]
        result=inspect_candidate_indices(data,0,constraints,len(source),full=True)
        self.assertIsNotNone(result)
        self.assertEqual(result["total_triangles_checked"],5)
        self.assertEqual(result["nondegenerate_triangles"],5)
        bad=bytearray(data)
        bad[6*2:6*2+2]=struct.pack("<H",99)
        self.assertIsNone(inspect_candidate_indices(bad,0,constraints,len(source),full=True))
        self.assertIsNone(inspect_candidate_indices(data,2,constraints,len(source),full=True))

if __name__=="__main__":
    unittest.main()
