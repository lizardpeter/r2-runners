"""No-retail-byte regressions for H1 index/source-topology closure."""
import pathlib
import sys
import struct
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_index_surface_verify import validate_full_indices

class IndexSourceTests(unittest.TestCase):
    def test_all_source_triangles_and_local_surface_indices(self):
        # First surface has two triangles, second one triangle. All source
        # baseIndex offsets are in original u16 index units.
        words=(0,1,2,2,1,3,0,1,2)
        data=struct.pack("<9H",*words)
        surfaces=[(0,6,4),(6,3,3)]
        result=validate_full_indices(data,0,surfaces,9)
        self.assertEqual(result["status"],"complete_original_index_array_verified")
        self.assertEqual(result["total_triangles_checked"],3)
        self.assertEqual(result["nondegenerate_triangles"],3)
    def test_off_by_two_indices_fail_source_count_boundary(self):
        words=(0,1,2,2,1,3,0,1,2)
        data=struct.pack("<9H",*words)
        surfaces=[(0,6,4),(6,3,3)]
        self.assertNotEqual(validate_full_indices(data,2,surfaces,9)["status"],
                            "complete_original_index_array_verified")
    def test_surface_triangle_going_out_of_local_vertices_is_rejected(self):
        words=(0,1,2,2,1,5)
        data=struct.pack("<6H",*words)
        result=validate_full_indices(data,0,[(0,6,4)],6)
        self.assertEqual(result["status"],"invalid_source_local_vertex_index")
    def test_duplicate_triangle_rejected_in_source_topology(self):
        words=(0,0,1)
        data=struct.pack("<3H",*words)
        result=validate_full_indices(data,0,[(0,3,3)],3)
        self.assertEqual(result["status"],"source_triangle_topology_inconsistent")

if __name__=="__main__":unittest.main()
