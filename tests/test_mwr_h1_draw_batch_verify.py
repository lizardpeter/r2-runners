import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_draw_batch_verify import verify_array_draw_batches


def world_fixture(counts=(4, 4)):
    surfaces=bytearray()
    indexes=bytearray()
    first_vertex=0
    for triangles in counts:
        row=bytearray(40)
        struct.pack_into("<I",row,4,first_vertex)
        struct.pack_into("<H",row,16,3)
        struct.pack_into("<H",row,18,triangles)
        struct.pack_into("<I",row,20,len(indexes)//2)
        surfaces.extend(row)
        for _ in range(triangles):
            indexes.extend(struct.pack("<3H",0,1,2))
        first_vertex+=3
    return indexes,surfaces,first_vertex


class H1OriginalDrawBatches(unittest.TestCase):
    def test_original_faces_preserved_across_source_surface_boundaries(self):
        words,surfaces,vertex_count=world_fixture()
        report=verify_array_draw_batches(words,surfaces,vertex_count,
                                         len(words)//2,max_triangles=4)
        self.assertEqual(report["status"],"fully_closed_source_order_renderer_draw_batches")
        self.assertEqual(report["original_source_surfaces_preserved"],2)
        self.assertEqual(report["original_triangles_preserved"],8)
        self.assertEqual(report["diagnostic_renderer_batches"],2)
        self.assertEqual(report["batched_source_vertex_references"],6)
        self.assertEqual(report["largest_batch_triangles"],4)
        self.assertEqual([(x["start_source_surface"],x["end_source_surface_exclusive"])
                         for x in report["first_12_source_batches"]],[(0,1),(1,2)])

    def test_source_surface_local_vertex_outside_span_fails(self):
        words,surfaces,vc=world_fixture()
        struct.pack_into("<H",words,0,3)
        with self.assertRaisesRegex(ValueError,"nonlocal"):
            verify_array_draw_batches(words,surfaces,vc,len(words)//2,max_triangles=4)

    def test_source_index_coverage_must_be_disjoint_and_gap_free(self):
        words,surfaces,vc=world_fixture()
        # Second surface reuses the first surface index range while leaving
        # the tail unowned; counts and maximum index values alone cannot prove.
        struct.pack_into("<I",surfaces,40+20,0)
        with self.assertRaisesRegex(ValueError,"gap/overlap"):
            verify_array_draw_batches(words,surfaces,vc,len(words)//2,max_triangles=4)

    def test_source_vertex_span_must_fit_original_world(self):
        words,surfaces,vc=world_fixture()
        struct.pack_into("<I",surfaces,40+4,99)
        with self.assertRaisesRegex(ValueError,"outside world"):
            verify_array_draw_batches(words,surfaces,vc,len(words)//2,max_triangles=4)

    def test_no_partial_surface_or_unbounded_batch(self):
        words,surfaces,vc=world_fixture(counts=(5,2))
        with self.assertRaisesRegex(ValueError,"policy cap"):
            verify_array_draw_batches(words,surfaces,vc,len(words)//2,max_triangles=4)
        with self.assertRaisesRegex(ValueError,"span size/count mismatch"):
            verify_array_draw_batches(words[:-2],surfaces,vc,len(words)//2,4)
        with self.assertRaisesRegex(ValueError,"invalid H1 diagnostic"):
            verify_array_draw_batches(words,surfaces,vc,len(words)//2,65_536)


if __name__=="__main__":
    unittest.main()
