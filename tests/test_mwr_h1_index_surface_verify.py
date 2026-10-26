"""Source-order-independent, complete H1 u16 world-index partition tests."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from mwr_h1_index_surface_verify import validate_full_indices


class H1IndexLinkageTests(unittest.TestCase):
    def setUp(self):
        self.original = struct.pack("<9H", 0, 1, 2, 0, 1, 2, 0, 1, 2)

    def test_complete_partition_accepts_unordered_surface_records(self):
        surfaces = [(6, 3, 3), (0, 3, 3), (3, 3, 3)]
        result = validate_full_indices(self.original, 0, surfaces, 9)
        self.assertEqual(result["status"], "complete_original_index_array_verified")
        self.assertTrue(result["original_index_partition_gap_free"])
        self.assertEqual(result["total_triangles_checked"], 3)

    def test_overlapping_ranges_with_equal_total_and_last_end_are_rejected(self):
        # The old count/high-water checks both passed this corrupted layout.
        surfaces = [(0, 3, 3), (0, 3, 3), (6, 3, 3)]
        result = validate_full_indices(self.original, 0, surfaces, 9)
        self.assertEqual(result["status"], "original_surface_indices_overlap_or_have_gap")

    def test_duplicate_reference_count_and_invalid_local_index_rejected(self):
        overcount = [(0, 6, 3), (6, 3, 3), (6, 3, 3)]
        result = validate_full_indices(self.original, 0, overcount, 9)
        self.assertEqual(result["status"], "surface_index_count_mismatch")
        broken = bytearray(self.original)
        broken[12:14] = struct.pack("<H", 99)
        good_ranges = [(0, 3, 3), (3, 3, 3), (6, 3, 3)]
        result = validate_full_indices(broken, 0, good_ranges, 9)
        self.assertEqual(result["status"], "invalid_source_local_vertex_index")

    def test_truncated_original_buffer_is_rejected(self):
        result = validate_full_indices(self.original[:-2], 0, [(0, 9, 3)], 9)
        self.assertEqual(result["status"], "truncated_source_index_bytes")


if __name__ == "__main__":
    unittest.main()
