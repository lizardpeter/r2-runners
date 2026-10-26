"""Verify H1 serialized material pointer block bounds without relocation."""
import pathlib,sys,unittest
from collections import Counter
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_surface_verify import inspect_source_material_tag_blocks

class H1MaterialReferenceProof(unittest.TestCase):
    def test_block3_pointer_ref_is_in_original_declared_zone_capacity(self):
        blocks=[100,0,200,4096,0,0,0]
        pointers=Counter({0xfdfdfdf300000100:42,0xfdfdfdf300000fff:7})
        report=inspect_source_material_tag_blocks(pointers,blocks)
        self.assertEqual(report["status"],"all_source_material_refs_fit_blocks")
        self.assertEqual(report["source_virtual_block_candidates"][3]["reference_count"],49)
        self.assertEqual(report["source_virtual_block_candidates"][3]["distinct_tags"],2)
    def test_out_of_range_or_unrecognized_tag_never_claims_material_binding(self):
        blocks=[100,0,200,4096,0,0,0]
        pointers=Counter({0xfdfdfdf300001000:1,0x12345678:1})
        report=inspect_source_material_tag_blocks(pointers,blocks)
        self.assertEqual(report["status"],"unresolved_source_reference_bounds")
        self.assertEqual(len(report["bounded_invalid_tag_samples"]),2)
    def test_inline_specials_are_not_offset_references(self):
        blocks=[100,0,200,4096,0,0,0]
        report=inspect_source_material_tag_blocks(Counter({
            0:1,0xFDFDFDFFFFFFFFFE:2,0xFDFDFDFFFFFFFFFF:3
        }),blocks)
        self.assertEqual(report["status"],"all_source_material_refs_fit_blocks")
        self.assertEqual(report["source_virtual_block_candidates"],{})
if __name__=="__main__":unittest.main()
