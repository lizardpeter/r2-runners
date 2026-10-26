"""Authenticate first H1 240-technique-slot root using full original XAsset table."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_technique_order_source import (
    inspect_first_authored_technique_set,ROOT_BYTES,INLINE
)
class FirstAuthoredTechniqueSetTests(unittest.TestCase):
    def test_exact_original_asset_offset_and_native_slot_identity(self):
        at=143
        blob=bytearray(at+ROOT_BYTES)
        struct.pack_into("<Q",blob,at,INLINE)
        blob[at+10]=5
        struct.pack_into("<Q",blob,at+16+73*8,INLINE)
        struct.pack_into("<Q",blob,at+16+239*8,0xFDFDFDF300001000)
        blob+=b"technique_set_fixture\0"
        table={"status":"fully_verified","validated_tables":[{
            "first_16_asset_types":[15],"end_offset":at
        }]}
        report=inspect_first_authored_technique_set(blob,table)
        self.assertEqual(report["status"],
            "source_owned_first_type15_fixed_header_and_name_verified")
        self.assertEqual(report["source_name"],"technique_set_fixture")
        self.assertEqual(report["original_world_vertex_format"],5)
        self.assertEqual([x["slot"] for x in report["first_12_original_active_slots"]],[73,239])
        self.assertEqual(report["original_populated_technique_slots"],2)
    def test_non_owned_asset_or_bad_name_is_not_admitted(self):
        raw=bytearray(140+ROOT_BYTES)
        struct.pack_into("<Q",raw,140,INLINE)
        struct.pack_into("<Q",raw,140+16,INLINE)
        raw+=bytes([255])*12
        source={"status":"fully_verified","validated_tables":[{
            "first_16_asset_types":[15],"end_offset":140
        }]}
        result=inspect_first_authored_technique_set(raw,source)
        self.assertEqual(result["status"],
            "source_owned_first_type15_header_needs_nested_loader_research")
        source["validated_tables"][0]["first_16_asset_types"]=[8]
        self.assertEqual(inspect_first_authored_technique_set(raw,source)["status"],
                         "first_authored_asset_not_technique_set")
if __name__=="__main__":unittest.main()
