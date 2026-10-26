"""Source-order authenticated native H1 ClipMap root, no map-specific offsets."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_clipmap_source import (
    inspect_first_authored_clipmap,clipmap_fields,pointer_kind,ROOT_BYTES,INLINE
)
class TestClipMapSource(unittest.TestCase):
    def fixture(self):
        at=100
        raw=bytearray(at+ROOT_BYTES)
        struct.pack_into("<Q",raw,at,INLINE)
        struct.pack_into("<I",raw,at+8,1)
        for offset,num,ptr_offset in [(16,200,24),(32,18,40),(112,170,120),
                                      (128,440,136),(144,40,152),
                                      (176,96,184),(192,48,200),(272,50,280),
                                      (288,80,296),(304,2,312)]:
            struct.pack_into("<I",raw,at+offset,num)
            struct.pack_into("<Q",raw,at+ptr_offset,INLINE)
        raw+=b"maps/mp/source_fixture.d3dbsp\0"
        verified={"status":"fully_verified","validated_tables":[{
            "end_offset":at,"first_16_asset_types":[24],
        }]}
        return raw,verified
    def test_authored_root_reads_exact_fields_and_source_name(self):
        raw,verified=self.fixture()
        output=inspect_first_authored_clipmap(raw,verified)
        self.assertEqual(output["status"],"authored_type24_source_root_structural")
        self.assertEqual(output["original_source_offset"],100)
        self.assertEqual(output["original_source_name"],"maps/mp/source_fixture.d3dbsp")
        self.assertEqual(output["typed_native_fields"]["plane_count"],200)
        self.assertEqual(output["typed_native_fields"]["brush_count"],40)
        self.assertEqual(output["typed_native_fields"]["collision_triangle_count"],48)
        self.assertFalse(output["nested_collision_arrays_admitted"])
    def test_invalid_null_pointer_and_without_asset_ownership(self):
        raw,verified=self.fixture()
        struct.pack_into("<Q",raw,100+152,0)
        output=inspect_first_authored_clipmap(raw,verified)
        self.assertIn("brush_count_nonzero_brushes_null",output["unresolved_conditions"])
        self.assertEqual(inspect_first_authored_clipmap(raw,{"status":"ambiguous"})["status"],
                         "not_a_unique_original_asset_directory")
        verified["validated_tables"][0]["first_16_asset_types"]=[31]
        self.assertEqual(inspect_first_authored_clipmap(raw,verified)["status"],
                         "first_original_asset_not_clipmap")
if __name__=="__main__":unittest.main()
