"""H1 native 0x280 clipMap_t structural discovery across block boundaries."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_clipmap_named_scanner import (
    classify_clipmap_root_at,H1NamedClipMapScanner
)
from mwr_h1_clipmap_source import INLINE,ROOT_BYTES
class H1OriginalNamedClipMapTests(unittest.TestCase):
    def root(self):
        b=bytearray(ROOT_BYTES)
        struct.pack_into("<Q",b,0,INLINE)
        struct.pack_into("<I",b,8,1)
        for c,p,n in [(16,24,200),(32,40,6),(144,152,120),
                      (112,120,350),(272,280,96),
                      (288,296,128),(304,312,4)]:
            struct.pack_into("<I",b,c,n)
            struct.pack_into("<Q",b,p,INLINE)
        return bytes(b)+b"maps/mp/source_fixture.d3dbsp\0"
    def test_native_owned_name_and_collision_fields_cross_decoded_chunks(self):
        source=self.root()
        finding=classify_clipmap_root_at(source,0)
        self.assertEqual(finding["source_counts"]["plane_count"],200)
        self.assertEqual(finding["source_counts"]["brush_count"],120)
        self.assertTrue(finding["clipmap_name_extension_looks_like_map"])
        blob=b"\xfa"*137+source+b"\xfb"*300
        scanner=H1NamedClipMapScanner()
        for at in range(0,len(blob),115):
            scanner.push(blob[at:at+115])
        report=scanner.report()
        self.assertEqual(report["candidate_count"],1)
        self.assertEqual(report["first_20"][0]["original_source_offset"],137)
    def test_bad_count_pointer_or_missing_authored_name_rejected(self):
        raw=bytearray(self.root())
        struct.pack_into("<Q",raw,152,0)
        self.assertIsNone(classify_clipmap_root_at(raw,0))
        raw=bytearray(self.root())
        raw[ROOT_BYTES:ROOT_BYTES+4]=bytes([255]*4)
        self.assertIsNone(classify_clipmap_root_at(raw,0))
if __name__=="__main__":unittest.main()
