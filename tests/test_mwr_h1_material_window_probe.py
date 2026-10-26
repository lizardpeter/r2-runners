"""H1 original MaterialTextureDef source-byte candidate checks."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_material_window_probe import texture_at,pointer_kind,INLINE
class H1MaterialTextureWords(unittest.TestCase):
    def test_preserves_original_texture_hash_semantic_and_source_pointer(self):
        raw=struct.pack("<IBBBBQ",0x11223344,97,122,0x43,5,INLINE)
        row=texture_at(raw,0)
        self.assertEqual(row["hash"],"11223344")
        self.assertEqual(row["sampler"],0x43)
        self.assertEqual(row["semantic"],5)
        self.assertEqual(row["pointer_kind"],"inline_owned")
        self.assertIsNone(texture_at(raw[:-1],0))
    def test_unsupported_alias_is_not_named_as_image(self):
        bad=struct.pack("<IBBBBQ",0x11223344,97,122,0x43,5,0x123456)
        self.assertIsNone(texture_at(bad,0))
        self.assertEqual(pointer_kind(0xfdfdfdf300010000),"virtual_block")
if __name__=="__main__":unittest.main()
