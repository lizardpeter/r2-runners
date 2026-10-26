"""Validate real H1 32B shader root to DXBC source body ownership conditions."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_shader_ownership_probe import source_owned_shader_candidate,INLINE
class TestShaderSourceLink(unittest.TestCase):
    def test_exact_inline_name_program_and_native_byte_count(self):
        header=struct.pack("<QQQII",INLINE,0,INLINE,1764,0x11223344)
        name=b"shaders/authored_vs\0"
        blob=b"\xea"*17+header+name+b"DXBC"+bytes(1760)
        start=17
        program=17+len(header)+len(name)
        evidence=source_owned_shader_candidate(blob,start,program,1764)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["original_name_candidate"],"shaders/authored_vs")
        self.assertEqual(evidence["source_program_pointer_form"],"inline_owned")
        self.assertEqual(evidence["original_microcode_crc"],"11223344")
        self.assertIsNone(source_owned_shader_candidate(blob,start,program,1763))
    def test_unknown_pointer_or_name_prefix_does_not_claim_ownership(self):
        header=struct.pack("<QQQII",INLINE,0,0x12345678,56,0)
        blob=header+b"authored\0"+b"DXBC"+bytes(52)
        self.assertIsNone(source_owned_shader_candidate(blob,0,len(header)+8,56))
        header=struct.pack("<QQQII",INLINE,0,INLINE,56,0)
        blob=header+bytes([1])+b"\0"+b"DXBC"+bytes(52)
        self.assertIsNone(source_owned_shader_candidate(blob,0,len(header)+2,56))
if __name__=="__main__":unittest.main()
