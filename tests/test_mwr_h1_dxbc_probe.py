"""Bounds-preserving H1 signed source DXBC container probes."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_dxbc_probe import H1DXBCSourceScanner

def container():
    b=bytearray(56)
    b[0:4]=b"DXBC"
    struct.pack_into("<III",b,20,1,len(b),1)
    struct.pack_into("<I",b,32,36)
    b[36:40]=b"SHDR"
    struct.pack_into("<I",b,40,12)
    return bytes(b)
class OriginalDXBCHeaderTests(unittest.TestCase):
    def test_recover_source_container_cross_chunk_boundaries(self):
        raw=b"\xfa"*73+container()+b"\xee"*11
        scanner=H1DXBCSourceScanner()
        for at in range(0,len(raw),17):scanner.push(raw[at:at+17])
        result=scanner.report()
        self.assertEqual(result["source_header_verified_candidates"],1)
        entry=result["first_24_source_headers"][0]
        self.assertEqual(entry["source_offset"],73)
        self.assertEqual(entry["declared_shader_container_bytes"],56)
        self.assertEqual(entry["source_chunk_count"],1)
    def test_reject_invalid_size_and_chunk_offsets(self):
        bad=bytearray(container())
        struct.pack_into("<I",bad,24,16)
        self.assertIsNone(H1DXBCSourceScanner.probe(bad,0))
        bad=bytearray(container())
        struct.pack_into("<I",bad,32,160)
        self.assertIsNone(H1DXBCSourceScanner.probe(bad,0))
if __name__=="__main__":unittest.main()
