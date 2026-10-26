"""Verify full authored DXBC chunk graph, not just signature and header."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_dxbc_verify import verify_dxbc_container
def fixture():
    b=bytearray(56)
    b[:4]=b"DXBC"
    struct.pack_into("<III",b,20,1,len(b),1)
    struct.pack_into("<I",b,32,36)
    b[36:40]=b"SHDR"
    struct.pack_into("<I",b,40,12)
    return b
class OriginalDXBCComplete(unittest.TestCase):
    def test_original_chunk_payload_and_full_container_digest(self):
        result=verify_dxbc_container(bytes(fixture()))
        self.assertEqual(result["status"],
            "complete_original_DXBC_container_source_verified")
        self.assertEqual(result["chunks_checked"],1)
        self.assertEqual(result["authored_chunk_types"],["SHDR"])
        self.assertEqual(len(result["original_program_sha256"]),64)
    def test_fails_on_invalid_chunk_extent_even_when_header_passes(self):
        corrupt=fixture()
        struct.pack_into("<I",corrupt,40,1000)
        result=verify_dxbc_container(bytes(corrupt))
        self.assertEqual(result["status"],"DXBC_source_chunk_size_or_fourcc_invalid")
        corrupt=fixture()
        corrupt[36:40]=bytes(4)
        result=verify_dxbc_container(bytes(corrupt))
        self.assertEqual(result["status"],"DXBC_source_chunk_size_or_fourcc_invalid")
if __name__=="__main__":unittest.main()
