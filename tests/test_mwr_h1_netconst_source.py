"""Synthetic H1 first-asset source-cursor closure, no map-specific offsets."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_netconst_source import inspect_ordered_netconst_bodies,INLINE

def root(name,ids):
    count=len(ids)
    header=struct.pack("<QIIIIQ",INLINE,23,0,count,0,INLINE if count else 0)
    out=header+name.encode("ascii")+b"\0"
    if count:
        out+=b"".join(struct.pack("<Q",INLINE if s is not None else 0) for s in ids)
        out+=b"".join(s.encode("ascii")+b"\0" for s in ids if s is not None)
    return out
def evidence(num):
    return {"status":"fully_verified","validated_tables":[{
        "end_offset":49,
        "asset_type_runs":[{"type_id":59,"count":num}]}]}
class H1NetConstTest(unittest.TestCase):
    def test_contiguous_inline_bodies_preserve_authored_cursor(self):
        body=root("ncs_test",[])+root("ncs_values",["one",None,"two"])
        data=b"\xaa"*49+body+b"\xfe"
        result=inspect_ordered_netconst_bodies(data,evidence(2))
        self.assertEqual(result["status"],"complete_authored_netconststrings_run")
        self.assertEqual(result["source_body_end"],len(data)-1)
        self.assertEqual(result["source_bodies"][1]["source_strings_seen"],3)
    def test_unknown_nested_pointer_fails_not_guessed(self):
        body=bytearray(root("ncs_test",["one"]))
        body[24:32]=struct.pack("<Q",0xfdfdfdf300000100)
        result=inspect_ordered_netconst_bodies(b"\0"*49+body,evidence(1))
        self.assertEqual(result["status"],"stopped_on_unresolved_source_asset_body")
        self.assertEqual(result["failed_cursor"],49)
if __name__=="__main__":unittest.main()
