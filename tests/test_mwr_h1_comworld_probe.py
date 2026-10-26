"""Synthetic authored H1 ComWorld light/env source-window checks."""
import pathlib,struct,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
from mwr_h1_comworld_probe import inspect_comworld_after_prefix,INLINE,LIGHT_BYTES

class H1ComWorldTest(unittest.TestCase):
    def test_native_light_array_and_env_indices_from_actual_count(self):
        root=struct.pack("<QIIQIIQ",INLINE,1,1,INLINE,1,0,INLINE)
        light=bytearray(LIGHT_BYTES)
        light[0]=2
        struct.pack_into("<3f",light,8,1.,0.5,0.25)
        struct.pack_into("<3f",light,20,0.,0.,-1.)
        struct.pack_into("<3f",light,44,10.,20.,30.)
        env=struct.pack("<4HBx",0,0,0,0,1)
        raw=b"\xab"*17+root+b"maps/mp/source_test.d3dbsp\0"+light+env
        result=inspect_comworld_after_prefix(raw,17)
        self.assertEqual(result["light_status"],"all_source_light_record_fields_structural")
        self.assertEqual(result["env_status"],"complete_original_light_environment_records")
        self.assertEqual(result["light_env_records_verified"],1)
        self.assertEqual(result["next_source_asset_candidate_cursor"],len(raw))
    def test_corrupted_light_environment_reference_not_admitted(self):
        root=struct.pack("<QIIQIIQ",INLINE,1,1,INLINE,1,0,INLINE)
        light=bytes(LIGHT_BYTES)
        bad_env=struct.pack("<4HBx",9,0,0,0,1)
        result=inspect_comworld_after_prefix(root+b"test\0"+light+bad_env,0)
        self.assertEqual(result["env_status"],"invalid_light_environment_reference_indices")
        self.assertEqual(result["light_env_records_verified"],0)

if __name__=="__main__":unittest.main()
