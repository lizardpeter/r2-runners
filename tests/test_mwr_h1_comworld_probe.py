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
    def test_authentic_h1_hdr_spots_and_directional_light_are_preview_eligible(self):
        root=struct.pack("<QIIQIIQ",INLINE,1,3,INLINE,1,0,INLINE)
        lights=[]
        for kind,color,radius in [
            (1,(0.13695666,0.22819264,0.4),0.0),
            (2,(54250.113,44205.47,34963.06),380.0),
            (3,(6200.012,2427.758,1249.654),65.0),
        ]:
            light=bytearray(LIGHT_BYTES)
            light[0]=kind
            light[1]=1
            light[2]=1
            struct.pack_into("<3f",light,8,*color)
            struct.pack_into("<3f",light,20,0.0,0.0,1.0)
            struct.pack_into("<f",light,80,radius)
            struct.pack_into("<f",light,84,0.5)
            struct.pack_into("<f",light,88,0.8)
            lights.append(light)
        env=struct.pack("<4HBx",0,1,2,0,3)
        raw=root+b"maps/mp/test.d3dbsp\0"+b"".join(lights)+env
        report=inspect_comworld_after_prefix(raw,0)
        counts=report["original_H1_neutral_light_preview_eligibility"][
            "source_native_light_classes_and_ranges"]
        self.assertEqual(counts,{
            "sun_candidates":1,"spot_candidates":1,"omni_candidates":1,
            "rejected_source_lights":0,
        })
        self.assertEqual(
            report["original_H1_neutral_light_preview_eligibility"][
                "max_eligible_native_local_radius"],380.0)
        self.assertEqual(report["env_status"],"complete_original_light_environment_records")
    def test_corrupted_light_environment_reference_not_admitted(self):
        root=struct.pack("<QIIQIIQ",INLINE,1,1,INLINE,1,0,INLINE)
        light=bytes(LIGHT_BYTES)
        bad_env=struct.pack("<4HBx",9,0,0,0,1)
        result=inspect_comworld_after_prefix(root+b"test\0"+light+bad_env,0)
        self.assertEqual(result["env_status"],"invalid_light_environment_reference_indices")
        self.assertEqual(result["light_env_records_verified"],0)

if __name__=="__main__":unittest.main()
