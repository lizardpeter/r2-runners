"""Synthetic source-layout tests for generic H1 static-model array discovery."""
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from mwr_h1_static_models_probe import (
    H1StaticModelDrawScanner, plausible_draw_record, STRIDE,
)

def draw_record(index):
    raw=bytearray(STRIDE)
    xyz=[float(index),3.,-20.,1.,0.,0.,0.,1.,0.,0.,0.,1.,1.]
    struct.pack_into("<13f",raw,0,*xyz)
    struct.pack_into("<Q",raw,56,0xfdfdfdf300000000+index+1)
    return bytes(raw)

class H1StaticModelArrayTests(unittest.TestCase):
    def test_unaligned_source_run_across_input_chunks(self):
        start=1_051_017
        count=32
        blob=b"\xfe"*start+b"".join(draw_record(i) for i in range(count))+b"\xfe"*391
        scanner=H1StaticModelDrawScanner()
        scanner.bind_root({"static_model_count":count})
        for at in range(0,len(blob),131_072):
            scanner.push(blob[at:at+131_072])
        result=scanner.report()
        self.assertEqual(result["status"],"unique_complete_original_static_model_draw_span")
        self.assertEqual(result["candidate_matches"][0]["start"],start)
        self.assertEqual(result["candidate_matches"][0]["records"],count)

    def test_corrupted_model_pointer_and_transform_rejected(self):
        record=bytearray(draw_record(3))
        self.assertTrue(plausible_draw_record(record,0))
        record[60:64]=b"\x00"*4
        self.assertFalse(plausible_draw_record(record,0))
        record=bytearray(draw_record(3))
        struct.pack_into("<f",record,48,float("nan"))
        self.assertFalse(plausible_draw_record(record,0))

    def test_complete_count_is_required_not_plausible_subset(self):
        scanner=H1StaticModelDrawScanner()
        scanner.bind_root({"static_model_count":20})
        scanner.push(b"".join(draw_record(i) for i in range(19)))
        self.assertEqual(scanner.report()["status"],
            "no_complete_original_static_model_draw_span")

if __name__=="__main__":
    unittest.main()
