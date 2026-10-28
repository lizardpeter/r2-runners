import unittest,struct,sys,pathlib
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from h1_pak_range_probe import source_rows
class TestH1PakRangeProbe(unittest.TestCase):
    def test_64bit_original_pak_offsets_and_archive_ids(self):
        packed=struct.pack('<6I',11<<16,0,1,1,64,1)
        self.assertEqual(source_rows(packed),[(11,0x100000001,0x100000040,0)])
    def test_fails_closed_on_corrupt_and_flags(self):
        with self.assertRaises(ValueError):source_rows(b'bad')
        with self.assertRaises(ValueError):source_rows(struct.pack('<6I',1,0,1,0,64,0))
        with self.assertRaises(ValueError):source_rows(struct.pack('<6I',11<<16,0,100,0,50,0))
if __name__=='__main__':unittest.main()