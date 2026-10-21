"""Offline regression for seekable original BO1 ZIP64 R2 byte-range reader."""
import io
import unittest
from unittest.mock import patch
from bo1_full_game_range import HttpRangeObject, BLOCK_SIZE

class ByteRangeTailTests(unittest.TestCase):
    @staticmethod
    def offline_reader(data: bytes):
        reader = object.__new__(HttpRangeObject)
        io.RawIOBase.__init__(reader)
        reader.url = "https://r2.houseofkublai.com/fake.zip"
        reader.size = len(data)
        reader.pos = 0
        reader.cache = {}
        reader._block = lambda index: data[index*BLOCK_SIZE:(index+1)*BLOCK_SIZE]
        return reader

    def test_zip_directory_end_read_without_explicit_size(self):
        data = b"x" * 4096 + b"ZIP64_DIRECTORY_END"
        reader = self.offline_reader(data)
        reader.seek(-20, io.SEEK_END)
        self.assertEqual(reader.read(), data[-20:])

    def test_read_without_length_refuses_unbounded_archive(self):
        reader = self.offline_reader(b"x" * (131072 + 1))
        with self.assertRaisesRegex(RuntimeError, "trailing-window"):
            reader.read()

    def test_explicit_range_reads_cross_2mb_block(self):
        data = b"A" * BLOCK_SIZE + b"B" * BLOCK_SIZE + b"C"
        reader = self.offline_reader(data)
        reader.seek(BLOCK_SIZE - 2)
        self.assertEqual(reader.read(5), b"AABBB")

if __name__ == "__main__":
    unittest.main()
