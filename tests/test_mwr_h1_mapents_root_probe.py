import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from mwr_h1_mapents_root_probe import (
    H1MapEntsBodyScanner, source_mapents_candidate, ROOT_SIZE, INLINE)


def fixture(name=b"maps/mp/mp_authored.d3dbsp", entity_count=4096, spawns=4):
    root = bytearray(ROOT_SIZE)
    struct.pack_into("<Q", root, 0, INLINE)
    struct.pack_into("<Q", root, 8, INLINE)
    struct.pack_into("<I", root, 16, entity_count)
    struct.pack_into("<H", root, 264, spawns)
    struct.pack_into("<Q", root, 272, INLINE)
    return bytes(root) + name + b"\0"


class H1MapEntsSourceRootTests(unittest.TestCase):
    def test_preserve_typed_source_and_truncated_inline_name(self):
        data = fixture()
        found = source_mapents_candidate(data, 0)
        self.assertEqual(found["original_name"], "maps/mp/mp_authored.d3dbsp")
        self.assertEqual(found["declared_entity_text_bytes"], 4096)
        self.assertEqual(found["source_spawn_record_count"], 4)
        self.assertTrue(found["not_authenticated_as_type29_XAsset_owner"])
        self.assertIsNone(source_mapents_candidate(data[:-2], 0))

    def test_reject_wrong_pointer_and_unowned_name(self):
        root = bytearray(fixture())
        struct.pack_into("<Q", root, 272, 0)
        self.assertIsNone(source_mapents_candidate(root, 0))
        root = bytearray(fixture(name=b"unrelated_test"))
        self.assertIsNone(source_mapents_candidate(root, 0))
        root = bytearray(fixture())
        struct.pack_into("<Q", root, 8, 0x123456789ABCDEF0)
        self.assertIsNone(source_mapents_candidate(root, 0))

    def test_streaming_chunks_keep_exact_source_offsets(self):
        data = b"invalid-prefix" + fixture() + b"tail"
        scanner = H1MapEntsBodyScanner()
        for i in range(0, len(data), 43):
            scanner.push(data[i:i+43])
        report = scanner.report()
        self.assertEqual(report["source_structural_candidate_count"], 1)
        self.assertEqual(report["first_16"][0]["original_source_offset"], len(b"invalid-prefix"))
        self.assertTrue(report["original_entity_and_spawn_payloads_not_admitted"])


if __name__ == "__main__":
    unittest.main()
