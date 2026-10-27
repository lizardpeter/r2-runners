"""Fail-closed original H1 MaterialTechnique native layout/cursor regression."""
import pathlib
import struct
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
from mwr_h1_technique_pass_source import (
    read_native_technique_candidate, inspect_first_inline_technique_after_set,
    HEADER_BYTES, PASS_BYTES, INLINE, ROOT_BYTES,
)


def source_fixture(first_ptr=INLINE, padding=3):
    root = 141
    name = b'parent_set\0'
    at = root + ROOT_BYTES + len(name) + padding
    raw = bytearray(at + HEADER_BYTES + PASS_BYTES + len(b'technique_0\0'))
    struct.pack_into('<Q', raw, root, INLINE)
    struct.pack_into('<Q', raw, root + 16 + 73 * 8, first_ptr)
    raw[root + ROOT_BYTES:root + ROOT_BYTES + len(name)] = name
    struct.pack_into('<QHH', raw, at, INLINE, 3, 1)
    pass_at = at + HEADER_BYTES
    struct.pack_into('<5Q', raw, pass_at, INLINE, 0, 0, 0, 0xFDFDFDF300000008)
    struct.pack_into('<Q', raw, pass_at + 64, INLINE)
    raw[pass_at + 41] = 2
    raw[at + HEADER_BYTES + PASS_BYTES:] = b'technique_0\0'
    parent = {
        'status': 'source_owned_first_type15_fixed_header_and_name_verified',
        'original_root_offset': root,
        'source_name_end': root + ROOT_BYTES + len(name),
        'source_name': 'parent_set',
    }
    return raw, at, parent


class TestFirstTechniquePassProbe(unittest.TestCase):
    def test_owned_parent_first_slot_and_native_pass_metadata(self):
        raw, at, parent = source_fixture()
        report = inspect_first_inline_technique_after_set(raw, parent)
        self.assertEqual(report['status'], 'first_technique_native_layout_candidate_not_pointer_relocated')
        self.assertEqual(report['source_technique_header_offset'], at)
        self.assertEqual(report['source_cursor_zero_padding'], 3)
        self.assertEqual(report['first_populated_slot'], 73)
        self.assertEqual(report['native_pass_count'], 1)
        self.assertEqual(report['first_passes'][0]['argument_count'], 2)
        self.assertEqual(report['first_passes'][0]['shader_pointer_kinds']['pixel_shader'],
                         'source_virtual_block_3')
        self.assertTrue(report['no_pass_arrays_admitted'])

    def test_virtual_or_shared_first_slot_cannot_authenticate_cursor(self):
        for ptr in (0xFDFDFDF300000008, 0xFDFDFDFFFFFFFFFE):
            with self.subTest(ptr=ptr):
                raw, _, parent = source_fixture(first_ptr=ptr)
                report = inspect_first_inline_technique_after_set(raw, parent)
                self.assertEqual(report['status'], 'first_populated_technique_slot_not_inline_owned')

    def test_reject_bad_pass_pointer_truncation_or_count(self):
        raw, at, parent = source_fixture()
        self.assertIsNotNone(read_native_technique_candidate(raw, at))
        bad = bytearray(raw)
        struct.pack_into('<Q', bad, at + HEADER_BYTES, 0x12345)
        self.assertIsNone(read_native_technique_candidate(bad, at))
        bad = bytearray(raw)
        struct.pack_into('<H', bad, at + 10, 33)
        self.assertIsNone(read_native_technique_candidate(bad, at))
        self.assertIsNone(read_native_technique_candidate(raw[:at+HEADER_BYTES+PASS_BYTES-1], at))
        bad = bytearray(raw)
        bad[at + HEADER_BYTES + 41] = 4
        struct.pack_into('<Q', bad, at + HEADER_BYTES + 64, 0)
        self.assertIsNone(read_native_technique_candidate(bad, at))

    def test_no_false_positive_from_padding_or_wrong_inline_name(self):
        raw, at, parent = source_fixture()
        raw[parent['source_name_end']] = 1
        self.assertEqual(inspect_first_inline_technique_after_set(raw, parent)['status'],
                         'first_inline_technique_not_found_under_bounded_cursor_model')
        raw, at, parent = source_fixture(padding=16)
        self.assertEqual(inspect_first_inline_technique_after_set(raw, parent)['status'],
                         'first_inline_technique_not_found_under_bounded_cursor_model')
        raw, at, parent = source_fixture()
        raw[at+HEADER_BYTES+PASS_BYTES] = 1
        self.assertIsNone(read_native_technique_candidate(raw, at))
        parent['status'] = 'source_owned_first_type15_header_needs_nested_loader_research'
        self.assertEqual(inspect_first_inline_technique_after_set(raw, parent)['status'],
                         'parent_technique_set_not_source_verified')


if __name__ == '__main__':
    unittest.main()
