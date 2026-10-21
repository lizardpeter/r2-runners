import io
import struct
import tempfile
from pathlib import Path
import unittest
import zipfile
import zlib

import bo1_probe


class T5SourceProbeTests(unittest.TestCase):
    @staticmethod
    def fixture_zone():
        zone = bytearray()
        zone.extend(struct.pack("<II", 60, 0))
        zone.extend(struct.pack("<7I", 8192, 0, 0, 0, 0, 0, 0))
        zone.extend(struct.pack("<4I", 0, 0, 1, 0xFFFFFFFF))
        zone.extend(struct.pack("<2I", 17, 0xFFFFFFFF))
        return bytes(zone)

    @classmethod
    def fixture_fastfile(cls):
        return b"IWffu100" + struct.pack("<I", 0x1D9) + zlib.compress(cls.fixture_zone())

    def test_proves_actual_t5_unsigned_header_and_serialized_asset(self):
        report = bo1_probe.probe_ff(self.fixture_fastfile())
        self.assertEqual(report["magic"], "IWffu100")
        self.assertEqual(report["version"], 0x1D9)
        self.assertEqual(report["asset_count"], 1)
        self.assertEqual(report["asset_types"], {"17": 1})
        self.assertEqual(report["asset_table_offset"], 52)
        self.assertEqual(report["asset_table_status"], "decoded_serialized")

    def test_refuses_signed_wrong_version_and_truncated_payload(self):
        ff = self.fixture_fastfile()
        with self.assertRaises(ValueError):
            bo1_probe.probe_ff(b"IWff0100" + ff[8:])
        with self.assertRaises(ValueError):
            bo1_probe.probe_ff(ff[:8] + b"\x00\x00\x00\x00" + ff[12:])
        with self.assertRaises(ValueError):
            bo1_probe.probe_ff(ff[:-3])

    def test_original_iwd_central_directory_image_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "iw_00.iwd"
            with zipfile.ZipFile(archive, "w") as f:
                f.writestr("images/original_wall.iwi", b"IWi\x0d")
                f.writestr("maps/layout.bsp", b"source")
            report = bo1_probe.probe_iwd(archive)
        self.assertEqual(report["members"], 2)
        self.assertEqual(report["iwi_members"], 1)
        self.assertEqual(report["iwi_uncompressed_bytes"], 4)

    def test_preserves_unknown_original_iwd_bytes_without_claiming_iwi(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "iw_01.iwd"
            archive.write_bytes(b"BO1_SOURCE_UNRECOGNIZED")
            report = bo1_probe.probe_iwd(archive)
        self.assertEqual(report["container_status"], "unrecognized_not_zip")
        self.assertIsNone(report["iwi_members"])
        self.assertTrue(report["source_bytes_preserved"])

    def test_original_iwd2_exact_stride_and_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "iw_01.iwd"
            archive.write_bytes(
                b"IWD2" + struct.pack("<II", 2, 2) +
                struct.pack("<III", 17, 31, 42) +
                struct.pack("<III", 18, 43, 55)
            )
            report = bo1_probe.probe_iwd(archive)
        self.assertEqual(report["container_status"], "original_t5_iwd2_record_table")
        self.assertEqual(report["record_count"], 2)
        self.assertEqual(report["record_stride_bytes"], 12)
        self.assertFalse(report["raw_field_semantics_verified"])

    def test_original_iwd2_rejects_invalid_record_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "iw_02.iwd"
            archive.write_bytes(b"IWD2" + struct.pack("<II", 2, 3) + bytes(24))
            with self.assertRaises(ValueError):
                bo1_probe.probe_iwd(archive)

    def test_selects_only_source_manifest_paths(self):
        manifest = {"files": [
            {"path": "zone/Common/mp_nuked.ff"},
            {"path": "zone/Common/mp_firingrange.ff"},
            {"path": "zone/Common/common_mp.ff"},
            {"path": "zone/Common/patch_mp.ff"},
            {"path": "main/iw_00.iwd"},
        ]}
        selected = bo1_probe.select_assets(manifest, "both")
        self.assertEqual(len(selected), 5)
        self.assertIn("main/iw_00.iwd", [f["path"] for f in selected])


if __name__ == "__main__":
    unittest.main()
