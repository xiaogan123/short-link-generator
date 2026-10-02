"""Synthetic, offline HFS+ checks for the bounded DMG owner normalizer."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/normalize-macos-dmg-owners.py"
spec = importlib.util.spec_from_file_location("dmg_owners", SCRIPT)
normalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(normalizer)


def hdiutil(*args):
    return subprocess.run(["/usr/bin/hdiutil", *map(str, args)],
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class DmgOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "darwin":
            raise unittest.SkipTest("hdiutil fixture requires macOS")
        cls.temp = tempfile.TemporaryDirectory(prefix="dmg-owner-tests-")
        cls.root = Path(cls.temp.name)
        cls.stage = cls.root / "stage"
        cls.app = cls.stage / "Fixture.app"
        contents = cls.app / "Contents"
        contents.mkdir(parents=True)
        payload = contents / "payload.txt"
        payload.write_bytes(b"synthetic signed-app stand-in\n")
        payload.chmod(0o644)
        (contents / "payload-link").symlink_to("payload.txt")
        (cls.stage / "background").write_bytes(b"outside-app synthetic file\n")
        cls.raw_path = cls.root / "fixture.cdr.dmg"
        cls.dmg_path = cls.root / "fixture.dmg"
        hdiutil("makehybrid", "-hfs", "-o", cls.root / "fixture.cdr", cls.stage)
        hdiutil("convert", cls.raw_path, "-format", "UDZO", "-o", cls.dmg_path)
        cls.raw = cls.raw_path.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_owner_only_and_source_bytes_modes_links(self):
        before = normalizer.parse_raw(self.raw)
        manifest = normalizer.compare_source_tree(before, self.app, self.app.name)
        self.assertEqual(manifest["files"], 1)
        self.assertEqual(manifest["links"], 1)
        result, report = normalizer.normalize_raw(self.raw, self.app, self.app.name)
        after = normalizer.parse_raw(result)
        self.assertEqual(report["catalogObjects"], len(before["records"]))
        self.assertTrue(report["allOwnersZeroAfter"])
        self.assertTrue(all(r["uid"] == r["gid"] == 0 for r in after["records"]))
        self.assertEqual(normalizer.compare_source_tree(after, self.app, self.app.name), manifest)
        normalizer.only_owner_bytes_changed(
            self.raw, result, [r["owner_offset"] for r in before["records"]])
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), report["inputRawSha256"])

    def test_partition_and_header_corruption_refused(self):
        raw = bytearray(self.raw)
        block = normalizer.be16(raw, 2)
        raw[block:block + 2] = b"XX"
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.parse_raw(raw)
        raw = bytearray(self.raw)
        _, start, _, _, _, _ = normalizer.image_layout(raw)
        raw[start + 1024:start + 1026] = b"HX"
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.parse_raw(raw)

    def test_bad_catalog_extent_refused(self):
        raw = bytearray(self.raw)
        _, start, volume, _, _, total_blocks = normalizer.image_layout(raw)
        bad = (total_blocks + 1).to_bytes(4, "big")
        for volume_header in (start + 1024, start + len(volume) - 1024):
            raw[volume_header + 272 + 16:volume_header + 272 + 20] = bad
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.parse_raw(raw)

    def test_bad_leaf_and_nonowner_byte_refused(self):
        raw = bytearray(self.raw)
        _, start, volume, header, block_size, total_blocks = normalizer.image_layout(raw)
        catalog, extents = normalizer.read_fork(volume, block_size, total_blocks,
                                               header[272:352])
        first_leaf = normalizer.be32(catalog, 24)
        node_size = normalizer.be16(catalog, 32)
        logical = first_leaf * node_size + 8
        for offset, length in extents:
            if logical < length:
                raw[start + offset + logical] = 0
                break
            logical -= length
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.parse_raw(raw)
        patched, _ = normalizer.normalize_raw(self.raw)
        wrong = bytearray(patched)
        wrong[0] ^= 1
        offsets = [r["owner_offset"] for r in normalizer.parse_raw(self.raw)["records"]]
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.only_owner_bytes_changed(self.raw, wrong, offsets)

    def test_catalog_alias_with_nonapp_file_forks_refused(self):
        parsed = normalizer.parse_raw(self.raw)
        outside = next(r for r in parsed["records"] if r["relative"] == "background")
        _, _, _, header, _, _ = normalizer.image_layout(self.raw)
        catalog_descriptor = bytes(header[272:352])
        for fork_offset in (88, 168):
            with self.subTest(fork_offset=fork_offset):
                damaged = bytearray(self.raw)
                descriptor = outside["owner_offset"] - 32 + fork_offset
                damaged[descriptor:descriptor + 80] = catalog_descriptor
                with self.assertRaisesRegex(normalizer.ImageRejected,
                                            "file fork overlaps HFS\\+ catalog"):
                    normalizer.normalize_raw(bytes(damaged), self.app, self.app.name)

    def test_catalog_alias_with_system_fork_refused(self):
        damaged = bytearray(self.raw)
        _, start, volume, header, _, _ = normalizer.image_layout(damaged)
        catalog_descriptor = bytes(header[272:352])
        for volume_header in (start + 1024, start + len(volume) - 1024):
            damaged[volume_header + 112:volume_header + 192] = catalog_descriptor
        with self.assertRaisesRegex(normalizer.ImageRejected,
                                    "allocation fork overlaps HFS\\+ catalog"):
            normalizer.parse_raw(damaged)

    def test_cli_roundtrip_and_no_source_mutation(self):
        output = self.root / "normalized.dmg"
        evidence = self.root / "normalized.json"
        source_before = (self.app / "Contents/payload.txt").read_bytes()
        image_before = hashlib.sha256(self.dmg_path.read_bytes()).hexdigest()
        subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                        str(self.dmg_path), str(output), str(self.app),
                        "--evidence", str(evidence)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        report = json.loads(evidence.read_text())
        self.assertTrue(report["roundtripRawExact"])
        self.assertTrue(report["hdiutilVerified"])
        self.assertTrue(report["allOwnersZeroAfter"])
        self.assertEqual(report["inputDmgSha256"], image_before)
        self.assertEqual(hashlib.sha256(self.dmg_path.read_bytes()).hexdigest(), image_before)
        self.assertEqual((self.app / "Contents/payload.txt").read_bytes(), source_before)
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.normalize_dmg(self.dmg_path, output, self.app)

    def test_failure_cleans_intermediates_and_target(self):
        output = self.root / "must-not-exist.dmg"
        payload = self.app / "Contents/payload.txt"
        original = payload.read_bytes()
        try:
            payload.write_bytes(b"changed source after image creation")
            with self.assertRaises(normalizer.ImageRejected):
                normalizer.normalize_dmg(self.dmg_path, output, self.app)
        finally:
            payload.write_bytes(original)
        self.assertFalse(output.exists())
        self.assertFalse(any(p.name.startswith("dmg-owner-normalize-") for p in self.root.iterdir()))


class OptionalGptEvidenceTests(unittest.TestCase):
    def test_gpt_crc_and_backup_refusal(self):
        location = os.environ.get("DMG_OWNER_GPT_RAW")
        if not location:
            self.skipTest("optional private GPT read-only evidence not supplied")
        raw = Path(location).read_bytes()
        self.assertEqual(normalizer.parse_raw(raw)["scheme"], "GPT")
        damaged = bytearray(raw)
        damaged[512 + 16] ^= 1
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.parse_raw(damaged)
        damaged = bytearray(raw)
        table_start = normalizer.le64(raw, 512 + 72) * 512
        damaged[table_start] ^= 1
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.parse_raw(damaged)
        damaged = bytearray(raw)
        damaged[-512 + 16] ^= 1
        with self.assertRaises(normalizer.ImageRejected):
            normalizer.parse_raw(damaged)


if __name__ == "__main__":
    unittest.main(verbosity=2)
