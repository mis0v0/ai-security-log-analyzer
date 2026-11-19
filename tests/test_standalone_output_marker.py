from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.build_standalone import (
    OUTPUT_MARKER,
    OUTPUT_MARKER_CONTENT,
    ensure_output_marker,
)


class StandaloneOutputMarkerTests(unittest.TestCase):
    def test_creates_private_marker_and_reuses_it_without_writing(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ensure_output_marker(directory)
            marker = directory / OUTPUT_MARKER
            before = marker.stat()
            self.assertEqual(marker.read_bytes(), OUTPUT_MARKER_CONTENT)
            self.assertEqual(before.st_mode & 0o777, 0o600)
            ensure_output_marker(directory)
            after = marker.stat()
            self.assertEqual((after.st_ino, after.st_mtime_ns), (before.st_ino, before.st_mtime_ns))

    def test_preserves_unrecognized_existing_marker(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / OUTPUT_MARKER
            marker.write_bytes(b"existing content")
            with self.assertRaises(ValueError):
                ensure_output_marker(directory)
            self.assertEqual(marker.read_bytes(), b"existing content")

    def test_marker_must_be_a_regular_file(self):
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / OUTPUT_MARKER).mkdir()
            with self.assertRaises(ValueError):
                ensure_output_marker(directory)
            self.assertTrue((directory / OUTPUT_MARKER).is_dir())
