"""Package integrity and extraction boundary tests, with no network requests."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("vendor_opaque", Path(__file__).parents[1] / "tools" / "vendor_opaque.py")
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)


class VendorTests(unittest.TestCase):
    def setUp(self):
        self.payloads = {
            "package/esm/index.js": b"export const version = 'fixture';\n",
            "package/package.json": json.dumps({"name": "@serenity-kit/opaque", "version": "1.1.0", "license": "MIT"}).encode(),
            "package/LICENSE": b"Fixture license\n",
            "package/README.md": b"Fixture README\n",
            "package/index.d.ts": b"export declare const version: string;\n",
        }
        self.spec = {"package": "@serenity-kit/opaque", "version": "1.1.0", "license": "MIT",
                     "browser_source": "package/esm/index.js",
                     "browser_sha256": hashlib.sha256(self.payloads["package/esm/index.js"]).hexdigest()}

    def archive(self, extra=None, skip=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in self.payloads.items():
                if name == skip:
                    continue
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if extra:
                member, data = extra
                archive.addfile(member, io.BytesIO(data) if data is not None else None)
        return output.getvalue()

    def extract(self, data, spec=None):
        return vendor.extract_files(data, spec or self.spec, hashlib.sha512(data).digest())

    def test_exact_bytes_are_preserved(self):
        self.assertEqual(self.extract(self.archive()), self.payloads)

    def test_archive_integrity_checked_before_parsing(self):
        with self.assertRaisesRegex(vendor.Invalid, "integrity mismatch"):
            vendor.extract_files(b"not a tar archive", self.spec, b"\0" * 64)

    def test_browser_hash_checked_before_writing(self):
        with self.assertRaisesRegex(vendor.Invalid, "SHA-256 mismatch"):
            self.extract(self.archive(), {**self.spec, "browser_sha256": "0" * 64})

    def test_missing_artifact_fails(self):
        with self.assertRaisesRegex(vendor.Invalid, "missing"):
            self.extract(self.archive(skip="package/LICENSE"))

    def test_duplicate_artifact_fails(self):
        duplicate = tarfile.TarInfo("package/esm/index.js")
        duplicate.size = 1
        with self.assertRaisesRegex(vendor.Invalid, "duplicated"):
            self.extract(self.archive(extra=(duplicate, b"x")))

    def test_symlink_artifact_is_not_followed(self):
        link = tarfile.TarInfo("package/esm/index.js")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../secret"
        with self.assertRaisesRegex(vendor.Invalid, "Invalid"):
            self.extract(self.archive(skip="package/esm/index.js", extra=(link, None)))

    def test_unlisted_traversal_path_is_never_extracted(self):
        traversal = tarfile.TarInfo("../../secret")
        traversal.size = 1
        self.assertEqual(self.extract(self.archive(extra=(traversal, b"x"))), self.payloads)

    def test_package_identity_must_match(self):
        self.payloads["package/package.json"] = json.dumps({"name": "other", "version": "1.1.0", "license": "MIT"}).encode()
        with self.assertRaisesRegex(vendor.Invalid, "metadata"):
            self.extract(self.archive())

    def test_destination_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(vendor, "ROOT", Path(directory)):
            (Path(directory) / "web").symlink_to(Path(directory), target_is_directory=True)
            with self.assertRaisesRegex(vendor.Invalid, "symbolic link"):
                vendor.safe_target("web/vendor/opaque.js")

    def test_atomic_write_replaces_file_with_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "opaque.js"
            vendor.write_atomic(destination, b"expected\0bytes\n")
            self.assertEqual(destination.read_bytes(), b"expected\0bytes\n")
            self.assertEqual([path.name for path in destination.parent.iterdir()], ["opaque.js"])


if __name__ == "__main__":
    unittest.main()
