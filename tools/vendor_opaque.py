#!/usr/bin/env python3
"""Verify or restore the pinned npm OPAQUE artifact without running npm scripts.

This reproduces bytes from a published package. It does not rebuild its embedded
WebAssembly from Rust sources or establish that those compiled bytes are safe.
"""

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


ROOT = Path(__file__).resolve().parent.parent
PROVENANCE = ROOT / "vendor" / "opaque" / "provenance.json"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
TARGETS = {
    "package/esm/index.js": "web/vendor/opaque.js",
    "package/package.json": "vendor/opaque/package.json",
    "package/LICENSE": "vendor/opaque/LICENSE",
    "package/README.md": "vendor/opaque/README.md",
    "package/index.d.ts": "vendor/opaque/index.d.ts",
}


class Invalid(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("Duplicate provenance field.")
        result[key] = value
    return result


def provenance():
    with PROVENANCE.open("rb") as source:
        data = source.read(65537)
    if len(data) > 65536:
        raise Invalid("Provenance file is too large.")
    value = json.loads(data, object_pairs_hook=unique_object)
    required = {"package", "version", "tarball", "integrity", "browser_source", "browser_sha256", "license"}
    if not isinstance(value, dict) or set(value) != required:
        raise Invalid("Invalid provenance structure.")
    if value["package"] != "@serenity-kit/opaque" or value["license"] != "MIT":
        raise Invalid("Unexpected package or license.")
    if not isinstance(value["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", value["version"]):
        raise Invalid("Invalid pinned package version.")
    expected_url = f'https://registry.npmjs.org/@serenity-kit/opaque/-/opaque-{value["version"]}.tgz'
    if value["tarball"] != expected_url or value["browser_source"] != "package/esm/index.js":
        raise Invalid("Unexpected package URL or browser source path.")
    if not isinstance(value["browser_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["browser_sha256"]):
        raise Invalid("Invalid browser artifact hash.")
    integrity = value["integrity"]
    if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
        raise Invalid("The pinned archive must have a SHA-512 integrity value.")
    try:
        digest = base64.b64decode(integrity[7:], validate=True)
    except (ValueError, binascii.Error) as error:
        raise Invalid("Invalid archive integrity value.") from error
    if len(digest) != 64 or base64.b64encode(digest).decode("ascii") != integrity[7:]:
        raise Invalid("Invalid archive integrity length or encoding.")
    return value, digest


def archive_bytes(source, spec):
    if source is not None:
        with Path(source).open("rb") as stream:
            data = stream.read(MAX_ARCHIVE + 1)
    else:
        request = Request(spec["tarball"], headers={"Accept-Encoding": "identity", "User-Agent": "cloud-cypher-vendor-check/1"})
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != spec["tarball"]:
                raise Invalid("Expected a direct HTTP 200 response from the pinned registry URL.")
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise Invalid("Unexpected content encoding for the package archive.")
            data = response.read(MAX_ARCHIVE + 1)
    if not data or len(data) > MAX_ARCHIVE:
        raise Invalid("Empty or oversized package archive.")
    return data


def extract_files(data, spec, expected_digest):
    if hashlib.sha512(data).digest() != expected_digest:
        raise Invalid("Archive integrity mismatch. No files were written.")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if member.name not in TARGETS:
                continue
            if member.name in files or not member.isfile() or not 0 <= member.size <= MAX_MEMBER:
                raise Invalid("Invalid, duplicated or oversized package member.")
            source = archive.extractfile(member)
            if source is None:
                raise Invalid("Cannot read a required package member.")
            with source:
                payload = source.read(MAX_MEMBER + 1)
            if len(payload) != member.size:
                raise Invalid("Incomplete package member.")
            files[member.name] = payload
    if set(files) != set(TARGETS):
        raise Invalid("Pinned package is missing a required artifact.")
    package = json.loads(files["package/package.json"], object_pairs_hook=unique_object)
    if package.get("name") != spec["package"] or package.get("version") != spec["version"] or package.get("license") != spec["license"]:
        raise Invalid("Package metadata does not match its pinned provenance.")
    if hashlib.sha256(files[spec["browser_source"]]).hexdigest() != spec["browser_sha256"]:
        raise Invalid("Browser artifact SHA-256 mismatch. No files were written.")
    return files


def safe_target(relative):
    target = ROOT
    for part in Path(relative).parts:
        target = target / part
        if target.is_symlink():
            raise Invalid("A vendor destination is a symbolic link.")
    return target


def write_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".opaque-", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", help="Read the pinned npm .tgz locally instead of downloading it")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Compare without writing (default)")
    mode.add_argument("--write", action="store_true", help="Restore pinned artifacts after all integrity checks pass")
    args = parser.parse_args(argv)
    try:
        spec, expected = provenance()
        files = extract_files(archive_bytes(args.archive, spec), spec, expected)
        destinations = {member: safe_target(relative) for member, relative in TARGETS.items()}
        results = []
        for member, target in destinations.items():
            payload = files[member]
            matched = target.is_file() and target.read_bytes() == payload
            if args.write and not matched:
                write_atomic(target, payload)
            results.append({"path": TARGETS[member], "status": "match" if matched else "restored" if args.write else "mismatch", "sha256": hashlib.sha256(payload).hexdigest()})
        good = all(item["status"] != "mismatch" for item in results)
        print(json.dumps({"package": spec["package"], "version": spec["version"], "archive_integrity": "verified", "status": "verified" if good else "mismatch", "files": results, "source_rebuild": False}, indent=2))
        return 0 if good else 1
    except (OSError, ValueError, tarfile.TarError, HTTPError, URLError) as error:
        print(f"Vendor check failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
