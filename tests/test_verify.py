"""Adversarial fixtures for the independently run release verifier."""

import base64
import contextlib
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest


SPEC = importlib.util.spec_from_file_location("cypher_verify", Path(__file__).parents[1] / "tools" / "verify.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


@contextlib.contextmanager
def local_server(assets, mutations=None):
    mutations = mutations or {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.removeprefix("/vault/") or "index.html"
            status, body, headers = mutations.get(path, (200, assets.get(path), {}))
            if body is None:
                status, body = 404, b"not found"
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield "http://127.0.0.1:%s/vault/" % server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.assets = {
            "index.html": b'<script type="module" src="app.js"></script>',
            "app.js": b'import "./crypto.js";\n',
            "crypto.js": b'export const cipher = "test fixture";\n',
            "http.js": b'export const authJson = "bounded fixture";\n',
            "account.js": b'import "./vendor/opaque.js";\n',
            "passkeys.js": b'export const passkey = "test fixture";\n',
            "vendor/opaque.js": b'export const opaque = "pinned fixture";\n',
            "style.css": b"body { color: black; }\n",
            "verify.html": b"<p>Independent verification instructions.</p>\n",
        }
        for path, body in self.assets.items():
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            (self.root / path).write_bytes(body)
        self.manifest = verify.build_manifest(self.root)
        self.base = "https://vault.example/vault/"

    def har_entry(self, path, body=None, **kwargs):
        entry = {"request": {"url": self.base + path, "method": "GET"},
                 "response": {"status": 200, "headers": [],
                              "content": {"mimeType": "application/octet-stream",
                                          "text": (self.assets[path] if body is None else body).decode("utf-8")}}}
        entry.update(kwargs)
        return entry

    def har(self):
        return {"log": {"entries": [self.har_entry(path) for path in verify.CORE]}}

    def codes(self, report):
        return {item["code"] for item in report["issues"]}

    def test_manifest_is_sorted_reproducible_and_excludes_only_own_output(self):
        output = self.root / "release-manifest.json"
        first = verify.build_manifest(self.root, output)
        verify.write_json(output, first)
        first_bytes = output.read_bytes()
        verify.write_json(output, verify.build_manifest(self.root, output))
        self.assertEqual(first_bytes, output.read_bytes())
        self.assertEqual(sorted(self.assets), [x["path"] for x in first["files"]])

    def test_all_web_files_are_covered_even_optional_in_har(self):
        self.assertIn("verify.html", [item["path"] for item in self.manifest["files"]])
        self.assertNotIn("verify.html", self.manifest["required_paths"])

    def test_authentication_and_opaque_runtime_are_required_when_present(self):
        for path in ("http.js", "account.js", "passkeys.js", "vendor/opaque.js"):
            self.assertIn(path, self.manifest["required_paths"])
            har = self.har()
            har["log"]["entries"] = [entry for entry in har["log"]["entries"] if entry["request"]["url"] != self.base + path]
            report, code = verify.verify_har(self.manifest, har, self.base)
            self.assertEqual(code, 2)
            self.assertIn("required_path_unobserved", self.codes(report))

    def test_manifest_rejects_symlink_even_inside_root(self):
        (self.root / "linked.js").symlink_to(self.root / "app.js")
        with self.assertRaises(verify.Invalid):
            verify.build_manifest(self.root)

    def test_manifest_rejects_duplicates_bad_hash_and_traversal(self):
        candidates = []
        duplicate = copy.deepcopy(self.manifest)
        duplicate["files"].append(duplicate["files"][0])
        candidates.append(duplicate)
        for path in ("../key", "/app.js", "a//b", "a/./b", "a\\b", "x?token=secret", "%2e%2e/key"):
            bad = copy.deepcopy(self.manifest)
            bad["files"][0]["path"] = path
            candidates.append(bad)
        bad = copy.deepcopy(self.manifest)
        bad["files"][0]["sha256"] = "xyz"
        candidates.append(bad)
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(verify.Invalid):
                verify.validate_manifest(candidate)

    def test_duplicate_json_keys_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"version": 1, "version": 2}')
        with self.assertRaises(verify.Invalid):
            verify.load_json(path)

    def test_url_probe_covers_entry_and_every_file(self):
        with local_server(self.assets) as base:
            report, code = verify.verify_url(self.manifest, base)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "verified_scope")
        self.assertEqual(len(report["checked"]), len(self.assets) + 1)
        self.assertEqual(report["unobserved_paths"], [])

    def test_url_probe_tampered_js_fails(self):
        with local_server(self.assets, {"app.js": (200, b"fetch('/steal');", {})}) as base:
            report, code = verify.verify_url(self.manifest, base)
        self.assertEqual(code, 1)
        self.assertIn("body_mismatch", self.codes(report))

    def test_url_probe_missing_file_is_incomplete(self):
        with local_server(self.assets, {"crypto.js": (404, b"missing", {})}) as base:
            report, code = verify.verify_url(self.manifest, base)
        self.assertEqual(code, 2)
        self.assertIn("http_error", self.codes(report))

    def test_url_probe_refuses_redirect_without_following_target(self):
        with local_server(self.assets, {"app.js": (302, b"", {"Location": "http://127.0.0.1:1/secret"})}) as base:
            report, code = verify.verify_url(self.manifest, base)
        self.assertEqual(code, 1)
        self.assertIn("redirect_refused", self.codes(report))
        self.assertNotIn("secret", json.dumps(report))

    def test_url_probe_catches_additional_script_in_html(self):
        html = self.assets["index.html"] + b'<script src="https://evil.example/a.js"></script>'
        with local_server(self.assets, {"index.html": (200, html, {})}) as base:
            report, code = verify.verify_url(self.manifest, base)
        self.assertEqual(code, 1)
        self.assertIn("body_mismatch", self.codes(report))

    def test_url_and_path_validation(self):
        for base in ("file:///tmp/", "https://user:pass@example.org/vault/", "https://example.org/vault/?secret=1",
                     "https://example.org/vault/../", "https://example.org/%2e%2e/", "https://example.org/vault",
                     "https://example.org:0/vault/", "https://example.org/vault/\n"):
            with self.subTest(base=base), self.assertRaises(verify.Invalid):
                verify.verify_url(self.manifest, base)

    def test_har_good_capture_claims_only_scope_and_lists_optional_absence(self):
        report, code = verify.verify_har(self.manifest, self.har(), self.base)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "verified_scope")
        self.assertEqual(report["unobserved_paths"], ["verify.html"])
        self.assertIn("provided_har", report["scope"])

    def test_har_entry_document_alias_and_query_are_hashed_without_reporting_query(self):
        har = self.har()
        har["log"]["entries"][0]["request"]["url"] = self.base + "?secret=redacted"
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 0)
        self.assertNotIn("redacted", json.dumps(report))

    def test_har_missing_body_is_incomplete_even_if_cached(self):
        har = self.har()
        response = har["log"]["entries"][1]["response"]
        response["_fromCache"] = True
        del response["content"]["text"]
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 2)
        self.assertIn("missing_response_body", self.codes(report))

    def test_har_cached_304_is_incomplete(self):
        har = self.har()
        har["log"]["entries"][1]["response"]["status"] = 304
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 2)
        self.assertIn("incomplete_http_response", self.codes(report))

    def test_har_missing_required_asset_is_incomplete(self):
        har = self.har()
        har["log"]["entries"].pop(2)
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 2)
        self.assertIn("required_path_unobserved", self.codes(report))

    def test_har_tampering_fails_even_with_matching_duplicate(self):
        har = self.har()
        har["log"]["entries"].append(self.har_entry("app.js", b"malicious();"))
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 1)
        self.assertIn("body_mismatch", self.codes(report))

    def test_har_incomplete_duplicate_does_not_become_pass(self):
        har = self.har()
        extra = self.har_entry("app.js")
        del extra["response"]["content"]["text"]
        har["log"]["entries"].append(extra)
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 2)

    def test_har_unlisted_script_and_html_fail(self):
        for path in ("unknown.js", "unknown.html"):
            har = self.har()
            extra = self.har_entry("app.js")
            extra["request"]["url"] = self.base + path
            har["log"]["entries"].append(extra)
            report, code = verify.verify_har(self.manifest, har, self.base)
            self.assertEqual(code, 1)
            self.assertIn("unlisted_application_resource", self.codes(report))

    def test_har_external_code_detected_by_suffix_mime_and_resource_type(self):
        for extension, mime, kind in (("x.js", "", ""), ("opaque", "application/wasm", ""),
                                      ("opaque", "", "worker"), ("opaque", "text/html", "")):
            har = self.har()
            extra = self.har_entry("app.js")
            extra["request"]["url"] = "https://cdn.example/" + extension + "?token=hidden"
            extra["response"]["content"]["mimeType"] = mime
            extra["_resourceType"] = kind
            har["log"]["entries"].append(extra)
            report, code = verify.verify_har(self.manifest, har, self.base)
            self.assertEqual(code, 1)
            self.assertIn("external_executable_or_document", self.codes(report))
            self.assertNotIn("hidden", json.dumps(report))

    def test_har_unrelated_json_data_does_not_claim_to_verify_it(self):
        har = self.har()
        extra = self.har_entry("app.js", b'{"name":"PRIVATE"}')
        extra["request"]["url"] = "https://vault.example/api/files/"
        extra["response"]["content"]["mimeType"] = "application/json"
        extra["response"]["headers"] = [{"name": "Set-Cookie", "value": "secret=PRIVATE"}]
        har["log"]["entries"].append(extra)
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 0)
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_har_base64_is_strict_and_valid_base64_matches(self):
        har = self.har()
        content = har["log"]["entries"][1]["response"]["content"]
        content.update(encoding="base64", text=base64.b64encode(self.assets["app.js"]).decode("ascii"))
        self.assertEqual(verify.verify_har(self.manifest, har, self.base)[1], 0)
        content["text"] += "!"
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 2)
        self.assertIn("invalid_har_body", self.codes(report))

    def test_sourcemap_or_source_metadata_cannot_override_served_body(self):
        har = self.har()
        entry = har["log"]["entries"][1]
        entry["_sourceMap"] = {"sourcesContent": [self.assets["app.js"].decode()]}
        entry["response"]["content"]["text"] = "malicious();"
        report, code = verify.verify_har(self.manifest, har, self.base)
        self.assertEqual(code, 1)

    def test_declared_security_headers_must_match_and_not_duplicate(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["response_headers"] = {"x-content-type-options": "nosniff"}
        har = self.har()
        for entry in har["log"]["entries"]:
            entry["response"]["headers"] = [{"name": "X-Content-Type-Options", "value": "nosniff"}]
        self.assertEqual(verify.verify_har(manifest, har, self.base)[1], 0)
        har["log"]["entries"][0]["response"]["headers"].append({"name": "x-content-type-options", "value": "nosniff"})
        report, code = verify.verify_har(manifest, har, self.base)
        self.assertEqual(code, 1)
        self.assertIn("security_header_mismatch", self.codes(report))

    def test_secret_headers_cannot_be_added_to_policy(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["response_headers"] = {"authorization": "Bearer PRIVATE"}
        with self.assertRaises(verify.Invalid):
            verify.validate_manifest(manifest)

    def test_cli_writes_report_and_returns_nonzero_on_incomplete_input(self):
        manifest_path = self.root / "manifest.json"
        har_path = self.root / "capture.har"
        report_path = self.root / "report.json"
        verify.write_json(manifest_path, self.manifest)
        verify.write_json(har_path, {"log": {"entries": []}})
        result = verify.main(["verify-har", "--manifest", str(manifest_path), "--har", str(har_path),
                              "--base-url", self.base, "--report", str(report_path)])
        self.assertEqual(result, 2)
        self.assertEqual(json.loads(report_path.read_text())["status"], "incomplete")

    def test_cli_does_not_overwrite_its_evidence(self):
        manifest_path = self.root / "manifest.json"
        har_path = self.root / "capture.har"
        verify.write_json(manifest_path, self.manifest)
        verify.write_json(har_path, {"log": {"entries": []}})
        original = manifest_path.read_bytes()
        with contextlib.redirect_stdout(__import__("io").StringIO()):
            result = verify.main(["verify-har", "--manifest", str(manifest_path), "--har", str(har_path),
                                  "--base-url", self.base, "--report", str(manifest_path)])
        self.assertEqual(result, 2)
        self.assertEqual(manifest_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
