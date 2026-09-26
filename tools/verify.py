#!/usr/bin/env python3
"""Compare a trusted static release with HTTP responses or a supplied HAR capture.

Python standard library only. This is an offline observer, not a browser execution
gate. Never obtain the trusted manifest from the server being examined.
"""

import argparse
import base64
import binascii
import hashlib
from http.client import HTTPException
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


FORMAT = "cloud-cypher-static-manifest"
MAX_BODY = 32 * 1024 * 1024
MAX_JSON = 128 * 1024 * 1024
CORE = ("index.html", "app.js", "crypto.js", "http.js", "account.js", "passkeys.js", "vendor/opaque.js", "style.css")
SECURITY_HEADERS = frozenset({
    "content-security-policy", "x-content-type-options", "referrer-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "cross-origin-resource-policy", "permissions-policy", "cache-control", "x-frame-options",
})
ACTIVE_SUFFIXES = (".js", ".mjs", ".cjs", ".wasm", ".html", ".htm", ".xhtml", ".css")
ACTIVE_TYPES = frozenset({
    "script", "stylesheet", "document", "main_frame", "sub_frame", "worker",
    "serviceworker", "sharedworker", "webassembly",
})
LIMITATIONS = [
    "A match establishes byte equality only within the stated observation scope.",
    "It does not establish source safety, server behavior, equal delivery to others, or future delivery.",
    "It does not block code execution or undo disclosure before verification.",
]


class Invalid(ValueError):
    """Invalid input, without reflecting potentially sensitive input values."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate_json_key")
        result[key] = value
    return result


def load_json(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_JSON + 1)
        if len(data) > MAX_JSON:
            raise Invalid("json_too_large")
        return json.loads(data, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid("invalid_json_number")))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Invalid("unreadable_json") from error


def safe_path(path):
    if (not isinstance(path, str) or not path or path.startswith("/")
            or not re.fullmatch(r"[A-Za-z0-9_.\-/]+", path)
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise Invalid("invalid_manifest_path")
    return path


def validate_header_policy(policy):
    if not isinstance(policy, dict):
        raise Invalid("invalid_header_policy")
    for key, value in policy.items():
        if (key not in SECURITY_HEADERS or not isinstance(value, str)
                or not value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
            raise Invalid("invalid_header_policy")
    return policy


def validate_manifest(manifest):
    if (not isinstance(manifest, dict) or manifest.get("format") != FORMAT
            or type(manifest.get("version")) is not int or manifest["version"] != 1
            or set(manifest) - {"format", "version", "files", "required_paths", "response_headers"}):
        raise Invalid("invalid_manifest_format")
    files = manifest.get("files")
    required = manifest.get("required_paths")
    if not isinstance(files, list) or not files or not isinstance(required, list) or not required:
        raise Invalid("invalid_manifest_files")
    paths = set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "bytes"}:
            raise Invalid("invalid_manifest_file")
        path = safe_path(item["path"])
        if (path in paths or not isinstance(item["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_BODY):
            raise Invalid("invalid_manifest_file")
        paths.add(path)
    for path in required:
        safe_path(path)
    if len(set(required)) != len(required) or not set(required) <= paths or "index.html" not in required:
        raise Invalid("invalid_required_paths")
    validate_header_policy(manifest.get("response_headers", {}))
    return manifest


def build_manifest(root, output=None, required=None, headers=None):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise Invalid("invalid_web_root")
    root = root.resolve()
    excluded = Path(output).resolve() if output else None
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Invalid("symlink_in_web_root")
        if path.resolve() == excluded or path.is_dir():
            continue
        if not path.is_file():
            raise Invalid("unsupported_web_file")
        relative = safe_path(path.relative_to(root).as_posix())
        with path.open("rb") as stream:
            data = stream.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            raise Invalid("web_file_too_large")
        files.append({"path": relative, "sha256": digest(data), "bytes": len(data)})
    available = {item["path"] for item in files}
    required = sorted(set(required)) if required is not None else [p for p in CORE if p in available]
    result = {"format": FORMAT, "version": 1, "files": files, "required_paths": required}
    if headers:
        result["response_headers"] = validate_header_policy(headers)
    return validate_manifest(result)


def parsed_url(url, base=False):
    if not isinstance(url, str) or any(ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise Invalid("invalid_url")
    try:
        parts = urlsplit(url)
        if (parts.scheme not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None):
            raise Invalid("invalid_url")
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise Invalid("invalid_url")
    except ValueError as error:
        raise Invalid("invalid_url") from error
    path = parts.path or "/"
    decoded = unquote(path, errors="strict")
    if ("\\" in decoded or any(c in decoded for c in "\x00\r\n")
            or any(p in (".", "..") for p in decoded.split("/"))
            or "%" in decoded or re.search(r"%2f|%5c", path, re.I)):
        raise Invalid("unsafe_url_path")
    if base and (parts.query or parts.fragment or not path.endswith("/") or "%" in path):
        raise Invalid("invalid_base_url")
    return parts, (parts.scheme, parts.hostname.lower(), port), decoded


def make_report(mode):
    return {"format": "cloud-cypher-verification-report", "version": 1,
            "scope": mode, "status": "incomplete", "checked": [], "issues": [],
            "required_paths": [], "observed_paths": [], "unobserved_paths": [],
            "limitations": list(LIMITATIONS)}


def issue(report, code, path=None, mismatch=False):
    item = {"code": code, "severity": "mismatch" if mismatch else "incomplete"}
    if path is not None:
        item["path"] = path
    report["issues"].append(item)


def finish(report):
    if any(item["severity"] == "mismatch" for item in report["issues"]):
        report["status"] = "mismatch"
        return report, 1
    if report["issues"]:
        report["status"] = "incomplete"
        return report, 2
    report["status"] = "verified_scope"
    return report, 0


def compare_headers(report, path, headers, policy):
    if not policy:
        return
    if not isinstance(headers, list):
        issue(report, "missing_security_headers", path)
        return
    collected = {}
    for item in headers:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("value"), str):
            issue(report, "invalid_response_headers", path)
            return
        name = item["name"].lower()
        if name in policy:
            collected.setdefault(name, []).append(item["value"].strip())
    for name, expected in policy.items():
        values = collected.get(name, [])
        if not values:
            issue(report, "required_security_header_missing", path, mismatch=True)
        elif len(values) != 1 or values[0] != expected:
            issue(report, "security_header_mismatch", path, mismatch=True)


def compare_body(report, item, body, status):
    actual = digest(body)
    good = actual == item["sha256"] and len(body) == item["bytes"]
    report["checked"].append({"path": item["path"], "sha256": actual,
                              "expected_sha256": item["sha256"], "http_status": status,
                              "status": "match" if good else "mismatch"})
    if not good:
        issue(report, "body_mismatch", item["path"], mismatch=True)
    return good


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def verify_url(manifest, base_url, timeout=15):
    validate_manifest(manifest)
    parsed_url(base_url, base=True)
    report = make_report("new_http_responses_for_all_manifest_paths_and_entry_document")
    report["limitations"].append("These are new unauthenticated observer requests, not a user's browser session.")
    report["security_header_policy_checked"] = bool(manifest.get("response_headers"))
    report["required_paths"] = [item["path"] for item in manifest["files"]]
    opener = build_opener(NoRedirect())
    observed = set()
    requests = [(item["path"], item) for item in manifest["files"]]
    index = next(item for item in manifest["files"] if item["path"] == "index.html")
    requests.append(("", index))
    for suffix, item in requests:
        try:
            request = Request(base_url + suffix, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"})
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                if response.geturl() != base_url + suffix:
                    issue(report, "unexpected_response_url", item["path"], mismatch=True)
                    continue
                if status != 200:
                    issue(report, "unexpected_http_status", item["path"])
                    continue
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    issue(report, "unsupported_content_encoding", item["path"])
                    continue
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    issue(report, "response_too_large", item["path"])
                    continue
                headers = [{"name": k, "value": v} for k, v in response.headers.items()]
                compare_headers(report, item["path"], headers, manifest.get("response_headers", {}))
                if compare_body(report, item, body, status):
                    observed.add(item["path"])
        except HTTPError as error:
            issue(report, "redirect_refused" if 300 <= error.code < 400 else "http_error",
                  item["path"], mismatch=300 <= error.code < 400)
            error.close()
        except (OSError, URLError, ValueError, HTTPException):
            issue(report, "request_failed", item["path"])
    report["observed_paths"] = sorted(observed)
    report["unobserved_paths"] = sorted(set(report["required_paths"]) - observed)
    return finish(report)


def active_resource(entry, path, content):
    kind = entry.get("_resourceType", entry.get("_initiatorType", ""))
    mime = content.get("mimeType", "")
    mime = mime.lower().split(";", 1)[0].strip() if isinstance(mime, str) else ""
    response = entry.get("response", {})
    for header in response.get("headers", []) if isinstance(response.get("headers"), list) else []:
        if isinstance(header, dict) and str(header.get("name", "")).lower() == "content-type":
            value = header.get("value", "")
            if isinstance(value, str):
                mime += ";" + value.lower()
    return ((isinstance(kind, str) and kind in ACTIVE_TYPES) or path.lower().endswith(ACTIVE_SUFFIXES)
            or any(value in mime for value in ("javascript", "ecmascript", "text/html", "application/xhtml", "application/wasm", "text/css")))


def decode_har_body(content):
    if "text" not in content or not isinstance(content["text"], str):
        raise Invalid("missing_response_body")
    encoding = content.get("encoding")
    try:
        if encoding == "base64":
            body = base64.b64decode(content["text"], validate=True)
        elif encoding is None:
            body = content["text"].encode("utf-8")
        else:
            raise Invalid("unsupported_har_encoding")
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise Invalid("invalid_har_body") from error
    if len(body) > MAX_BODY:
        raise Invalid("response_too_large")
    return body


def verify_har(manifest, har, base_url, required=None):
    validate_manifest(manifest)
    _, origin, prefix = parsed_url(base_url, base=True)
    report = make_report("provided_har_response_bodies_and_declared_required_paths")
    report["security_header_policy_checked"] = bool(manifest.get("response_headers"))
    report["limitations"].extend([
        "A HAR is a supplied, editable capture, not an attestation from the browser.",
        "Capture completeness, prior caches, generated code, workers and runtime execution are not proven.",
        "Unencoded HAR text is reconstructed as UTF-8; base64 preserves exported binary bytes.",
        "Unobserved optional manifest files were not verified in this capture.",
    ])
    files = {item["path"]: item for item in manifest["files"]}
    required = manifest["required_paths"] if required is None else required
    for path in required:
        safe_path(path)
    if not required or not set(required) <= files.keys() or "index.html" not in required:
        raise Invalid("invalid_required_paths")
    report["required_paths"] = sorted(set(required))
    if (not isinstance(har, dict) or not isinstance(har.get("log"), dict)
            or not isinstance(har["log"].get("entries"), list)):
        raise Invalid("invalid_har")
    observed = set()
    for entry in har["log"]["entries"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict) or not isinstance(entry.get("response"), dict):
            issue(report, "invalid_har_entry")
            continue
        response = entry["response"]
        content = response.get("content", {})
        if not isinstance(content, dict):
            issue(report, "invalid_har_content")
            continue
        try:
            _, current_origin, path = parsed_url(entry["request"].get("url"))
        except (Invalid, UnicodeError):
            issue(report, "invalid_request_url")
            continue
        in_scope = current_origin == origin and path.startswith(prefix)
        relative = path[len(prefix):] if in_scope else None
        if relative == "":
            relative = "index.html"
        if relative not in files:
            if in_scope or active_resource(entry, path, content):
                issue(report, "unlisted_application_resource" if in_scope else "external_executable_or_document", mismatch=True)
            continue
        request_method = entry["request"].get("method")
        if request_method != "GET":
            issue(report, "unexpected_request_method", relative, mismatch=True)
            continue
        status = response.get("status")
        if type(status) is not int or status != 200:
            issue(report, "redirect_response" if type(status) is int and 300 <= status < 400 and status != 304 else "incomplete_http_response",
                  relative, mismatch=type(status) is int and 300 <= status < 400 and status != 304)
            continue
        compare_headers(report, relative, response.get("headers"), manifest.get("response_headers", {}))
        try:
            body = decode_har_body(content)
        except Invalid as error:
            issue(report, str(error), relative)
            continue
        if compare_body(report, files[relative], body, status):
            observed.add(relative)
    for path in sorted(set(required) - observed):
        issue(report, "required_path_unobserved", path)
    report["observed_paths"] = sorted(observed)
    report["unobserved_paths"] = sorted(files.keys() - observed)
    return finish(report)


def write_json(path, value):
    data = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    if path:
        Path(path).write_text(data, encoding="utf-8")
    else:
        sys.stdout.write(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("manifest", help="Build a manifest from independently trusted local source bytes")
    build.add_argument("--root", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--require-path", action="append", dest="required")
    build.add_argument("--headers-policy", help="Optional local JSON object of exact required security response headers")
    for name in ("verify-url", "verify-har"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", required=True, help="Independent LOCAL trusted manifest, never fetched from the target")
        command.add_argument("--base-url", required=True, help="HTTP(S) directory URL ending in /, without credentials/query/fragment")
        command.add_argument("--report")
        if name == "verify-url":
            command.add_argument("--timeout", type=float, default=15)
        else:
            command.add_argument("--har", required=True)
            command.add_argument("--require-path", action="append", dest="required")
    args = parser.parse_args(argv)
    try:
        if args.command == "manifest":
            policy = load_json(args.headers_policy) if args.headers_policy else None
            manifest = build_manifest(args.root, args.output, args.required, policy)
            write_json(args.output, manifest)
            return 0
        if args.report and Path(args.report).resolve() in {
                Path(args.manifest).resolve(),
                *([Path(args.har).resolve()] if args.command == "verify-har" else [])}:
            # Never replace the supplied evidence with its report, including on error.
            args.report = None
            raise Invalid("report_overwrites_input")
        manifest = validate_manifest(load_json(args.manifest))
        if args.command == "verify-url":
            if not 0 < args.timeout <= 120:
                raise Invalid("invalid_timeout")
            report, code = verify_url(manifest, args.base_url, args.timeout)
        else:
            report, code = verify_har(manifest, load_json(args.har), args.base_url, args.required)
        write_json(args.report, report)
        return code
    except (Invalid, OSError, UnicodeError) as error:
        report = make_report("invalid_or_unreadable_input")
        issue(report, str(error) if isinstance(error, Invalid) else "input_output_error")
        report, code = finish(report)
        try:
            write_json(getattr(args, "report", None), report)
        except OSError:
            sys.stderr.write("Cannot write verification report.\n")
        return code


if __name__ == "__main__":
    sys.exit(main())
