#!/usr/bin/env python3
"""Bounded Mesh declaration client. No Git execution or secrets in exported files."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

LIMIT = 2 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("configuration API redirects are refused")


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def load(path):
    with Path(path).open("rb") as source:
        data = source.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("configuration input exceeds 2 MiB")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def save(path, value):
    # Artifacts contain network intent, never the bearer token. Refuse to silently
    # overwrite an existing preview whose request identity may already be applied.
    with Path(path).open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, ensure_ascii=False)
        output.write("\n")


def endpoint():
    origin = os.environ.get("PEERWARD_CONTROL_URL", "").rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    try:
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
        raise ValueError("PEERWARD_CONTROL_URL must be an API origin without credentials or a path")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("HTTPS is required except for an isolated loopback fixture")
    mesh = str(uuid.UUID(os.environ["PEERWARD_MESH_ID"], version=None))
    if uuid.UUID(mesh).version != 4:
        raise ValueError("Mesh identity must be UUID v4")
    token = os.environ.get("PEERWARD_MACHINE_TOKEN", "")
    if not token.startswith("pw_machine_") or any(char.isspace() for char in token):
        raise ValueError("a scoped machine credential is required")
    return origin + "/api/v1/meshes/" + mesh + "/configuration", token, mesh


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("export", "validate", "preview", "apply"))
    parser.add_argument("--file", type=Path, help="declaration JSON")
    parser.add_argument("--output", type=Path, help="new export or review artifact path")
    parser.add_argument("--preview", type=Path, help="retained review artifact for apply/retry")
    args = parser.parse_args()
    base, token, mesh = endpoint()
    opener = urllib.request.build_opener(NoRedirect)

    def api(method, suffix, body=None, version=None):
        data = None if body is None else encode(body)
        if data is not None and len(data) > LIMIT:
            raise ValueError("request exceeds the 2 MiB API limit")
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if version is not None:
            headers["If-Match"] = '"' + str(version) + '"'
        request = urllib.request.Request(base + suffix, data=data, headers=headers, method=method)
        with opener.open(request, timeout=30) as response:
            result = response.read(LIMIT + 1)
        if len(result) > LIMIT:
            raise ValueError("API response exceeds 2 MiB")
        return json.loads(result)

    if args.operation == "export":
        if not args.output:
            parser.error("export requires --output")
        snapshot = api("GET", "/export")
        save(args.output, snapshot["document"])
        print(json.dumps({"version": snapshot["version"], "output": str(args.output)}))
        return
    if not args.file:
        parser.error("this operation requires --file")
    document = load(args.file)
    if args.operation == "validate":
        result = api("POST", "/validate", document)
    elif args.operation == "preview":
        if not args.output:
            parser.error("preview requires --output")
        snapshot = api("GET", "/export")
        result = api("POST", "/preview", document, snapshot["version"])
        save(args.output, {"mesh_id": mesh, "request_id": str(uuid.uuid4()),
                           "document": document, "input_sha256": hashlib.sha256(encode(document)).hexdigest(),
                           "preview": result})
    else:
        if not args.preview:
            parser.error("apply requires --preview; reuse the same file after a lost response")
        retained = load(args.preview)
        if retained["mesh_id"] != mesh or retained["document"] != document or retained["input_sha256"] != hashlib.sha256(encode(document)).hexdigest():
            raise ValueError("declaration or Mesh differs from the reviewed artifact")
        review = retained["preview"]
        if not review["can_apply"]:
            raise ValueError("review has failed assertions; correct and preview again")
        result = api("POST", "/apply", {"request_id": retained["request_id"], "document": document,
                                       "preview_digest": review["preview_digest"]}, review["version"])
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["can_apply"]:
        raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read(8192))
            message = body.get("error", {}).get("code", "api_error")
        except (ValueError, TypeError):
            message = "api_error"
        print(f"API rejected configuration: HTTP {error.code}, {message}", file=sys.stderr)
        raise SystemExit(1) from None
    except (ValueError, KeyError, OSError) as error:
        # Do not include HTTP request headers, raw URLs, environment or secrets.
        print(f"Configuration operation failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
