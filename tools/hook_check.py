"""Pulls the server exe of every build in data/builds.json that records an exe_sha256 from the private exe store.

It runs the hook self-test and the compat tool's check on each exe, and refuses a change to a build that lists none.
Run it from the repository root with GH_TOKEN, GITHUB_ACTOR and RUNNER_TEMP set; ctest runs test_hook_check.py.
"""

import base64
import contextlib
import hashlib
import http.client
import io
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path

REPOSITORY = "anthony-spruyt/enshrouded-server-exe"
LABEL_PREFIX = "io.github.anthony-spruyt.enshrouded."
EXE_NAME = "enshrouded_server.exe"
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)
ATTEMPTS = 3
TIMEOUT = 60
MAX_REDIRECTS = 3
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
CONNECTION_ERRORS = (OSError, http.client.HTTPException)
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
MAX_JSON_BYTES = 1 << 20
MAX_LAYER_BYTES = 1 << 30
REGULAR_FILE_TYPES = (tarfile.REGTYPE, tarfile.AREGTYPE)
CHUNK_BYTES = 1 << 20
TOOL_TIMEOUT = 120
BUILD_ID = re.compile(r"\d{1,12}", re.ASCII)
WORK_NAME = "exe-hook-check"
BUILDS_PATH = Path("data") / "builds.json"
SELFTEST_PATH = Path("build") / "livemap_selftest.exe"
COMPAT_PATH = Path("build") / "tools" / "compat" / "livemap_compat.exe"
PINNED_ROWS = {
    "25988414": "4e5da307fd9436448b8c1e75278d3f238411ed7ccfa6bf50b47dce3b730ef5ca",
    "26083076": "023099bde5efd4c6ffa1791c99d156ea9105136b7e45165ad4a274ae3214d290",
    "26319703": "7ec5bc5e3f155f711d4b1ae5f6e2dd8777d4c074d388d293567b3a16c6b61d21",
}
SITE_LINE = re.compile(r"^(\w+)\s+rva 0x[0-9a-f]+$", re.MULTILINE)


class HookCheckError(Exception):
    pass


class RegistryStatusError(HookCheckError):
    def __init__(self, status, what):
        super().__init__(f"the registry answered {status} for {what}")
        self.status = status


@dataclass
class Reply:
    status: int
    headers: object
    stream: object


@dataclass(frozen=True)
class Tools:
    selftest: Path
    compat: Path


TOOLS = Tools(SELFTEST_PATH, COMPAT_PATH)


class Registry:
    def __init__(self, opener, sleep=time.sleep):
        self._opener = opener
        self._sleep = sleep
        self._bearer = None

    def login(self, actor, secret):
        credentials = base64.b64encode(f"{actor}:{secret}".encode()).decode()
        url = f"https://ghcr.io/token?service=ghcr.io&scope=repository:{REPOSITORY}:pull"
        what = "the pull token"
        body = self._get(
            url, {"Authorization": f"Basic {credentials}"}, what, lambda stream: read_json_body(stream, what)
        )
        token = parse_json(body, "the pull token").get("token")
        if not isinstance(token, str) or not token:
            raise HookCheckError("the registry's reply has no pull token")
        self._bearer = token

    def manifest(self, tag):
        headers = {"Authorization": f"Bearer {self._bearer}", "Accept": MANIFEST_ACCEPT}
        what = f"the manifest of build {tag}"
        url = f"https://ghcr.io/v2/{REPOSITORY}/manifests/{tag}"
        body = self._get(url, headers, what, lambda stream: read_json_body(stream, what))
        return parse_json(body, what), "sha256:" + hashlib.sha256(body).hexdigest()

    def config(self, tag, descriptor):
        what = f"the config of build {tag}"
        digest, size = descriptor_fields(descriptor, what, MAX_JSON_BYTES)

        def read(stream):
            out = io.BytesIO()
            copy_verified(stream, out, digest, size, what)
            return out.getvalue()

        return parse_json(self._blob(digest, what, read), what)

    def layer(self, tag, descriptor, dest):
        what = f"the layer of build {tag}"
        digest, size = descriptor_fields(descriptor, what, MAX_LAYER_BYTES)

        def save(stream):
            try:
                out = dest.open("wb")
            except OSError as exc:
                raise write_error(what, exc) from exc
            with out:
                copy_verified(stream, out, digest, size, what)

        self._blob(digest, what, save)

    def _blob(self, digest, what, consume):
        url = f"https://ghcr.io/v2/{REPOSITORY}/blobs/{digest}"
        return self._get(url, {"Authorization": f"Bearer {self._bearer}"}, what, consume)

    def _get(self, url, headers, what, consume):
        failure = None
        for attempt in range(1, ATTEMPTS + 1):
            try:
                return self._fetch(url, headers, what, consume)
            except CONNECTION_ERRORS as exc:
                failure = exc
                print(f"{what}: {type(exc).__name__} on attempt {attempt} of {ATTEMPTS}")
                if attempt < ATTEMPTS:
                    self._sleep(attempt)
        raise HookCheckError(f"the registry could not be reached for {what} ({type(failure).__name__})")

    def _fetch(self, url, headers, what, consume):
        for _ in range(MAX_REDIRECTS + 1):
            reply = self._send(url, headers)
            with contextlib.closing(reply.stream):
                if reply.status in REDIRECT_STATUSES:
                    url = redirect_target(url, reply.headers.get("Location"), what)
                    headers = {key: value for key, value in headers.items() if key.lower() != "authorization"}
                    continue
                if reply.status != 200:
                    raise RegistryStatusError(reply.status, what)
                return consume(reply.stream)
        raise HookCheckError(f"too many redirects for {what}")

    def _send(self, url, headers):
        request = urllib.request.Request(url, headers=headers)
        try:
            response = self._opener.open(request, timeout=TIMEOUT)
        except urllib.error.HTTPError as exc:
            return Reply(exc.code, exc.headers, exc)
        return Reply(response.status, response.headers, response)


def read_json_body(stream, what):
    body = stream.read(MAX_JSON_BYTES + 1)
    if len(body) > MAX_JSON_BYTES:
        raise HookCheckError(f"{what} is longer than the {MAX_JSON_BYTES} bytes allowed")
    return body


def parse_json(body, what):
    try:
        value = json.loads(body)
    except ValueError as exc:
        raise HookCheckError(f"{what} is not JSON") from exc
    if not isinstance(value, dict):
        raise HookCheckError(f"{what} is not a JSON object")
    return value


def redirect_target(current, location, what):
    if not location:
        raise HookCheckError(f"the registry redirected {what} without a Location")
    target = urllib.parse.urljoin(current, location)
    if urllib.parse.urlsplit(target).scheme != "https":
        raise HookCheckError(f"the registry redirected {what} to an address that is not an https address")
    return target


def descriptor_fields(descriptor, what, limit):
    digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
    size = descriptor.get("size") if isinstance(descriptor, dict) else None
    if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
        raise HookCheckError(f"{what} has no sha256 digest in the manifest")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise HookCheckError(f"{what} has no size in the manifest")
    if size > limit:
        raise HookCheckError(f"{what} is {size} bytes, more than the {limit} allowed")
    return digest, size


def write_error(what, exc):
    return HookCheckError(f"{what} could not be written ({type(exc).__name__})")


def copy_verified(stream, out, digest, size, what):
    hasher = hashlib.sha256()
    total = 0
    while chunk := stream.read(CHUNK_BYTES):
        total += len(chunk)
        if total > size:
            raise HookCheckError(f"{what} is longer than the {size} bytes the manifest says")
        hasher.update(chunk)
        try:
            out.write(chunk)
        except OSError as exc:
            raise write_error(what, exc) from exc
    if total != size:
        raise HookCheckError(f"{what} is {total} bytes, but the manifest says {size}")
    actual = "sha256:" + hasher.hexdigest()
    if actual != digest:
        raise HookCheckError(f"{what} has digest {actual}, but the manifest says {digest}")
    print(f"{what}: {digest}, {size} bytes")


def pull_exe(registry, tag, expected_sha256, work):
    try:
        return pull_checked(registry, tag, expected_sha256, work)
    except RegistryStatusError as exc:
        if exc.status == 404:
            raise HookCheckError(f"the exe store has no exe for build {tag} ({exc})") from exc
        raise


def pull_checked(registry, tag, expected_sha256, work):
    manifest, manifest_digest = registry.manifest(tag)
    print(f"build {tag}: manifest {manifest_digest}")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) != 1:
        count = len(layers) if isinstance(layers, list) else 0
        raise HookCheckError(f"the image for build {tag} must have exactly one layer, not {count}")
    check_labels(registry.config(tag, manifest.get("config")), tag, expected_sha256)

    folder = work / tag
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / "layer"
    try:
        registry.layer(tag, layers[0], archive)
        exe = extract_exe(archive, folder / EXE_NAME, tag, expected_sha256)
    finally:
        archive.unlink(missing_ok=True)
    return exe


def check_labels(config, tag, expected_sha256):
    inner = config.get("config")
    labels = inner.get("Labels") if isinstance(inner, dict) else None
    labels = labels if isinstance(labels, dict) else {}
    for name, want in (("build-id", tag), ("exe-sha256", expected_sha256)):
        got = labels.get(LABEL_PREFIX + name)
        if got != want:
            raise HookCheckError(f"the image for build {tag} has label {name} {got!r}, expected {want!r}")


def extract_exe(archive, dest, tag, expected_sha256):
    what = f"the layer of build {tag}"
    try:
        with tarfile.open(archive, mode="r:*") as tar:
            members = list(itertools.islice(tar, 2))
            if len(members) != 1 or members[0].name != EXE_NAME or members[0].type not in REGULAR_FILE_TYPES:
                raise HookCheckError(f"{what} must hold exactly one regular file named {EXE_NAME}")
            if members[0].size > MAX_LAYER_BYTES:
                raise HookCheckError(
                    f"{EXE_NAME} in {what} is {members[0].size} bytes, more than the {MAX_LAYER_BYTES} allowed"
                )
            source = tar.extractfile(members[0])
            with dest.open("wb") as out:
                actual, size = copy_hashed(source, out)
    except (tarfile.TarError, EOFError, zlib.error) as exc:
        raise HookCheckError(f"{what} is not a readable tar archive ({type(exc).__name__})") from exc
    print(f"build {tag}: {EXE_NAME} sha256 {actual}, {size} bytes")
    if actual != expected_sha256:
        raise HookCheckError(f"{EXE_NAME} sha256 is {actual}, expected {expected_sha256} (build {tag})")
    return dest


def copy_hashed(source, out):
    hasher = hashlib.sha256()
    total = 0
    while chunk := source.read(CHUNK_BYTES):
        hasher.update(chunk)
        out.write(chunk)
        total += len(chunk)
    return hasher.hexdigest(), total


def run_tool(name, program, arguments, label, run):
    if not program.is_file():
        raise HookCheckError(f"{program} was not built")
    env = {key: value for key, value in os.environ.items() if key != "GH_TOKEN"}
    try:
        result = run(
            [str(program), *arguments], capture_output=True, text=True, errors="replace", timeout=TOOL_TIMEOUT, env=env
        )
    except subprocess.TimeoutExpired as exc:
        raise HookCheckError(f"{name} timed out after {TOOL_TIMEOUT} seconds (build {label})") from exc
    except OSError as exc:
        raise HookCheckError(f"{name} could not start ({type(exc).__name__})") from exc
    print(result.stdout, end="")
    print(result.stderr, end="")
    if result.returncode != 0:
        raise HookCheckError(f"{name} exited with {result.returncode} (build {label})")
    return result.stdout


def run_compat_check(compat, exe, builds_path, row, run=subprocess.run):
    label = row["label"]
    arguments = ["check", "--builds", str(builds_path), "--exe", str(exe)]
    stdout = run_tool("livemap_compat check", compat, arguments, label, run)
    if not re.search(rf"^ok: row {re.escape(label)} ", stdout, flags=re.MULTILINE):
        raise HookCheckError(f"livemap_compat check did not report row {label}")


def run_selftest(selftest, exe, row, run=subprocess.run):
    label = row["label"]
    stdout = run_tool("livemap_selftest", selftest, [str(exe)], label, run)
    if not re.search(rf"^server build {re.escape(label)}$", stdout, flags=re.MULTILINE):
        raise HookCheckError(f"livemap_selftest did not report server build {label}")
    if "OK: all hook sites found" not in stdout:
        raise HookCheckError(f"livemap_selftest did not report that all hook sites were found (build {label})")
    expected = [name for name in row["expected"] if name != "param_entity"]
    found = SITE_LINE.findall(stdout)
    if sorted(found) != sorted(expected):
        missing = ", ".join(sorted(set(expected) - set(found)))
        unexpected = ", ".join(sorted(set(found) - set(expected)))
        details = "".join(
            (f"; missing: {missing}" if missing else "", f"; unexpected: {unexpected}" if unexpected else "")
        )
        raise HookCheckError(
            f"livemap_selftest found {len(found)} of {len(expected)} hook sites{details} (build {label})"
        )
    print(f"Hook check passed: all {len(expected)} hook sites found on server build {label}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def build_opener():
    return urllib.request.build_opener(NoRedirect)


def select_builds(builds_path):
    selected = []
    for row in json.loads(builds_path.read_text(encoding="utf-8"))["builds"]:
        if row["steam"]["exe_sha256"] is None:
            print(
                f"::notice title=Hook check::build {row['label']} lists no exe_sha256 in data/builds.json, "
                "so its row and its sigset cannot change."
            )
            continue
        for tag in row["buildids"]:
            if not BUILD_ID.fullmatch(tag):
                raise HookCheckError(f"{tag!r} in data/builds.json is not a build id")
            selected.append((row, tag))
    if not selected:
        raise HookCheckError("data/builds.json has no build with an exe_sha256 to check")
    return selected


def row_digest(row, patterns):
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":")) + json.dumps(
        patterns, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def check_row_coverage(builds_path):
    document = json.loads(builds_path.read_text(encoding="utf-8"))
    for row in document["builds"]:
        if row["steam"]["exe_sha256"] is not None:
            continue
        label = row["label"]
        if label not in PINNED_ROWS:
            raise HookCheckError(f"build {label} lists no exe_sha256: a build needs one in data/builds.json")
        if row_digest(row, document["sigsets"][row["sigset"]]) != PINNED_ROWS[label]:
            raise HookCheckError(f"build {label} lists no exe_sha256, so its row and its sigset cannot change")


def check_builds(builds_path, tools, work, registry, run=subprocess.run):
    check_row_coverage(builds_path)
    for row, tag in select_builds(builds_path):
        exe = pull_exe(registry, tag, row["steam"]["exe_sha256"], work)
        run_selftest(tools.selftest, exe, row, run)
        run_compat_check(tools.compat, exe, builds_path, row, run)


def require_env(env, name):
    value = env.get(name)
    if not value:
        raise HookCheckError(f"{name} is not set")
    return value


def main(env=None, opener=None, run=subprocess.run, sleep=time.sleep):
    env = os.environ if env is None else env
    work = None
    try:
        work = Path(require_env(env, "RUNNER_TEMP")) / WORK_NAME
        actor = require_env(env, "GITHUB_ACTOR")
        secret = require_env(env, "GH_TOKEN")
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        registry = Registry(opener or build_opener(), sleep)
        registry.login(actor, secret)
        check_builds(BUILDS_PATH, TOOLS, work, registry, run)
    except HookCheckError as exc:
        print(f"::error::{exc}")
        return 1
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
