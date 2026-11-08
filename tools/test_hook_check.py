"""Tests for hook_check.py with a fake registry and synthetic images; ctest runs them with pytest."""

import base64
import errno
import gzip
import hashlib
import http.client
import http.server
import io
import json
import re
import subprocess
import tarfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from pathlib import Path

import hook_check
import pytest
from hook_check import HookCheckError, Registry

ACTOR = "octocat"
SECRET = "job-secret-value"
BEARER = "pull-token-value"
TAG = "1234567"
EXE = b"MZ synthetic server exe"
EXE_SHA256 = hashlib.sha256(EXE).hexdigest()
SIGNED_HOST = "localhost"
UNUSED_DIR = Path("unused")


def digest_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def make_layer(members=((hook_check.EXE_NAME, EXE),), compress=True):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    raw = buffer.getvalue()
    return gzip.compress(raw) if compress else raw


class Image:
    def __init__(self, tag=TAG, layer=None, labels=None, layers=1, config=None):
        self.tag = tag
        self.layer = make_layer() if layer is None else layer
        if labels is None:
            labels = {
                hook_check.LABEL_PREFIX + "build-id": tag,
                hook_check.LABEL_PREFIX + "exe-sha256": EXE_SHA256,
            }
        self.config = json.dumps({"config": {"Labels": labels}} if config is None else config).encode()
        descriptor = {"digest": digest_of(self.layer), "size": len(self.layer)}
        self.manifest = json.dumps(
            {
                "schemaVersion": 2,
                "config": {"digest": digest_of(self.config), "size": len(self.config)},
                "layers": [descriptor] * layers,
            }
        ).encode()
        self.blobs = {digest_of(self.config): self.config, digest_of(self.layer): self.layer}


class Reply:
    def __init__(self, status=200, body=b"", headers=None):
        self.status = status
        self.body = body
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value
        self.stream = io.BytesIO(body)
        self.closed = False

    def read(self, size=-1):
        return self.stream.read(size)

    def close(self):
        self.closed = True


class FakeRegistry:
    """Answers like ghcr.io: a pull token, manifests, and blobs that redirect to another host."""

    def __init__(self, *images):
        self.images = {image.tag: image for image in images}
        self.blobs = {}
        for image in images:
            self.blobs.update(image.blobs)
        self.scripted = []
        self.seen = []

    def script(self, needle, *outcomes):
        self.scripted.append((needle, list(outcomes)))

    def open(self, request, timeout=None):
        headers = {key.lower(): value for key, value in request.header_items()}
        self.seen.append((request.full_url, headers, timeout))
        for needle, outcomes in self.scripted:
            if needle in request.full_url and outcomes:
                return self.deliver(request.full_url, outcomes.pop(0))
        return self.deliver(request.full_url, self.answer(request.full_url, headers))

    @staticmethod
    def deliver(url, outcome):
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome.status >= 300:
            raise urllib.error.HTTPError(url, outcome.status, "status", outcome.headers, outcome.stream)
        return outcome

    def answer(self, url, headers):
        parts = urllib.parse.urlsplit(url)
        segments = parts.path.strip("/").split("/")
        if parts.hostname == SIGNED_HOST:
            return self.answer_signed(segments[-1], headers)
        if segments == ["token"]:
            return self.answer_token(headers)
        if headers.get("authorization") != f"Bearer {BEARER}":
            return Reply(401)
        if segments[-2] == "manifests":
            image = self.images.get(segments[-1])
            return Reply(404) if image is None else Reply(body=image.manifest)
        return Reply(307, headers={"Location": f"https://{SIGNED_HOST}/blobs/{segments[-1]}"})

    def answer_signed(self, digest, headers):
        if "authorization" in headers:
            return Reply(400)
        return Reply(body=self.blobs[digest])

    @staticmethod
    def answer_token(headers):
        expected = "Basic " + base64.b64encode(f"{ACTOR}:{SECRET}".encode()).decode()
        if headers.get("authorization") != expected:
            return Reply(401)
        return Reply(body=json.dumps({"token": BEARER}).encode())


def make_registry(*images):
    fake = FakeRegistry(*images)
    registry = Registry(fake, sleep=lambda seconds: None)
    registry.login(ACTOR, SECRET)
    return fake, registry


def test_login_sends_basic_credentials_and_manifest_uses_the_bearer_token():
    fake, registry = make_registry(Image())
    manifest, digest = registry.manifest(TAG)
    assert len(manifest["layers"]) == 1
    assert digest == digest_of(fake.images[TAG].manifest)
    token_url, token_headers, _ = fake.seen[0]
    assert urllib.parse.urlsplit(token_url).path == "/token"
    assert token_headers["authorization"].startswith("Basic ")
    assert fake.seen[1][1]["authorization"] == f"Bearer {BEARER}"
    assert "application/vnd.oci.image.manifest.v1+json" in fake.seen[1][1]["accept"]


def test_login_refused_names_the_status_and_not_the_secret():
    fake = FakeRegistry()
    fake.script("/token", Reply(403))
    registry = Registry(fake, sleep=lambda seconds: None)
    with pytest.raises(HookCheckError, match="403") as caught:
        registry.login(ACTOR, SECRET)
    assert SECRET not in str(caught.value)


def test_404_on_a_manifest_says_the_store_has_no_exe_for_the_build():
    _, registry = make_registry()
    with pytest.raises(HookCheckError, match=f"no exe for build {TAG}"):
        hook_check.pull_exe(registry, TAG, EXE_SHA256, UNUSED_DIR)


@pytest.mark.parametrize("status", [401, 403, 429, 500, 502, 503])
def test_other_statuses_are_registry_failures_not_absence(status):
    fake, registry = make_registry(Image())
    fake.script("/manifests/", Reply(status))
    with pytest.raises(HookCheckError, match=f"answered {status}") as caught:
        hook_check.pull_exe(registry, TAG, EXE_SHA256, UNUSED_DIR)
    assert "no exe" not in str(caught.value)


def test_a_201_is_not_a_200():
    fake, registry = make_registry(Image())
    fake.script("/manifests/", Reply(201, body=b"{}"))
    with pytest.raises(HookCheckError, match="answered 201"):
        hook_check.pull_exe(registry, TAG, EXE_SHA256, UNUSED_DIR)


def descriptor_of(image, which="layer"):
    blob = image.layer if which == "layer" else image.config
    return {"digest": digest_of(blob), "size": len(blob)}


def test_blob_redirect_is_followed_without_the_authorization_header(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    registry.layer(TAG, descriptor_of(image), tmp_path / "layer")
    assert (tmp_path / "layer").read_bytes() == image.layer
    blob_url, blob_headers, _ = fake.seen[-2]
    assert urllib.parse.urlsplit(blob_url).hostname == "ghcr.io"
    assert blob_headers["authorization"] == f"Bearer {BEARER}"
    signed_url, signed_headers, _ = fake.seen[-1]
    assert urllib.parse.urlsplit(signed_url).hostname == SIGNED_HOST
    assert "authorization" not in signed_headers


def test_config_blob_redirect_drops_the_authorization_header_too():
    image = Image()
    fake, registry = make_registry(image)
    assert registry.config(TAG, descriptor_of(image, "config")) == json.loads(image.config)
    assert "authorization" not in fake.seen[-1][1]


@pytest.mark.parametrize(
    "location",
    ["http://127.0.0.1/blobs/x", "HTTP://127.0.0.1/blobs/x", "ftp://localhost/blobs/x", "file:///blobs/x"],
)
def test_redirect_that_is_not_https_is_refused(location, tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    fake.script("/blobs/", Reply(302, headers={"Location": location}))
    descriptor = descriptor_of(image)
    with pytest.raises(HookCheckError, match="not an https"):
        registry.layer(TAG, descriptor, tmp_path / "layer")
    assert len(fake.seen) == 2


def test_redirect_without_a_location_is_refused(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    fake.script("/blobs/", Reply(302))
    descriptor = descriptor_of(image)
    with pytest.raises(HookCheckError, match="without a Location"):
        registry.layer(TAG, descriptor, tmp_path / "layer")


def test_relative_redirect_stays_on_the_registry_host_and_loses_the_header(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    fake.script("/v2/", Reply(307, headers={"Location": "/elsewhere"}))
    fake.script("/elsewhere", Reply(200, body=image.layer))
    registry.layer(TAG, descriptor_of(image), tmp_path / "layer")
    elsewhere = [seen for seen in fake.seen if seen[0].endswith("/elsewhere")]
    assert urllib.parse.urlsplit(elsewhere[0][0]).hostname == "ghcr.io"
    assert "authorization" not in elsewhere[0][1]


def test_redirect_loop_ends(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    fake.script("/blobs/", *[Reply(302, headers={"Location": "https://localhost/blobs/loop"})] * 10)
    descriptor = descriptor_of(image)
    with pytest.raises(HookCheckError, match="too many redirects"):
        registry.layer(TAG, descriptor, tmp_path / "layer")
    assert len(fake.seen) <= 2 + hook_check.MAX_REDIRECTS + 1


class BrokenStream(Reply):
    def read(self, size=-1):
        raise ConnectionResetError("reset by peer")


class CutStream(Reply):
    def __init__(self, body):
        super().__init__(body=body)
        self.sent = False

    def read(self, size=-1):
        if self.sent:
            raise ConnectionResetError("reset by peer")
        self.sent = True
        return self.body[: len(self.body) // 2]


CONNECTION_FAILURES = [
    urllib.error.URLError("unreachable"),
    TimeoutError("timed out"),
    ConnectionResetError("reset"),
    http.client.RemoteDisconnected("closed"),
]


@pytest.mark.parametrize("failure", CONNECTION_FAILURES, ids=lambda failure: type(failure).__name__)
def test_connection_errors_are_retried_and_the_third_attempt_can_succeed(failure):
    fake, registry = make_registry(Image())
    fake.script("/manifests/", failure, failure)
    manifest, _ = registry.manifest(TAG)
    assert len(manifest["layers"]) == 1
    assert len([seen for seen in fake.seen if "/manifests/" in seen[0]]) == 3


def test_three_connection_errors_end_the_retries(capsys):
    fake, registry = make_registry(Image())
    fake.script("/manifests/", *[TimeoutError("timed out")] * 5)
    with pytest.raises(HookCheckError, match=r"could not be reached.*TimeoutError"):
        registry.manifest(TAG)
    assert len([seen for seen in fake.seen if "/manifests/" in seen[0]]) == hook_check.ATTEMPTS == 3
    printed = capsys.readouterr().out
    assert SECRET not in printed
    assert BEARER not in printed


def test_a_connection_error_while_reading_the_body_is_retried(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    fake.script("localhost/blobs/", BrokenStream(body=image.layer))
    registry.layer(TAG, descriptor_of(image), tmp_path / "layer")
    assert (tmp_path / "layer").read_bytes() == image.layer


class FailingDisk:
    def __init__(self, fails_on):
        self.fails_on = fails_on

    def open(self, mode):
        if self.fails_on == "open":
            raise PermissionError(errno.EACCES, "permission denied")
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def write(self, data):
        raise OSError(errno.ENOSPC, "no space left on device")


@pytest.mark.parametrize("fails_on", ["open", "write"])
def test_a_local_write_error_is_reported_as_such_and_not_retried(fails_on):
    image = Image()
    fake, registry = make_registry(image)
    descriptor = descriptor_of(image)
    disk = FailingDisk(fails_on)
    with pytest.raises(HookCheckError, match=r"could not be written \(\w+\)"):
        registry.layer(TAG, descriptor, disk)
    assert len([seen for seen in fake.seen if seen[0].startswith("https://ghcr.io/v2/")]) == 1


def test_a_config_cut_off_halfway_is_read_again_from_the_start():
    image = Image()
    fake, registry = make_registry(image)
    fake.script("localhost/blobs/", CutStream(image.config))
    assert registry.config(TAG, descriptor_of(image, "config")) == json.loads(image.config)


def test_an_http_error_status_is_not_retried():
    fake, registry = make_registry(Image())
    fake.script("/manifests/", Reply(503), Reply(503), Reply(503))
    with pytest.raises(HookCheckError, match="answered 503"):
        registry.manifest(TAG)
    assert len([seen for seen in fake.seen if "/manifests/" in seen[0]]) == 1


def test_every_request_has_a_timeout(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    registry.manifest(TAG)
    registry.config(TAG, descriptor_of(image, "config"))
    registry.layer(TAG, descriptor_of(image), tmp_path / "layer")
    assert len(fake.seen) == 6
    assert all(timeout is not None and 0 < timeout <= 300 for _, _, timeout in fake.seen)


def test_layer_with_the_wrong_digest_is_refused(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    tampered = bytes([image.layer[0] ^ 1]) + image.layer[1:]
    fake.blobs[digest_of(image.layer)] = tampered
    descriptor = descriptor_of(image)
    with pytest.raises(HookCheckError, match=r"has digest sha256:[0-9a-f]{64}, but the manifest says"):
        registry.layer(TAG, descriptor, tmp_path / "layer")


@pytest.mark.parametrize("delta", [-1, 1])
def test_layer_that_differs_in_size_from_the_manifest_is_refused(delta, tmp_path):
    image = Image()
    _, registry = make_registry(image)
    descriptor = descriptor_of(image)
    descriptor["size"] += delta
    with pytest.raises(HookCheckError, match="the manifest says"):
        registry.layer(TAG, descriptor, tmp_path / "layer")


@pytest.mark.parametrize(
    "descriptor",
    [
        None,
        {},
        {"digest": "sha256:abc", "size": 1},
        {"digest": "md5:" + "0" * 32, "size": 1},
        {"digest": "sha256:" + "0" * 64},
    ],
)
def test_descriptor_without_a_sha256_digest_and_size_is_refused(descriptor, tmp_path):
    _, registry = make_registry(Image())
    with pytest.raises(HookCheckError, match="in the manifest"):
        registry.layer(TAG, descriptor, tmp_path / "layer")


def test_oversized_config_is_refused_before_it_is_fetched():
    image = Image()
    fake, registry = make_registry(image)
    descriptor = {"digest": digest_of(image.config), "size": hook_check.MAX_JSON_BYTES + 1}
    with pytest.raises(HookCheckError, match="more than"):
        registry.config(TAG, descriptor)
    assert len(fake.seen) == 1


def test_oversized_layer_is_refused_before_it_is_fetched(tmp_path):
    image = Image()
    fake, registry = make_registry(image)
    descriptor = {"digest": digest_of(image.layer), "size": hook_check.MAX_LAYER_BYTES + 1}
    dest = tmp_path / "layer"
    with pytest.raises(HookCheckError, match="more than"):
        registry.layer(TAG, descriptor, dest)
    assert len(fake.seen) == 1
    assert not dest.exists()


def test_replies_that_are_not_json_or_lack_the_token_are_refused():
    fake = FakeRegistry(Image())
    registry = Registry(fake, sleep=lambda seconds: None)
    fake.script("/token", Reply(body=b"not json"), Reply(body=b'{"other": 1}'), Reply(body=b'{"token": ""}'))
    for _ in range(3):
        with pytest.raises(HookCheckError, match="pull token"):
            registry.login(ACTOR, SECRET)
    fake.script("/manifests/", Reply(body=b"<html>"))
    registry.login(ACTOR, SECRET)
    with pytest.raises(HookCheckError, match="manifest"):
        registry.manifest(TAG)


def test_manifest_and_token_replies_have_a_size_limit(monkeypatch):
    fake, registry = make_registry(Image())
    monkeypatch.setattr(hook_check, "MAX_JSON_BYTES", 10)
    with pytest.raises(HookCheckError, match="longer than"):
        registry.manifest(TAG)
    fake.script("/token", Reply(body=b'{"token": "' + b"x" * 20 + b'"}'))
    with pytest.raises(HookCheckError, match="longer than"):
        registry.login(ACTOR, SECRET)


def pull(image, tmp_path, expected=EXE_SHA256, tag=TAG):
    _, registry = make_registry(image)
    return hook_check.pull_exe(registry, tag, expected, tmp_path)


def test_pull_writes_the_exe_into_the_work_dir_and_drops_the_layer(tmp_path):
    exe = pull(Image(), tmp_path)
    assert exe == tmp_path / TAG / hook_check.EXE_NAME
    assert exe.read_bytes() == EXE
    assert [path.name for path in (tmp_path / TAG).iterdir()] == [hook_check.EXE_NAME]


def test_pull_reads_an_uncompressed_layer_too(tmp_path):
    assert pull(Image(layer=make_layer(compress=False)), tmp_path).read_bytes() == EXE


def test_pull_never_uses_extract_or_extractall(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("tar members must be copied with extractfile")

    monkeypatch.setattr(tarfile.TarFile, "extract", refuse)
    monkeypatch.setattr(tarfile.TarFile, "extractall", refuse)
    assert pull(Image(), tmp_path).read_bytes() == EXE


@pytest.mark.parametrize("count", [0, 2])
def test_an_image_without_exactly_one_layer_is_refused(count, tmp_path):
    image = Image(layers=count)
    with pytest.raises(HookCheckError, match="exactly one layer"):
        pull(image, tmp_path)


def test_an_index_in_place_of_an_image_is_refused(tmp_path):
    image = Image()
    image.manifest = json.dumps({"schemaVersion": 2, "manifests": []}).encode()
    with pytest.raises(HookCheckError, match="exactly one layer"):
        pull(image, tmp_path)


@pytest.mark.parametrize(
    ("labels", "message"),
    [
        (
            {
                "io.github.anthony-spruyt.enshrouded.build-id": "7654321",
                "io.github.anthony-spruyt.enshrouded.exe-sha256": EXE_SHA256,
            },
            "build-id",
        ),
        (
            {
                "io.github.anthony-spruyt.enshrouded.build-id": TAG,
                "io.github.anthony-spruyt.enshrouded.exe-sha256": "0" * 64,
            },
            "exe-sha256",
        ),
        ({"io.github.anthony-spruyt.enshrouded.build-id": TAG}, "exe-sha256"),
        ({}, "build-id"),
    ],
)
def test_labels_must_name_the_build_and_the_row_sha(labels, message, tmp_path):
    image = Image(labels=labels)
    with pytest.raises(HookCheckError, match=message):
        pull(image, tmp_path)


@pytest.mark.parametrize("config", [{}, {"config": None}, {"config": {"Labels": None}}, {"config": {"Labels": ["x"]}}])
def test_an_image_config_without_labels_is_refused(config, tmp_path):
    image = Image(config=config)
    with pytest.raises(HookCheckError, match="build-id"):
        pull(image, tmp_path)


def test_labels_are_checked_before_the_layer_is_downloaded(tmp_path):
    image = Image(labels={})
    fake, registry = make_registry(image)
    with pytest.raises(HookCheckError, match="build-id"):
        hook_check.pull_exe(registry, TAG, EXE_SHA256, tmp_path)
    assert not [seen for seen in fake.seen if digest_of(image.layer) in seen[0]]
    assert not (tmp_path / TAG).exists()


@pytest.mark.parametrize(
    "members",
    [
        (),
        ((hook_check.EXE_NAME, EXE), ("second.txt", b"x")),
        (("other.exe", EXE),),
        (("./" + hook_check.EXE_NAME, EXE),),
        (("sub/" + hook_check.EXE_NAME, EXE),),
        (("../" + hook_check.EXE_NAME, EXE),),
        (("/" + hook_check.EXE_NAME, EXE),),
        ((hook_check.EXE_NAME.upper(), EXE),),
    ],
)
def test_the_layer_must_hold_exactly_one_file_with_the_exe_name(members, tmp_path):
    image = Image(layer=make_layer(members))
    with pytest.raises(HookCheckError, match="exactly one regular file named"):
        pull(image, tmp_path)
    assert list(tmp_path.rglob(hook_check.EXE_NAME)) == []
    assert not (tmp_path.parent / hook_check.EXE_NAME).exists()


@pytest.mark.parametrize(
    "kind",
    [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.CONTTYPE, tarfile.GNUTYPE_SPARSE],
)
def test_a_member_that_is_not_a_regular_file_is_refused(kind, tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(hook_check.EXE_NAME)
        info.type = kind
        info.linkname = "/etc/hostname"
        tar.addfile(info)
    image = Image(layer=buffer.getvalue())
    with pytest.raises(HookCheckError, match="exactly one regular file named"):
        pull(image, tmp_path)
    assert list(tmp_path.rglob(hook_check.EXE_NAME)) == []


def test_a_file_larger_than_the_cap_is_refused_before_it_is_written(tmp_path, monkeypatch):
    archive = tmp_path / "layer"
    archive.write_bytes(make_layer())
    dest = tmp_path / hook_check.EXE_NAME
    monkeypatch.setattr(hook_check, "MAX_LAYER_BYTES", len(EXE) - 1)
    with pytest.raises(HookCheckError, match="more than"):
        hook_check.extract_exe(archive, dest, TAG, EXE_SHA256)
    assert not dest.exists()


@pytest.mark.parametrize("layer", [b"not a tar archive at all" * 50, make_layer()[:-30]])
def test_an_unreadable_layer_is_refused(layer, tmp_path):
    image = Image(layer=layer)
    with pytest.raises(HookCheckError, match="not a readable tar"):
        pull(image, tmp_path)


def test_an_exe_that_does_not_match_the_row_sha_is_refused(tmp_path):
    image = Image(layer=make_layer(((hook_check.EXE_NAME, b"different bytes"),)))
    with pytest.raises(
        HookCheckError, match=f"sha256 is {hashlib.sha256(b'different bytes').hexdigest()}, expected {EXE_SHA256}"
    ):
        pull(image, tmp_path)


LABEL = "9999999"
ROW = {
    "label": LABEL,
    "sigset": "patch1",
    "buildids": [TAG],
    "steam": {"depot": None, "manifest": None, "exe_sha256": EXE_SHA256},
    "expected": {"player_table": "0x7bed90", "movement": "0x9581a", "param_entity": "0x65fc00"},
}
GOOD_OUTPUT = (
    f"server build {LABEL}\n"
    "player_table  rva 0x7bed90\n"
    "movement      rva 0x9581a\n"
    "param_entity  rva 0x65fc00 entity table +0x830\n"
    "OK: all hook sites found\n"
)
GOOD_COMPAT_OUTPUT = f"ok: row {LABEL} (patch1), 3 hooks checked\n"
FAILED_COMPAT_OUTPUT = f"failed: row {LABEL} (patch1)\n  movement: a problem\n"


class FakeRun:
    """Stands in for subprocess.run; `only` limits `returncode` and `failure` to the selftest or the compat check."""

    def __init__(self, stdout=None, returncode=0, stderr="", failure=None, only=None):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.failure = failure
        self.only = only
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        tool = "compat" if command[1] == "check" else "selftest"
        good = GOOD_COMPAT_OUTPUT if tool == "compat" else GOOD_OUTPUT
        if self.only not in (None, tool):
            return subprocess.CompletedProcess(command, 0, good, "")
        if self.failure:
            raise self.failure
        return subprocess.CompletedProcess(
            command, self.returncode, good if self.stdout is None else self.stdout, self.stderr
        )


@pytest.fixture
def selftest(tmp_path):
    path = tmp_path / "livemap_selftest.exe"
    path.write_bytes(b"")
    return path


def test_selftest_runs_on_the_extracted_exe_with_a_timeout(selftest, tmp_path):
    run = FakeRun()
    hook_check.run_selftest(selftest, tmp_path / "exe", ROW, run)
    command, kwargs = run.calls[0]
    assert command == [str(selftest), str(tmp_path / "exe")]
    assert 0 < kwargs["timeout"] <= 600


def test_selftest_runs_without_the_registry_token_and_keeps_the_rest_of_the_environment(
    selftest, tmp_path, monkeypatch
):
    monkeypatch.setenv("GH_TOKEN", SECRET)
    monkeypatch.setenv("HOOK_CHECK_PROBE", "kept")
    run = FakeRun()
    hook_check.run_selftest(selftest, tmp_path / "exe", ROW, run)
    env = run.calls[0][1]["env"]
    assert "GH_TOKEN" not in env
    assert env["HOOK_CHECK_PROBE"] == "kept"


def test_selftest_output_is_printed(selftest, tmp_path, capsys):
    hook_check.run_selftest(selftest, tmp_path / "exe", ROW, FakeRun(stderr="a warning\n"))
    printed = capsys.readouterr().out
    assert "player_table" in printed
    assert "a warning" in printed
    assert f"all 2 hook sites found on server build {LABEL}" in printed


@pytest.mark.parametrize(
    ("run", "message"),
    [
        (FakeRun(returncode=1), "exited with 1"),
        (FakeRun(returncode=2, stdout=""), "exited with 2"),
        (FakeRun(stdout=GOOD_OUTPUT.replace(LABEL, "1111111")), f"did not report server build {LABEL}"),
        (
            FakeRun(stdout=GOOD_OUTPUT.replace(f"build {LABEL}", f"build {LABEL}0")),
            f"did not report server build {LABEL}",
        ),
        (
            FakeRun(stdout=GOOD_OUTPUT.replace("OK: all hook sites found", "FAIL: a hook site moved")),
            "all hook sites were found",
        ),
        (
            FakeRun(stdout=GOOD_OUTPUT.replace("movement      rva 0x9581a\n", "")),
            "found 1 of 2 hook sites; missing: movement",
        ),
        (
            FakeRun(stdout=GOOD_OUTPUT.replace("0x9581a", "0x1  (UNEXPECTED)")),
            "found 1 of 2 hook sites; missing: movement",
        ),
        (FakeRun(stdout=GOOD_OUTPUT.replace("movement ", "elsewhere")), "missing: movement; unexpected: elsewhere"),
        (FakeRun(stdout=GOOD_OUTPUT + "chest          rva 0x5\n"), "found 3 of 2 hook sites; unexpected: chest"),
        (FakeRun(failure=subprocess.TimeoutExpired("selftest", 1)), "timed out"),
        (FakeRun(failure=OSError("cannot start")), "could not start"),
    ],
)
def test_selftest_failures_fail_the_check(run, message, selftest, tmp_path):
    with pytest.raises(HookCheckError, match=message):
        hook_check.run_selftest(selftest, tmp_path / "exe", ROW, run)


def test_a_selftest_that_was_not_built_fails_the_check(tmp_path):
    run = FakeRun()
    with pytest.raises(HookCheckError, match="was not built"):
        hook_check.run_selftest(tmp_path / "missing.exe", tmp_path / "exe", ROW, run)
    assert run.calls == []


@pytest.fixture
def compat(tmp_path):
    path = tmp_path / "livemap_compat.exe"
    path.write_bytes(b"")
    return path


@pytest.fixture
def tools(selftest, compat):
    return hook_check.Tools(selftest, compat)


def test_compat_check_runs_on_the_extracted_exe_and_the_builds_file_with_a_timeout(compat, tmp_path):
    run = FakeRun()
    builds = tmp_path / "builds.json"
    hook_check.run_compat_check(compat, tmp_path / "exe", builds, ROW, run)
    command, kwargs = run.calls[0]
    assert command == [str(compat), "check", "--builds", str(builds), "--exe", str(tmp_path / "exe")]
    assert 0 < kwargs["timeout"] <= 600


def test_compat_check_runs_without_the_registry_token_and_keeps_the_rest_of_the_environment(
    compat, tmp_path, monkeypatch
):
    monkeypatch.setenv("GH_TOKEN", SECRET)
    monkeypatch.setenv("HOOK_CHECK_PROBE", "kept")
    run = FakeRun()
    hook_check.run_compat_check(compat, tmp_path / "exe", tmp_path / "builds.json", ROW, run)
    env = run.calls[0][1]["env"]
    assert "GH_TOKEN" not in env
    assert env["HOOK_CHECK_PROBE"] == "kept"


def test_compat_check_output_is_printed(compat, tmp_path, capsys):
    run = FakeRun(stderr="a warning\n")
    hook_check.run_compat_check(compat, tmp_path / "exe", tmp_path / "builds.json", ROW, run)
    printed = capsys.readouterr().out
    assert f"ok: row {LABEL}" in printed
    assert "a warning" in printed


@pytest.mark.parametrize(
    ("run", "message"),
    [
        (FakeRun(returncode=3, stdout=FAILED_COMPAT_OUTPUT), "exited with 3"),
        (FakeRun(returncode=1, stdout=""), "exited with 1"),
        (FakeRun(stdout=GOOD_COMPAT_OUTPUT.replace(LABEL, "1111111")), f"did not report row {LABEL}"),
        (FakeRun(stdout=GOOD_COMPAT_OUTPUT.replace(LABEL, LABEL + "0")), f"did not report row {LABEL}"),
        (FakeRun(stdout=""), f"did not report row {LABEL}"),
        (FakeRun(stdout=FAILED_COMPAT_OUTPUT), f"did not report row {LABEL}"),
        (FakeRun(failure=subprocess.TimeoutExpired("compat", 1)), "timed out"),
        (FakeRun(failure=OSError("cannot start")), "could not start"),
    ],
)
def test_compat_check_failures_fail_the_check(run, message, compat, tmp_path):
    with pytest.raises(HookCheckError, match=message):
        hook_check.run_compat_check(compat, tmp_path / "exe", tmp_path / "builds.json", ROW, run)


def test_a_failed_compat_check_still_prints_what_it_found(compat, tmp_path, capsys):
    run = FakeRun(returncode=3, stdout=FAILED_COMPAT_OUTPUT)
    with pytest.raises(HookCheckError):
        hook_check.run_compat_check(compat, tmp_path / "exe", tmp_path / "builds.json", ROW, run)
    assert "movement: a problem" in capsys.readouterr().out


def test_a_compat_tool_that_was_not_built_fails_the_check(tmp_path):
    run = FakeRun()
    with pytest.raises(HookCheckError, match="was not built"):
        hook_check.run_compat_check(tmp_path / "missing.exe", tmp_path / "exe", tmp_path / "b.json", ROW, run)
    assert run.calls == []


PATTERNS = [{"site": "movement", "bytes": "48 8b 05", "offset": "0x3"}]


def builds_file(tmp_path, *rows, sigsets=None):
    path = tmp_path / "builds.json"
    sigsets = {"patch1": PATTERNS} if sigsets is None else sigsets
    path.write_text(json.dumps({"sigsets": sigsets, "builds": list(rows)}), encoding="utf-8")
    return path


def make_row(label, buildids, sha256, sigset="patch1"):
    return {
        **ROW,
        "label": label,
        "sigset": sigset,
        "buildids": buildids,
        "steam": {"depot": None, "manifest": None, "exe_sha256": sha256},
    }


def test_a_build_with_an_exe_needs_no_pin(tmp_path):
    hook_check.check_row_coverage(builds_file(tmp_path, make_row("a", ["11"], EXE_SHA256)))


def test_a_build_without_an_exe_that_is_not_pinned_is_refused(tmp_path):
    path = builds_file(tmp_path, make_row("a", ["11"], EXE_SHA256), make_row("b", ["12"], None))
    with pytest.raises(HookCheckError, match="build b lists no exe_sha256"):
        hook_check.check_row_coverage(path)


@pytest.fixture
def pinned(monkeypatch):
    row = make_row("b", ["12"], None)
    monkeypatch.setattr(hook_check, "PINNED_ROWS", {"b": hook_check.row_digest(row, PATTERNS)})


def shared_sigset_files(tmp_path, patterns=PATTERNS, **changes):
    rows = (make_row("a", ["11"], EXE_SHA256), {**make_row("b", ["12"], None), **changes})
    return builds_file(tmp_path, *rows, sigsets={"patch1": patterns})


def test_a_pinned_build_without_an_exe_is_accepted(tmp_path, pinned):
    hook_check.check_row_coverage(shared_sigset_files(tmp_path))


def test_a_pinned_build_whose_row_changed_is_refused(tmp_path, pinned):
    path = shared_sigset_files(tmp_path, buildids=["13"])
    with pytest.raises(HookCheckError, match="build b lists no exe_sha256, so its row and its sigset cannot change"):
        hook_check.check_row_coverage(path)


def test_a_pinned_build_is_refused_when_its_sigset_changed_although_a_build_with_an_exe_uses_it(tmp_path, pinned):
    changed = [{**PATTERNS[0], "offset": "0x4"}]
    path = shared_sigset_files(tmp_path, patterns=changed)
    with pytest.raises(HookCheckError, match="build b lists no exe_sha256"):
        hook_check.check_row_coverage(path)


def test_a_pinned_build_is_the_same_whatever_the_order_of_its_keys(tmp_path, pinned):
    reordered = [dict(reversed(list(PATTERNS[0].items())))]
    row = dict(reversed(list(make_row("b", ["12"], None).items())))
    rows = (make_row("a", ["11"], EXE_SHA256), row)
    hook_check.check_row_coverage(builds_file(tmp_path, *rows, sigsets={"patch1": reordered}))


def test_the_builds_of_this_repository_are_covered():
    hook_check.check_row_coverage(Path(__file__).resolve().parents[1] / hook_check.BUILDS_PATH)


def test_rows_with_an_exe_sha256_are_selected_once_per_build_id(tmp_path):
    path = builds_file(tmp_path, make_row("a", ["11", "12"], EXE_SHA256), make_row("b", ["21"], EXE_SHA256))
    assert [(row["label"], tag) for row, tag in hook_check.select_builds(path)] == [
        ("a", "11"),
        ("a", "12"),
        ("b", "21"),
    ]


def test_rows_without_an_exe_sha256_get_a_notice_and_are_not_selected(tmp_path, capsys):
    path = builds_file(tmp_path, make_row("old", ["11"], None), make_row("new", ["21"], EXE_SHA256))
    assert [tag for _, tag in hook_check.select_builds(path)] == ["21"]
    printed = capsys.readouterr().out
    assert "::notice title=Hook check::build old lists no exe_sha256" in printed
    assert "build new" not in printed


def test_no_row_with_an_exe_sha256_fails_the_check(tmp_path):
    path = builds_file(tmp_path, make_row("old", ["11"], None))
    with pytest.raises(HookCheckError, match="no build with an exe_sha256"):
        hook_check.select_builds(path)


@pytest.mark.parametrize("bad", ["", "1a", "../1", "1/2", "1234567890123", " 1", "\u0661\u0662\u0663"])
def test_build_ids_are_digits_only_before_they_reach_a_url_or_path(bad, tmp_path):
    path = builds_file(tmp_path, make_row("a", [bad], EXE_SHA256))
    with pytest.raises(HookCheckError, match="not a build id"):
        hook_check.select_builds(path)


def test_every_selected_build_is_pulled_self_tested_and_compat_checked(tmp_path, selftest, compat, monkeypatch):
    other = Image(tag="7654321")
    fake, registry = make_registry(Image(), other)
    old = make_row("old", ["99"], None)
    monkeypatch.setattr(hook_check, "PINNED_ROWS", {"old": hook_check.row_digest(old, PATTERNS)})
    rows = (make_row(LABEL, [TAG, "7654321"], EXE_SHA256), old)
    run = FakeRun()
    work = tmp_path / "work"
    path = builds_file(tmp_path, *rows)
    hook_check.check_builds(path, hook_check.Tools(selftest, compat), work, registry, run)
    exes = [work / TAG / hook_check.EXE_NAME, work / "7654321" / hook_check.EXE_NAME]
    assert [(Path(command[0]), command[1:]) for command, _ in run.calls] == [
        (selftest, [str(exes[0])]),
        (compat, ["check", "--builds", str(path), "--exe", str(exes[0])]),
        (selftest, [str(exes[1])]),
        (compat, ["check", "--builds", str(path), "--exe", str(exes[1])]),
    ]
    assert not [seen for seen in fake.seen if "/99" in seen[0]]


def test_a_failed_compat_check_fails_the_whole_check(tmp_path, tools):
    _, registry = make_registry(Image(), Image(tag="7654321"))
    path = builds_file(tmp_path, make_row(LABEL, [TAG, "7654321"], EXE_SHA256))
    run = FakeRun(returncode=3, stdout=FAILED_COMPAT_OUTPUT, only="compat")
    with pytest.raises(HookCheckError, match="livemap_compat check exited with 3"):
        hook_check.check_builds(path, tools, tmp_path / "work", registry, run)
    assert len(run.calls) == 2


def test_a_build_missing_from_the_store_fails_the_whole_check(tmp_path, tools):
    _, registry = make_registry(Image())
    path = builds_file(tmp_path, make_row(LABEL, [TAG, "7654321"], EXE_SHA256))
    run = FakeRun()
    with pytest.raises(HookCheckError, match="no exe for build 7654321"):
        hook_check.check_builds(path, tools, tmp_path / "work", registry, run)


def test_a_build_without_an_exe_or_a_pin_fails_before_anything_is_pulled(tmp_path, tools):
    fake, registry = make_registry(Image())
    path = builds_file(tmp_path, make_row(LABEL, [TAG], EXE_SHA256), make_row("draft", ["12"], None))
    run = FakeRun()
    requests = len(fake.seen)
    with pytest.raises(HookCheckError, match="build draft"):
        hook_check.check_builds(path, tools, tmp_path / "work", registry, run)
    assert len(fake.seen) == requests
    assert run.calls == []


def test_the_compat_tool_is_where_the_root_build_puts_it():
    cmake = (Path(__file__).resolve().parents[1] / "CMakeLists.txt").read_text(encoding="utf-8")
    subdirectories = re.findall(r"^add_subdirectory\(([\w/]+)\)", cmake, flags=re.MULTILINE)
    assert [Path("build") / name for name in subdirectories if Path(name).name == "compat"] == [
        hook_check.COMPAT_PATH.parent
    ]


class RedirectingServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        self.send_response(302)
        self.send_header("Location", "/next")
        self.end_headers()


def test_the_real_opener_hands_redirects_back_instead_of_following_them():
    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectingServer)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/start", headers={"Authorization": "Bearer x"}
        )
        opener = hook_check.build_opener()
        with pytest.raises(urllib.error.HTTPError) as caught:
            opener.open(request, timeout=5)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert caught.value.code == 302
    assert caught.value.headers["Location"] == "/next"
    assert server.requests == ["/start"]


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "data").mkdir(parents=True)
    (root / hook_check.COMPAT_PATH.parent).mkdir(parents=True)
    (root / hook_check.SELFTEST_PATH).write_bytes(b"")
    (root / hook_check.COMPAT_PATH).write_bytes(b"")
    (root / "data" / "builds.json").write_text(
        json.dumps({"sigsets": {"patch1": PATTERNS}, "builds": [make_row(LABEL, [TAG], EXE_SHA256)]}),
        encoding="utf-8",
    )
    monkeypatch.chdir(root)
    return root


def make_env(tmp_path):
    return {"RUNNER_TEMP": str(tmp_path / "runner"), "GITHUB_ACTOR": ACTOR, "GH_TOKEN": SECRET}


def test_main_passes_and_leaves_no_exe_behind(repo, tmp_path, capsys):
    fake = FakeRegistry(Image())
    run = FakeRun()
    assert hook_check.main(make_env(tmp_path), fake, run, lambda seconds: None) == 0
    assert f"Hook check passed: all 2 hook sites found on server build {LABEL}" in capsys.readouterr().out
    assert [command[1] == "check" for command, _ in run.calls] == [False, True]
    assert not (tmp_path / "runner" / hook_check.WORK_NAME).exists()


@pytest.mark.parametrize("missing", ["RUNNER_TEMP", "GITHUB_ACTOR", "GH_TOKEN"])
def test_main_fails_when_an_environment_variable_is_missing(missing, repo, tmp_path, capsys):
    env = make_env(tmp_path)
    del env[missing]
    assert hook_check.main(env, FakeRegistry(Image()), FakeRun(), lambda seconds: None) == 1
    assert f"::error::{missing} is not set" in capsys.readouterr().out


def test_main_fails_the_check_when_the_store_has_no_exe(repo, tmp_path, capsys):
    assert hook_check.main(make_env(tmp_path), FakeRegistry(), FakeRun(), lambda seconds: None) == 1
    assert f"::error::the exe store has no exe for build {TAG}" in capsys.readouterr().out


@pytest.mark.parametrize("status", [401, 403, 500])
def test_main_fails_the_check_when_the_registry_fails_and_never_prints_the_token(status, repo, tmp_path, capsys):
    fake = FakeRegistry(Image())
    fake.script("/manifests/", Reply(status))
    run = FakeRun()
    assert hook_check.main(make_env(tmp_path), fake, run, lambda seconds: None) == 1
    printed = capsys.readouterr().out
    assert f"::error::the registry answered {status}" in printed
    assert SECRET not in printed
    assert BEARER not in printed
    assert run.calls == []
    assert not (tmp_path / "runner" / hook_check.WORK_NAME).exists()


def test_main_removes_the_exe_when_the_selftest_fails(repo, tmp_path, capsys):
    run = FakeRun(returncode=1)
    assert hook_check.main(make_env(tmp_path), FakeRegistry(Image()), run, lambda seconds: None) == 1
    assert "::error::livemap_selftest exited with 1" in capsys.readouterr().out
    assert not (tmp_path / "runner" / hook_check.WORK_NAME).exists()


def test_main_fails_the_check_and_removes_the_exe_when_the_compat_check_fails(repo, tmp_path, capsys):
    run = FakeRun(returncode=3, stdout=FAILED_COMPAT_OUTPUT, only="compat")
    assert hook_check.main(make_env(tmp_path), FakeRegistry(Image()), run, lambda seconds: None) == 1
    printed = capsys.readouterr().out
    assert "movement: a problem" in printed
    assert "::error::livemap_compat check exited with 3" in printed
    assert not (tmp_path / "runner" / hook_check.WORK_NAME).exists()


def test_main_fails_the_check_when_a_build_has_no_exe_or_pin(repo, tmp_path, capsys):
    path = repo / "data" / "builds.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["builds"].append(make_row("draft", ["12"], None))
    path.write_text(json.dumps(doc), encoding="utf-8")
    run = FakeRun()
    assert hook_check.main(make_env(tmp_path), FakeRegistry(Image()), run, lambda seconds: None) == 1
    assert "::error::" in capsys.readouterr().out
    assert run.calls == []


def test_main_starts_from_an_empty_work_dir(repo, tmp_path):
    work = tmp_path / "runner" / hook_check.WORK_NAME
    (work / "stale").mkdir(parents=True)
    run = FakeRun()
    seen_stale = []
    original = run.__call__

    def spy(command, **kwargs):
        seen_stale.append((work / "stale").exists())
        return original(command, **kwargs)

    assert hook_check.main(make_env(tmp_path), FakeRegistry(Image()), spy, lambda seconds: None) == 0
    assert seen_stale == [False, False]


def test_the_workflow_cleanup_step_deletes_the_directory_the_check_writes_to():
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci-repo.yaml").read_text(
        encoding="utf-8"
    )
    cleanup = workflow.split("name: Delete the server executable", 1)[1]
    assert f'"{hook_check.WORK_NAME}"' in cleanup
