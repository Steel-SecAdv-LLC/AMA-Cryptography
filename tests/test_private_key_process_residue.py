#!/usr/bin/env python3
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
"""A private-key export leaves no copy of the key in the process, freed or live.

A child process exports a key through every encoding; the parent reads the
child's memory from ``/proc/<pid>/mem`` and counts 12-octet windows of the key
and of its Base64 and Base64url text.  The count after the exports must equal
the count with the key live, and be zero once the key is dropped.  A
differential, not an allocator claim.  Positive controls show the scan sees a
live and a freed unwiped copy.  Skips only where the platform cannot read a
child's memory (not Linux or CPython).
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from typing import Iterator

import pytest

import ama_cryptography.pqc_backends as pb

REPO = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(pb._native_lib is None, reason="native library not built")

#: The child.  Prints a tag at each sync point and waits for a byte on stdin;
#: the key octets it wants found go to the parent through an inherited pipe as
#: ``memoryview`` slices, never as ``bytes``.  Offsets: three 12-octet windows
#: (8, 14 and 20 octets into the secret region) of the key and of the seed.
CHILD = textwrap.dedent("""
    import gc
    import os
    import sys

    import ama_cryptography.key_formats as kf
    import ama_cryptography.pqc_backends as pb

    alg, ops = sys.argv[1], sys.argv[2].split(",")
    WINDOWS = (8, 14, 20)


    def rnd(n):
        out = bytearray(n)
        with open("/dev/urandom", "rb", buffering=0) as source:
            source.readinto(out)
        return out


    def make_private(name):
        a = kf.ALGORITHMS[name]
        if a.kind == "pq":
            seed = rnd(a.pq_seed_bytes)
            if a.pq_family == "ml-dsa":
                public, secret = pb.native_ml_dsa_keypair_from_seed(a.pq_param_set, seed)
            else:
                d, z = seed[:32], seed[32:]
                public, secret = pb.native_ml_kem_keypair_from_seed(a.pq_param_set, d, z)
                for i in range(32):
                    d[i] = 0
                    z[i] = 0
                del d, z
            return kf.PrivateKey(name, secret, public, seed)
        n = a.private_bytes if a.kind == "okp" else a.field_bytes
        secret = rnd(n)
        if a.kind == "ec":
            secret[0] &= 0x7F if a.field_bytes != 66 else 0
            secret[1] |= 1
        key = kf.PrivateKey(name, secret, None)
        key.public()
        return key


    # The protocol must not allocate while a freed block is waiting to be
    # scanned: `os.read(0, 1)` allocates a one-octet `bytes`, which lands in
    # the same size class as a freed 32-octet `bytearray` and is handed that
    # very block, hiding it from the scan.  Tags are
    # encoded and the read buffer made before anything is exported.
    TAGS = {name: (name + "\\n").encode() for name in ops + ["live", "dropped"]}
    WAIT = [bytearray(1)]


    def sync(tag):
        os.write(1, TAGS[tag])
        os.readv(0, WAIT)


    key = make_private(alg)
    family = kf.ALGORITHMS[alg].pq_family or ""
    base = {"ml-dsa": 128, "ml-kem": 64}.get(family, 0)
    fd = int(os.environ["NEEDLE_FD"])
    for at in WINDOWS:
        os.write(fd, memoryview(key.key)[base + at : base + at + 12])
    if key.seed is not None:
        for at in WINDOWS:
            os.write(fd, memoryview(key.seed)[at : at + 12])
    os.close(fd)
    gc.collect()
    sync("live")

    for op in ops:
        if op == "control_live":
            kept = bytes(key.key)  # an immutable copy, kept alive
        elif op == "control_freed":
            spare = [bytearray(key.key) for _ in range(64)]  # unwiped, then freed
            del spare
        elif op.startswith("to_pkcs8:") or op.startswith("to_pem:"):
            method, arm = op.split(":")
            out = getattr(key, method)(pq_format=arm)
            del out
        else:
            out = getattr(key, op)()
            del out
        gc.collect()
        sync(op)

    del key
    gc.collect()
    sync("dropped")
""")

MAPS = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S{4}) ")


def _readable_regions(pid: int) -> Iterator[tuple[int, int]]:
    with open(f"/proc/{pid}/maps", encoding="ascii") as maps:
        for line in maps:
            match = MAPS.match(line)
            if match is None or match[3][:2] != "rw":
                continue
            if "[vvar" in line or "[vsyscall]" in line:
                continue
            yield int(match[1], 16), int(match[2], 16)


def _scan(pid: int, needles: dict[str, bytes]) -> dict[str, int]:
    """How many times each needle occurs in the writable memory of ``pid``."""
    counts = dict.fromkeys(needles, 0)
    longest = max(len(n) for n in needles.values())
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for low, high in _readable_regions(pid):
            position, tail = low, b""
            while position < high:
                size = min(1 << 22, high - position)
                try:
                    mem.seek(position)
                    chunk = mem.read(size)
                except (OSError, OverflowError, ValueError):
                    break
                if not chunk:
                    break
                buffer = tail + chunk
                for name, needle in needles.items():
                    at = buffer.find(needle)
                    while at != -1:
                        counts[name] += 1
                        at = buffer.find(needle, at + 1)
                tail = buffer[-(longest - 1) :]
                position += size
    return counts


def _needles(octets: bytes, label: str, windows: int) -> dict[str, bytes]:
    """The raw 12-octet windows and, for each, the Base64 and Base64url text of
    the nine octets that start on a 3-octet boundary at each of the three
    alignments (whatever offset the secret sits at in an encoded stream, one
    of the three is a whole number of Base64 groups)."""
    found: dict[str, bytes] = {}
    for index in range(windows):
        window = octets[index * 12 : index * 12 + 12]
        found[f"{label}{index}:raw"] = window
        for alignment in range(3):
            part = window[alignment : alignment + 9]
            standard, url = base64.b64encode(part), base64.urlsafe_b64encode(part)
            found[f"{label}{index}:b64/{alignment}"] = standard
            if url != standard:
                found[f"{label}{index}:b64u/{alignment}"] = url
    return found


class Run:
    """One child process, stepped through its sync points by the parent."""

    def __init__(self, tmp_path: Path, algorithm: str, ops: list[str]) -> None:
        script = tmp_path / "child.py"
        script.write_text(CHILD, encoding="utf-8")
        read_fd, write_fd = os.pipe()
        env = dict(os.environ, PYTHONPATH=str(REPO), NEEDLE_FD=str(write_fd))
        self.process = subprocess.Popen(
            [sys.executable, str(script), algorithm, ",".join(ops)],
            cwd=str(REPO),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(write_fd,),
        )
        os.close(write_fd)
        # A child that hangs (a deadlocked import) must not hang the suite.
        self._watchdog = threading.Timer(300, self.process.kill)
        self._watchdog.start()
        assert self.process.stdout is not None
        self.tags = [self.process.stdout.readline().decode().strip()]
        # The child wrote its needles before it printed its first tag, so they
        # are all in the pipe.
        raw = b""
        os.set_blocking(read_fd, False)
        try:
            while True:
                try:
                    piece = os.read(read_fd, 4096)
                except BlockingIOError:
                    break
                if not piece:
                    break
                raw += piece
        finally:
            os.close(read_fd)
        seeded = len(raw) == 72
        assert len(raw) in (
            36,
            72,
        ), f"the child sent {len(raw)} needle octets; stderr: {self.stderr()}"
        self.needles = _needles(raw[:36], "key", 3)
        if seeded:
            self.needles.update(_needles(raw[36:72], "seed", 3))
        self.position = 0

    def stderr(self) -> str:
        if self.process.poll() is None:
            return "(still running)"
        assert self.process.stderr is not None
        raw: bytes = self.process.stderr.read()
        return raw.decode(errors="replace")[-500:]

    def step(self) -> tuple[str, dict[str, int]]:
        """Scan at the current sync point, release the child to the next, and
        return ``(tag, counts)`` for the point scanned."""
        counts = _scan(self.process.pid, self.needles)
        tag = self.tags[self.position]
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(b"x")
        self.process.stdin.flush()
        self.tags.append(self.process.stdout.readline().decode().strip())
        self.position += 1
        return tag, counts

    def finish(self) -> int:
        self._watchdog.cancel()
        try:
            for pipe in (self.process.stdin, self.process.stdout):
                if pipe is not None:
                    pipe.close()
            code = self.process.wait(timeout=60)
            assert code == 0, self.stderr()
        finally:
            if self.process.stderr is not None:
                self.process.stderr.close()
        return code


@pytest.fixture(scope="module")
def scan_works() -> None:
    """Skip, once, with the reason, on a platform that cannot read a child's
    memory.  Nothing here is skipped for any other cause: a platform that can
    read it must pass the controls."""
    if not sys.platform.startswith("linux"):
        pytest.skip("reading another process's memory is done through /proc, Linux only")
    if sys.implementation.name != "cpython":
        pytest.skip("the scan reasons about CPython's allocator, not this implementation's")
    probe = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        regions = list(_readable_regions(probe.pid))
        if not regions:
            pytest.skip("/proc/<pid>/maps of a child lists no writable region")
        with open(f"/proc/{probe.pid}/mem", "rb", 0) as mem:
            mem.seek(regions[0][0])
            mem.read(16)
    except (OSError, ValueError) as exc:
        pytest.skip(f"cannot read a child's memory through /proc/<pid>/mem: {exc}")
    finally:
        probe.kill()
        probe.wait()
        if probe.stdin is not None:
            probe.stdin.close()


def _run_all(tmp_path: Path, algorithm: str, ops: list[str]) -> list[tuple[str, dict[str, int]]]:
    """Scan the child with the key live, after each op, and after the key is dropped."""
    run = Run(tmp_path, algorithm, ops)
    steps = [run.step() for _ in range(len(ops) + 2)]
    run.finish()
    return steps


def _grown(baseline: dict[str, int], counts: dict[str, int]) -> dict[str, tuple[int, int]]:
    return {k: (baseline[k], v) for k, v in counts.items() if v != baseline[k]}


def _raw(counts: dict[str, int]) -> int:
    return sum(v for k, v in counts.items() if k.endswith(":raw"))


CLASSICAL_OPS = ["to_pkcs8", "to_pem", "to_jwk", "to_cose"]
PQ_OPS = [
    "to_pkcs8:seed",
    "to_pkcs8:both",
    "to_pkcs8:expandedKey",
    "to_pem:seed",
    "to_pem:both",
    "to_pem:expandedKey",
]
CASES = [
    ("Ed25519", CLASSICAL_OPS),
    ("P-256", CLASSICAL_OPS),
    ("ML-DSA-65", PQ_OPS),
    ("ML-KEM-1024", PQ_OPS),
]


@pytest.mark.usefixtures("scan_works")
def test_the_scan_sees_a_live_copy_and_a_freed_unwiped_copy(tmp_path: Path) -> None:
    """Positive control.  A kept ``bytes`` copy of the key, and sixty-four freed
    unwiped ``bytearray`` copies of it (the leak a mutable copy leaves: freed
    memory is not zeroed), each raise the raw count over what it was.  Without
    this, a scan that read nothing would pass every export."""
    steps = _run_all(tmp_path, "P-256", ["control_live", "control_freed"])
    (_, baseline), (_, live), (_, freed), _dropped = steps
    assert _raw(baseline) >= 3, f"the key's own buffer was not found: {baseline}"
    assert _raw(live) - _raw(baseline) >= 3, _grown(baseline, live)
    assert _raw(freed) - _raw(live) >= 3 * 32, _grown(live, freed)


@pytest.mark.usefixtures("scan_works")
@pytest.mark.parametrize(("algorithm", "ops"), CASES, ids=[c[0] for c in CASES])
def test_exporting_a_key_leaves_no_copy_in_the_process(
    tmp_path: Path, algorithm: str, ops: list[str]
) -> None:
    """PIN.  After every encoding is made and dropped no count has grown over
    the live-key baseline (key, seed, their Base64 and Base64url text), and every
    count is zero once the key is dropped."""
    steps = _run_all(tmp_path, algorithm, ops)
    baseline = steps[0][1]
    assert _raw(baseline) >= 3, f"the key's own buffer was not found: {baseline}"
    for tag, counts in steps[1:-1]:
        assert _grown(baseline, counts) == {}, (algorithm, tag)
    tag, counts = steps[-1]
    assert tag == "dropped", steps[-1][0]
    assert {k: v for k, v in counts.items() if v} == {}, (algorithm, "after the key was dropped")
