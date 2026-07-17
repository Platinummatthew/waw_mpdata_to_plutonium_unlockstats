#!/usr/bin/env python3
r"""Convert World at War PC multiplayer MPData to Plutonium T4 ``unlockstats_mp``.

Supported input forms:

    0x211c bytes  retail encrypted ``iwm0`` mpdata container
    0x211c bytes  plaintext ``ice0`` container
    0x2104 bytes  decrypted payload (fs_game path + player stats)
    0x2000 bytes  raw player stats / playerstats.txt / unlockstats_mp

The 0x2000-byte player-stat block is preserved byte-for-byte whenever its inner
CRC-32 is valid. Encrypted ``iwm0`` input is decrypted and authenticated with the
original World at War CD key before extraction. Existing inspection and editing
commands remain available for raw Plutonium ``unlockstats_mp`` files.

Current Plutonium import target (July 2026):
``%LOCALAPPDATA%\Plutonium\storage\t4\plutonium\unlockstats_mp``.

IWM encryption/decryption support is a Python reimplementation based on
codmpdatadec, Copyright (C) 2009 Luigi Auriemma. Modified implementation,
July 2026.

SPDX-License-Identifier: GPL-2.0-or-later
"""

from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import hmac
import os
import re
import shutil
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

FILE_SIZE = 0x2000
CHECKSUM_OFFSET = 0x0000
BODY_OFFSET = 0x0004
BYTE_STATS_COUNT = 2000
BYTE_STATS_OFFSET = BODY_OFFSET
DWORD_STATS_COUNT = 1498
DWORD_STATS_OFFSET = BYTE_STATS_OFFSET + BYTE_STATS_COUNT  # 0x07d4
TAIL_OFFSET = DWORD_STATS_OFFSET + DWORD_STATS_COUNT * 4    # 0x1f3c
TAIL_SIZE = FILE_SIZE - TAIL_OFFSET                          # 196
MAX_STAT_INDEX = BYTE_STATS_COUNT + DWORD_STATS_COUNT - 1   # 3497

# Retail mpdata / IWM container layout.
IWM_CONTAINER_SIZE = 0x211C
IWM_PAYLOAD_SIZE = 0x2104
IWM_SIGNATURE_OFFSET = 0x0000
IWM_SEED_OFFSET = 0x0004
IWM_CRYPT_OFFSET = 0x0008
IWM_DATA_OFFSET = 0x0018
IWM_FS_GAME_SIZE = 0x0104
IWM_STATS_OFFSET = IWM_DATA_OFFSET + IWM_FS_GAME_SIZE  # 0x011c
IWM_PAYLOAD_STATS_OFFSET = IWM_FS_GAME_SIZE           # 0x0104
IWM_CRYPT_WORDS = 0x845
IWM_CRYPT_SIZE = IWM_CRYPT_WORDS * 4                  # 0x2114
MASK32 = 0xFFFFFFFF

CURRENT_OUTPUT_NAME = "unlockstats_mp"
PLUTONIUM_RELATIVE_TARGET = Path("Plutonium") / "storage" / "t4" / "plutonium" / CURRENT_OUTPUT_NAME
SOURCE_PRIMARY_NAMES = ("mpdata",)
SOURCE_BACKUP_NAMES = ("mpdatabk0000",)


class UnlockStatsError(Exception):
    """A user-facing unlockstats_mp error."""



@dataclass
class ImportResult:
    stats: bytearray
    source_format: str
    source_size: int
    source_encoding: str = "binary"
    outer_authenticated: bool | None = None
    key_description: str | None = None
    fs_game_path: str = ""
    inner_crc_stored: int = 0
    inner_crc_calculated: int = 0

    @property
    def inner_crc_valid(self) -> bool:
        return self.inner_crc_stored == self.inner_crc_calculated


@dataclass
class SourceData:
    requested_path: Path
    selected_name: str
    data: bytes
    source_encoding: str
    on_disk_size: int

    @property
    def display_name(self) -> str:
        return self.selected_name


# Pure-Python MD4. This keeps the converter dependency-free and allows it to run
# on Python/OpenSSL builds where MD4 is disabled.
def _rol32(value: int, count: int) -> int:
    value &= MASK32
    return ((value << count) | (value >> (32 - count))) & MASK32


def md4(data: bytes | bytearray | memoryview) -> bytes:
    message = bytearray(data)
    bit_length = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += struct.pack("<Q", bit_length)

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | ((~x) & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    for block_offset in range(0, len(message), 64):
        x = list(struct.unpack_from("<16I", message, block_offset))
        a, b, c, d = a0, b0, c0, d0

        # Round 1.
        shifts = (3, 7, 11, 19)
        for i in range(16):
            k = i
            value = (a + f(b, c, d) + x[k]) & MASK32
            a, b, c, d = d, _rol32(value, shifts[i & 3]), b, c

        # Round 2.
        shifts = (3, 5, 9, 13)
        order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for i, k in enumerate(order):
            value = (a + g(b, c, d) + x[k] + 0x5A827999) & MASK32
            a, b, c, d = d, _rol32(value, shifts[i & 3]), b, c

        # Round 3.
        shifts = (3, 9, 11, 15)
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i, k in enumerate(order):
            value = (a + h(b, c, d) + x[k] + 0x6ED9EBA1) & MASK32
            a, b, c, d = d, _rol32(value, shifts[i & 3]), b, c

        a0 = (a0 + a) & MASK32
        b0 = (b0 + b) & MASK32
        c0 = (c0 + c) & MASK32
        d0 = (d0 + d) & MASK32

    return struct.pack("<4I", a0, b0, c0, d0)


def _iwm_hash(prefix: bytes, data: bytes | bytearray) -> bytes:
    return md4(prefix + bytes(data))


def _prepare_codkey_buffer(cd_key: str) -> bytes:
    """Emulate the 34-byte key buffer used by CoD4/CoD5 LiveStorage."""
    try:
        encoded = cd_key.encode("ascii")
    except UnicodeEncodeError as exc:
        raise UnlockStatsError("The CD key must contain ASCII characters only.") from exc

    buf = bytearray(b" " * 32 + b"\x00\x00")
    if len(encoded) < 34:
        buf[:len(encoded)] = encoded
        buf[len(encoded)] = 0
    else:
        buf[:34] = encoded[:34]
    if len(encoded) > 16:  # World at War branch in the original implementation.
        buf[22] = 0
    return bytes(buf)


def derive_iwm_key(cd_key: str, seed: int) -> tuple[int, int, int, int]:
    cod_seed = struct.pack("<I", 0x1F93AB07)
    first = _iwm_hash(cod_seed, _prepare_codkey_buffer(cd_key))
    inner = bytes(value ^ 0x36 for value in first)
    outer = bytes(value ^ 0x5C for value in first)
    intermediate = _iwm_hash(inner, struct.pack("<I", seed & MASK32))
    key_bytes = _iwm_hash(outer, intermediate)
    return struct.unpack("<4I", key_bytes)


def _iwm_mx_decrypt(previous: int, current: int, delta: int, key_word: int) -> int:
    left = (((previous >> 5) ^ ((current << 2) & MASK32)) +
            (((previous << 4) & MASK32) ^ (current >> 3))) & MASK32
    right = ((key_word ^ previous) + (delta ^ current)) & MASK32
    return (left ^ right) & MASK32


def _iwm_mx_encrypt(previous: int, following: int, delta: int, key_word: int) -> int:
    left = (((previous >> 5) ^ ((following << 2) & MASK32)) +
            (((previous << 4) & MASK32) ^ (following >> 3))) & MASK32
    right = ((key_word ^ previous) + (delta ^ following)) & MASK32
    return (left ^ right) & MASK32


def decrypt_iwm_words(ciphertext: bytes | bytearray, key: Sequence[int]) -> bytes:
    if len(ciphertext) != IWM_CRYPT_SIZE:
        raise UnlockStatsError(
            f"Invalid encrypted block size: expected 0x{IWM_CRYPT_SIZE:x}, got 0x{len(ciphertext):x}"
        )
    words = list(struct.unpack(f"<{IWM_CRYPT_WORDS}I", ciphertext))
    delta = 0xB54CDA56
    last = IWM_CRYPT_WORDS - 1
    while True:
        current = words[0]
        for i in range(last, 0, -1):
            previous = words[i - 1]
            key_word = key[(i ^ (delta >> 2)) & 3]
            words[i] = (words[i] - _iwm_mx_decrypt(previous, current, delta, key_word)) & MASK32
            current = words[i]
        previous = words[last]
        key_word = key[(delta >> 2) & 3]
        words[0] = (words[0] - _iwm_mx_decrypt(previous, current, delta, key_word)) & MASK32
        delta = (delta + 0x61C88647) & MASK32
        if delta == 0:
            break
    return struct.pack(f"<{IWM_CRYPT_WORDS}I", *words)


def encrypt_iwm_words(plaintext: bytes | bytearray, key: Sequence[int]) -> bytes:
    """Inverse operation used by self-tests and test-vector generation."""
    if len(plaintext) != IWM_CRYPT_SIZE:
        raise UnlockStatsError(
            f"Invalid plaintext block size: expected 0x{IWM_CRYPT_SIZE:x}, got 0x{len(plaintext):x}"
        )
    words = list(struct.unpack(f"<{IWM_CRYPT_WORDS}I", plaintext))
    delta = 0
    last = IWM_CRYPT_WORDS - 1
    for _ in range(6):
        delta = (delta - 0x61C88647) & MASK32
        previous = words[last]
        for i in range(0, last):
            following = words[i + 1]
            key_word = key[(i ^ (delta >> 2)) & 3]
            words[i] = (words[i] + _iwm_mx_encrypt(previous, following, delta, key_word)) & MASK32
            previous = words[i]
        following = words[0]
        key_word = key[(last ^ (delta >> 2)) & 3]
        words[last] = (words[last] + _iwm_mx_encrypt(previous, following, delta, key_word)) & MASK32
    return struct.pack(f"<{IWM_CRYPT_WORDS}I", *words)


def key_variants(value: str) -> list[tuple[str, str]]:
    raw = value.strip()
    candidates = [
        ("as entered", raw),
        ("uppercase", raw.upper()),
        ("alphanumeric", "".join(ch for ch in raw if ch.isalnum())),
        ("alphanumeric uppercase", "".join(ch for ch in raw.upper() if ch.isalnum())),
    ]
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for description, candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            result.append((description, candidate))
    return result


def _safe_fs_game_path(raw: bytes | bytearray) -> str:
    text = bytes(raw).split(b"\x00", 1)[0]
    return "".join(chr(value) if 32 <= value <= 126 else "?" for value in text)


def _stats_result(
    stats: bytes | bytearray,
    *,
    source_format: str,
    source_size: int,
    source_encoding: str = "binary",
    outer_authenticated: bool | None = None,
    key_description: str | None = None,
    fs_game_path: str = "",
) -> ImportResult:
    if len(stats) != FILE_SIZE:
        raise UnlockStatsError(f"Internal extraction error: expected 0x2000 stats bytes, got 0x{len(stats):x}")
    stats_copy = bytearray(stats)
    return ImportResult(
        stats=stats_copy,
        source_format=source_format,
        source_size=source_size,
        source_encoding=source_encoding,
        outer_authenticated=outer_authenticated,
        key_description=key_description,
        fs_game_path=fs_game_path,
        inner_crc_stored=stored_crc(stats_copy),
        inner_crc_calculated=calculated_crc(stats_copy),
    )


def decrypt_iwm0_container(
    data: bytes | bytearray,
    cd_key: str,
    *,
    key_description: str = "supplied CD key",
    source_encoding: str = "binary",
) -> ImportResult:
    if len(data) != IWM_CONTAINER_SIZE or bytes(data[:4]) != b"iwm0":
        raise UnlockStatsError("Input is not an encrypted 0x211c-byte iwm0 container.")
    seed = struct.unpack_from("<I", data, IWM_SEED_OFFSET)[0]
    failures: list[str] = []
    for variant_description, variant in key_variants(cd_key):
        key = derive_iwm_key(variant, seed)
        decrypted_tail = decrypt_iwm_words(data[IWM_CRYPT_OFFSET:], key)
        plain = bytearray(data)
        plain[IWM_CRYPT_OFFSET:] = decrypted_tail
        decrypted_hash = bytes(plain[IWM_CRYPT_OFFSET:IWM_DATA_OFFSET])
        payload = bytes(plain[IWM_DATA_OFFSET:])
        auth_salt = ((key[2] + 0x928D764C) & MASK32) ^ seed
        expected_hash = _iwm_hash(struct.pack("<I", auth_salt), payload)
        if not hmac.compare_digest(decrypted_hash, expected_hash):
            failures.append(variant_description)
            continue
        return _stats_result(
            plain[IWM_STATS_OFFSET:],
            source_format="retail encrypted iwm0 mpdata",
            source_size=len(data),
            source_encoding=source_encoding,
            outer_authenticated=True,
            key_description=f"{key_description}; {variant_description}",
            fs_game_path=_safe_fs_game_path(plain[IWM_DATA_OFFSET:IWM_STATS_OFFSET]),
        )
    tried = ", ".join(failures) if failures else "no usable key variants"
    raise UnlockStatsError(
        "The mpdata authentication hash did not match. The CD key is wrong for this file "
        f"or the file is damaged (tried: {tried})."
    )


def build_iwm0_container(stats: bytes | bytearray, cd_key: str, *, seed: int, fs_game_path: str = "") -> bytes:
    """Build a deterministic encrypted test container; not exposed as a CLI command."""
    if len(stats) != FILE_SIZE:
        raise UnlockStatsError("A test container requires exactly 0x2000 stats bytes.")
    plain = bytearray(IWM_CONTAINER_SIZE)
    plain[:4] = b"iwm0"
    struct.pack_into("<I", plain, IWM_SEED_OFFSET, seed & MASK32)
    path_bytes = fs_game_path.encode("utf-8", "replace")[:IWM_FS_GAME_SIZE - 1]
    plain[IWM_DATA_OFFSET:IWM_DATA_OFFSET + len(path_bytes)] = path_bytes
    plain[IWM_STATS_OFFSET:] = stats
    normalized = key_variants(cd_key)[-1][1]
    key = derive_iwm_key(normalized, seed)
    payload = bytes(plain[IWM_DATA_OFFSET:])
    auth_salt = ((key[2] + 0x928D764C) & MASK32) ^ (seed & MASK32)
    plain[IWM_CRYPT_OFFSET:IWM_DATA_OFFSET] = _iwm_hash(struct.pack("<I", auth_salt), payload)
    plain[IWM_CRYPT_OFFSET:] = encrypt_iwm_words(plain[IWM_CRYPT_OFFSET:], key)
    return bytes(plain)


def _decode_hex_wrapped_input(data: bytes) -> tuple[bytes, str]:
    if len(data) in (FILE_SIZE, IWM_PAYLOAD_SIZE, IWM_CONTAINER_SIZE):
        return data, "binary"
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data, "binary"
    compact = re.sub(r"\s+", "", text)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if len(compact) % 2 or not compact or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return data, "binary"
    decoded = bytes.fromhex(compact)
    if len(decoded) in (FILE_SIZE, IWM_PAYLOAD_SIZE, IWM_CONTAINER_SIZE):
        return decoded, "ASCII hexadecimal"
    return data, "binary"


def read_source_bytes(path: Path) -> tuple[bytes, str]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UnlockStatsError(f"Could not read {path}: {exc}") from exc
    return _decode_hex_wrapped_input(raw)


def _candidate_priority(name: str) -> int | None:
    lowered = Path(name).name.lower()
    if lowered in SOURCE_PRIMARY_NAMES:
        return 0
    if lowered in SOURCE_BACKUP_NAMES:
        return 1
    if lowered in (CURRENT_OUTPUT_NAME, "unlockstats", "playerstats.txt"):
        return 2
    if lowered.endswith(".corrupt") or lowered == "mpdata.corrupt":
        return 3
    return None


def _select_candidate(names: Sequence[str], container_label: str) -> str:
    ranked: dict[int, list[str]] = {}
    for name in names:
        priority = _candidate_priority(name)
        if priority is not None:
            ranked.setdefault(priority, []).append(name)
    for priority in sorted(ranked):
        candidates = sorted(ranked[priority], key=lambda value: (len(Path(value).parts), value.lower()))
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            preview = "\n  ".join(candidates[:20])
            more = "" if len(candidates) <= 20 else f"\n  ... and {len(candidates) - 20} more"
            raise UnlockStatsError(
                f"More than one equally preferred multiplayer source was found in {container_label}:\n  "
                f"{preview}{more}\nSelect the exact mpdata file instead."
            )
    raise UnlockStatsError(
        f"No mpdata, mpdatabk0000, .corrupt MPData, {CURRENT_OUTPUT_NAME}, or playerstats.txt "
        f"was found in {container_label}."
    )


def load_source(value: str | Path) -> SourceData:
    requested = Path(value).expanduser()
    if requested.is_dir():
        files = [str(item.relative_to(requested)) for item in requested.rglob("*") if item.is_file()]
        selected_rel = _select_candidate(files, str(requested))
        selected = requested / selected_rel
        data, encoding = read_source_bytes(selected)
        return SourceData(requested, str(selected), data, encoding, selected.stat().st_size)

    if not requested.exists():
        raise UnlockStatsError(f"Input does not exist: {requested}")

    if requested.is_file() and requested.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(requested, "r") as archive:
                names = [info.filename for info in archive.infolist() if not info.is_dir()]
                selected_name = _select_candidate(names, str(requested))
                raw = archive.read(selected_name)
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            raise UnlockStatsError(f"Could not read ZIP archive {requested}: {exc}") from exc
        data, encoding = _decode_hex_wrapped_input(raw)
        return SourceData(requested, f"{requested}!{selected_name}", data, encoding, len(raw))

    data, encoding = read_source_bytes(requested)
    return SourceData(requested, str(requested), data, encoding, requested.stat().st_size)


def default_output_path(requested: Path) -> Path:
    if requested.is_dir():
        return requested / CURRENT_OUTPUT_NAME
    return requested.with_name(CURRENT_OUTPUT_NAME)


def default_plutonium_target() -> Path:
    override = os.environ.get("PLUTONIUM_T4_DIR", "").strip()
    if override:
        return Path(override).expanduser() / "plutonium" / CURRENT_OUTPUT_NAME
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if not local_app_data:
        raise UnlockStatsError(
            "LOCALAPPDATA is unavailable. Supply --target explicitly, or set PLUTONIUM_T4_DIR "
            "to the Plutonium storage\\t4 directory."
        )
    return Path(local_app_data) / PLUTONIUM_RELATIVE_TARGET


def identify_source(data: bytes | bytearray) -> str:
    size = len(data)
    if size == FILE_SIZE:
        return "raw 0x2000 player stats / unlockstats_mp"
    if size == IWM_PAYLOAD_SIZE:
        return "decrypted 0x2104 payload"
    if size == IWM_CONTAINER_SIZE:
        signature = bytes(data[:4])
        if signature == b"iwm0":
            return "retail encrypted iwm0 mpdata"
        if signature == b"ice0":
            return "plaintext ice0 container"
        return f"unknown 0x211c container (signature {signature!r})"
    return f"unknown size 0x{size:x} ({size} bytes)"


def extract_plain_source(data: bytes | bytearray, *, source_encoding: str = "binary") -> ImportResult:
    size = len(data)
    if size == FILE_SIZE:
        return _stats_result(
            data,
            source_format="raw player stats / playerstats.txt / unlockstats_mp",
            source_size=size,
            source_encoding=source_encoding,
        )
    if size == IWM_PAYLOAD_SIZE:
        return _stats_result(
            data[IWM_PAYLOAD_STATS_OFFSET:],
            source_format="decrypted 0x2104 mpdata payload",
            source_size=size,
            source_encoding=source_encoding,
            fs_game_path=_safe_fs_game_path(data[:IWM_PAYLOAD_STATS_OFFSET]),
        )
    if size == IWM_CONTAINER_SIZE and bytes(data[:4]) == b"ice0":
        return _stats_result(
            data[IWM_STATS_OFFSET:],
            source_format="plaintext ice0 mpdata container",
            source_size=size,
            source_encoding=source_encoding,
            outer_authenticated=None,
            fs_game_path=_safe_fs_game_path(data[IWM_DATA_OFFSET:IWM_STATS_OFFSET]),
        )
    if size == IWM_CONTAINER_SIZE and bytes(data[:4]) == b"iwm0":
        raise UnlockStatsError("This is encrypted iwm0 mpdata and requires its original World at War CD key.")
    raise UnlockStatsError(
        "Unsupported input. Expected 0x211c encrypted/plain mpdata, 0x2104 decrypted payload, "
        "or 0x2000 raw player stats."
    )


def registry_cd_keys() -> list[tuple[str, str]]:
    if os.name != "nt":
        return []
    try:
        import winreg  # type: ignore
    except ImportError:
        return []
    paths = [
        r"SOFTWARE\Activision\Call of Duty WAW",
        r"SOFTWARE\WOW6432Node\Activision\Call of Duty WAW",
        r"SOFTWARE\Activision\CODWAWbeta",
        r"SOFTWARE\WOW6432Node\Activision\CODWAWbeta",
    ]
    hives = [("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)]
    views = [0]
    for name in ("KEY_WOW64_32KEY", "KEY_WOW64_64KEY"):
        value = getattr(winreg, name, 0)
        if value and value not in views:
            views.append(value)
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for hive_name, hive in hives:
        for path in paths:
            for view in views:
                try:
                    with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as handle:
                        value, _ = winreg.QueryValueEx(handle, "codkey")
                except OSError:
                    continue
                if isinstance(value, bytes):
                    value = value.decode("ascii", "ignore")
                if isinstance(value, str) and value.strip() and value not in seen:
                    seen.add(value)
                    found.append((f"Windows registry {hive_name}\\{path}", value))
    return found


def collect_key_candidates(args: argparse.Namespace) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    if getattr(args, "cd_key", None):
        candidates.append(("--cd-key", args.cd_key))
    if getattr(args, "key_file", None):
        key_path = Path(args.key_file)
        try:
            key_text = key_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise UnlockStatsError(f"Could not read CD key file {key_path}: {exc}") from exc
        if key_text:
            candidates.append((f"key file {key_path}", key_text.splitlines()[0].strip()))
    env_key = os.environ.get("WAW_CD_KEY", "").strip()
    if env_key:
        candidates.append(("WAW_CD_KEY environment variable", env_key))
    if not getattr(args, "no_registry", False):
        candidates.extend(registry_cd_keys())
    deduped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for description, key in candidates:
        if key not in seen:
            seen.add(key)
            deduped.append((description, key))
    return deduped


def extract_with_available_keys(
    data: bytes,
    source_encoding: str,
    args: argparse.Namespace,
    *,
    prompt_if_needed: bool,
) -> ImportResult:
    if not (len(data) == IWM_CONTAINER_SIZE and data[:4] == b"iwm0"):
        return extract_plain_source(data, source_encoding=source_encoding)

    errors: list[str] = []
    for description, key in collect_key_candidates(args):
        try:
            return decrypt_iwm0_container(
                data,
                key,
                key_description=description,
                source_encoding=source_encoding,
            )
        except UnlockStatsError as exc:
            errors.append(str(exc))

    if prompt_if_needed and sys.stdin.isatty():
        key = getpass.getpass("World at War CD key (input hidden): ").strip()
        if key:
            return decrypt_iwm0_container(
                data,
                key,
                key_description="interactive prompt",
                source_encoding=source_encoding,
            )

    detail = ""
    if errors:
        detail = " None of the supplied/registry keys authenticated the file."
    raise UnlockStatsError(
        "Encrypted iwm0 mpdata requires the original World at War CD key. "
        "Use --key-file, set WAW_CD_KEY, allow Windows registry lookup, or run interactively."
        + detail
    )


# Names extracted from WaW playerstats table listings and confirmed where possible
# against the public WaW game scripts. Unknown indices remain fully accessible by
# their numeric stat index.
KNOWN_STATS: dict[int, str] = {
    # Script-confirmed byte stats.
    251: "MENU_RANK_CURRENT",
    252: "MENU_RANK_PROMOTION",
    260: "FEATURE_CREATE_A_CLASS",

    # Multiplayer map skip/passed stats.
    2000: "MP_AIRFIELD_SKIP_PASSED",
    2001: "MP_ASYLUM_SKIP_PASSED",
    2002: "MP_CASTLE_SKIP_PASSED",
    2003: "MP_CLIFFSIDE_SKIP_PASSED",
    2004: "MP_COURTYARD_SKIP_PASSED",
    2005: "MP_DOME_SKIP_PASSED",
    2006: "MP_DOWNFALL_SKIP_PASSED",
    2007: "MP_HANGAR_SKIP_PASSED",
    2008: "MP_MAKIN_SKIP_PASSED",
    2009: "MP_OUTSKIRTS_SKIP_PASSED",
    2010: "MP_ROUNDHOUSE_SKIP_PASSED",
    2011: "MP_SEELOW_SKIP_PASSED",
    2012: "MP_UPHEAVAL_SKIP_PASSED",
    2013: "MP_MAKIN_DAY_SKIP_PASSED",
    2014: "MP_SUBWAY_SKIP_PASSED",
    2015: "MP_KNEEDEEP_SKIP_PASSED",
    2016: "MP_NACHTFEUER_SKIP_PASSED",
    2017: "MP_DOCKS_SKIP_PASSED",
    2018: "MP_STALINGRAD_SKIP_PASSED",
    2019: "MP_KWAI_SKIP_PASSED",
    2020: "MP_BGATE_SKIP_PASSED",
    2021: "MP_DRUM_SKIP_PASSED",
    2022: "MP_VODKA_SKIP_PASSED",

    # Campaign and Zombies map flags.
    2032: "MAK_SKIP_PASSED",
    2033: "PEL1_SKIP_PASSED",
    2034: "PEL2_SKIP_PASSED",
    2035: "SEE1_SKIP_PASSED",
    2036: "PEL1A_SKIP_PASSED",
    2037: "PEL1B_SKIP_PASSED",
    2038: "SEE2_SKIP_PASSED",
    2039: "BER1_SKIP_PASSED",
    2040: "BER2_SKIP_PASSED",
    2041: "OKI2_SKIP_PASSED",
    2042: "OKI3_SKIP_PASSED",
    2043: "BER3_SKIP_PASSED",
    2044: "BER3B_SKIP_PASSED",
    2045: "NZ_PROTOTYPE_SKIP_PASSED",
    2046: "NZ_ASYLUM_SKIP_PASSED",
    2047: "NZ_SUMPF_SKIP_PASSED",
    2048: "NZ_FACTORY_SKIP_PASSED",

    # Aggregate Zombies stats.
    2100: "ZOMBIE_KILLS",
    2101: "ZOMBIE_POINTS",
    2102: "ZOMBIE_ROUNDS",
    2103: "ZOMBIE_DOWNS",
    2104: "ZOMBIE_REVIVES",
    2105: "ZOMBIE_PERKS_CONSUMED",
    2106: "ZOMBIE_HEADSHOTS",

    # Core multiplayer stats.
    2300: "VERSION",
    2301: "RANKXP",
    2302: "SCORE",
    2303: "KILLS",
    2304: "KILL_STREAK",
    2305: "DEATHS",
    2306: "DEATH_STREAK",
    2307: "ASSISTS",
    2308: "HEADSHOTS",
    2309: "TEAMKILLS",
    2310: "SUICIDES",
    2311: "TIME_PLAYED_ALLIES",
    2312: "TIME_PLAYED_OPFOR",
    2313: "TIME_PLAYED_OTHER",
    2314: "TIME_PLAYED_TOTAL",
    2315: "KDRATIO",
    2316: "WINS",
    2317: "LOSSES",
    2318: "TIES",
    2319: "WIN_STREAK",
    2320: "CUR_WIN_STREAK",
    2321: "WLRATIO",
    2322: "HITS",
    2323: "MISSES",
    2324: "TOTAL_SHOTS",
    2325: "ACCURACY",
    2326: "PLEVEL",
    2350: "RANK",
    2351: "MINXP",
    2352: "MAXXP",
    2353: "LASTXP",
    2354: "SESSIONBANS",
    2355: "GAMETYPEBAN",
    2356: "BLOB_REV_NUM",
    2357: "TIMEWHENNEXTHOST",
    2358: "BADHOSTCOUNT",
    2359: "KEYARCHIVEFLUSH",
    2360: "LEADERBOARDFAILURES",
    2361: "LASTSTATSBACKUP",
    2362: "STATSBACKUPVERSION",
    2363: "MAPPACKMASK",
}

# Web token/XUID fields.
for _n in range(1, 17):
    KNOWN_STATS[2379 + _n] = f"WEBTOKEN_{_n}"
KNOWN_STATS[2396] = "XUIDPT1"
KNOWN_STATS[2397] = "XUIDPT2"

# Per-mode multiplayer leaderboard groups.
_MODES = [
    "TDM", "DM", "SAB", "SD", "CTF", "DOM", "TWAR", "KOTH",
    "HCTDM", "HCDM", "HCSAB", "HCSD", "HCCTF", "HCDOM", "HCTWAR", "HCKOTH",
]
_MODE_GROUPS = [
    (3200, "KILLS"),
    (3216, "DEATHS"),
    (3232, "KILL_STREAK"),
    (3248, "KDRATIO"),
    (3264, "WINS"),
    (3280, "LOSSES"),
    (3296, "WIN_STREAK"),
    (3312, "WLRATIO"),
    (3328, "SCORE"),
    (3344, "TIME_PLAYED_TOTAL"),
    (3360, "CUR_WIN_STREAK"),
]
for _start, _suffix in _MODE_GROUPS:
    for _offset, _mode in enumerate(_MODES):
        KNOWN_STATS[_start + _offset] = f"{_mode}_{_suffix}"

# Arcade and per-map Zombies leaderboard stats.
_ARCADE_NAMES = [
    "ARCADEMODE_SCORE_MAK",
    "ARCADEMODE_SCORE_PEL1",
    "ARCADEMODE_SCORE_PEL2",
    "ARCADEMODE_SCORE_SEE1",
    "ARCADEMODE_SCORE_PEL1A",
    "ARCADEMODE_SCORE_PEL1B",
    "ARCADEMODE_SCORE_SEE2",
    "ARCADEMODE_SCORE_BER1",
    "ARCADEMODE_SCORE_BER2",
    "ARCADEMODE_SCORE_OKI2",
    "ARCADEMODE_SCORE_OKI3",
    "ARCADEMODE_SCORE_BER3",
    "ARCADEMODE_SCORE_BER3B",
    "NZ_PROTOTYPE_HIGHESTWAVE",
    "NZ_PROTOTYPE_TIMEINWAVE",
    "NZ_PROTOTYPE_TOTALPOINTS",
    "NZ_ASYLUM_HIGHESTWAVE",
    "NZ_ASYLUM_TIMEINWAVE",
    "NZ_ASYLUM_TOTALPOINTS",
    "NZ_SUMPF_HIGHESTWAVE",
    "NZ_SUMPF_TIMEINWAVE",
    "NZ_SUMPF_TOTALPOINTS",
    "NZ_FACTORY_HIGHESTWAVE",
    "NZ_FACTORY_TIMEINWAVE",
    "NZ_FACTORY_TOTALPOINTS",
]
for _offset, _name in enumerate(_ARCADE_NAMES):
    KNOWN_STATS[3400 + _offset] = _name


def normalize_name(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")


NAME_TO_INDEX = {normalize_name(name): index for index, name in KNOWN_STATS.items()}
# Friendly and typo-compatible aliases.
NAME_TO_INDEX.update({
    "LEVEL": 2350,
    "PRESTIGE": 2326,
    "PRESTIGE_LEVEL": 2326,
    "XP": 2301,
    "RANK_XP": 2301,
    "ZOMBIE_HEASHOTS": 2106,
    "CURRENT_MENU_RANK": 251,
    "PROMOTION_MENU_RANK": 252,
})

CORE_INFO_STATS = [
    251, 252, 260,
    2301, 2350, 2351, 2352, 2353, 2326,
    2302, 2303, 2304, 2305, 2306, 2307, 2308, 2309, 2310,
    2311, 2312, 2313, 2314, 2315,
    2316, 2317, 2318, 2319, 2320, 2321,
    2322, 2323, 2324, 2325,
    2100, 2101, 2102, 2103, 2104, 2105, 2106,
]


def load_file(path: Path) -> bytearray:
    try:
        data = bytearray(path.read_bytes())
    except OSError as exc:
        raise UnlockStatsError(f"Could not read {path}: {exc}") from exc
    if len(data) != FILE_SIZE:
        raise UnlockStatsError(
            f"Invalid file size: expected {FILE_SIZE} bytes (0x{FILE_SIZE:x}), "
            f"got {len(data)} bytes"
        )
    return data


def stored_crc(data: bytes | bytearray) -> int:
    return struct.unpack_from("<I", data, CHECKSUM_OFFSET)[0]


def calculated_crc(data: bytes | bytearray) -> int:
    return zlib.crc32(data[BODY_OFFSET:]) & 0xFFFFFFFF


def update_crc(data: bytearray) -> int:
    crc = calculated_crc(data)
    struct.pack_into("<I", data, CHECKSUM_OFFSET, crc)
    return crc


def validate_stat_index(index: int) -> None:
    if not 0 <= index <= MAX_STAT_INDEX:
        raise UnlockStatsError(
            f"Invalid stat index {index}; valid range is 0..{MAX_STAT_INDEX}"
        )


def stat_offset(index: int) -> int:
    validate_stat_index(index)
    if index < BYTE_STATS_COUNT:
        return BYTE_STATS_OFFSET + index
    return DWORD_STATS_OFFSET + (index - BYTE_STATS_COUNT) * 4


def stat_width(index: int) -> int:
    validate_stat_index(index)
    return 1 if index < BYTE_STATS_COUNT else 4


def get_stat_unsigned(data: bytes | bytearray, index: int) -> int:
    offset = stat_offset(index)
    if index < BYTE_STATS_COUNT:
        return data[offset]
    return struct.unpack_from("<I", data, offset)[0]


def unsigned_to_signed32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def get_stat_signed(data: bytes | bytearray, index: int) -> int:
    value = get_stat_unsigned(data, index)
    return value if index < BYTE_STATS_COUNT else unsigned_to_signed32(value)


def set_stat(data: bytearray, index: int, value: int) -> tuple[int, int]:
    validate_stat_index(index)
    old = get_stat_unsigned(data, index)
    offset = stat_offset(index)
    if index < BYTE_STATS_COUNT:
        if not 0 <= value <= 0xFF:
            raise UnlockStatsError(
                f"Byte stat {index} accepts only 0..255; got {value}"
            )
        data[offset] = value
        return old, value

    if not -(1 << 31) <= value <= 0xFFFFFFFF:
        raise UnlockStatsError(
            f"Dword stat {index} accepts -2147483648..4294967295; got {value}"
        )
    encoded = value & 0xFFFFFFFF
    struct.pack_into("<I", data, offset, encoded)
    return old, encoded


def parse_int(value: str) -> int:
    text = value.strip().replace("_", "")
    try:
        return int(text, 0)
    except ValueError:
        # Permit ordinary decimal numbers such as 08, which int(..., 0) rejects.
        try:
            return int(text, 10)
        except ValueError as exc:
            raise UnlockStatsError(f"Invalid integer value: {value!r}") from exc


def parse_stat_identifier(value: str) -> int:
    text = value.strip()
    try:
        index = parse_int(text)
    except UnlockStatsError:
        key = normalize_name(text)
        if key not in NAME_TO_INDEX:
            raise UnlockStatsError(
                f"Unknown stat name {value!r}. Use 'list-names' or a numeric index."
            )
        index = NAME_TO_INDEX[key]
    validate_stat_index(index)
    return index


def display_name(index: int) -> str:
    return KNOWN_STATS.get(index, "")


def format_stat(data: bytes | bytearray, index: int) -> str:
    value_u = get_stat_unsigned(data, index)
    width = stat_width(index)
    name = display_name(index) or "UNKNOWN"
    if width == 1:
        return (
            f"{index:4d}  0x{stat_offset(index):04x}  u8   "
            f"{name:<30} {value_u:10d}  0x{value_u:02x}"
        )
    value_s = unsigned_to_signed32(value_u)
    return (
        f"{index:4d}  0x{stat_offset(index):04x}  u32  "
        f"{name:<30} {value_u:10d}  signed={value_s:11d}  0x{value_u:08x}"
    )


def require_valid_or_warn(data: bytes | bytearray, allow_bad_crc: bool) -> None:
    stored = stored_crc(data)
    calc = calculated_crc(data)
    if stored != calc and not allow_bad_crc:
        raise UnlockStatsError(
            f"Checksum mismatch: stored 0x{stored:08x}, calculated 0x{calc:08x}. "
            "Use --allow-bad-crc to inspect/repair this file deliberately."
        )


def write_output(
    data: bytearray,
    input_path: Path,
    output_path: Path,
    force: bool,
) -> None:
    try:
        input_resolved = input_path.resolve()
        output_resolved = output_path.resolve()
    except OSError:
        input_resolved = input_path.absolute()
        output_resolved = output_path.absolute()
    if input_resolved == output_resolved:
        raise UnlockStatsError(
            "Refusing to overwrite the input file. Choose a different output path."
        )
    if output_path.exists() and not force:
        raise UnlockStatsError(
            f"Output already exists: {output_path}. Add --force to replace it."
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_bytes(data)
    except OSError as exc:
        raise UnlockStatsError(f"Could not write {output_path}: {exc}") from exc



def _print_import_summary(path: Path, result: ImportResult) -> None:
    print(f"Input:                 {path}")
    print(f"Detected format:       {result.source_format}")
    print(f"Decoded input size:    {result.source_size} bytes (0x{result.source_size:x})")
    print(f"Source encoding:       {result.source_encoding}")
    if result.outer_authenticated is True:
        print("Outer authentication:  VALID")
    elif result.outer_authenticated is False:
        print("Outer authentication:  INVALID")
    else:
        print("Outer authentication:  not applicable / not present")
    if result.key_description:
        print(f"Key source:            {result.key_description}")
    if result.fs_game_path:
        print(f"fs_game path:          {result.fs_game_path}")
    print(f"Inner stored CRC-32:   0x{result.inner_crc_stored:08x}")
    print(f"Inner calculated CRC:  0x{result.inner_crc_calculated:08x}")
    print(f"Inner checksum valid:  {'YES' if result.inner_crc_valid else 'NO'}")
    print(f"Stats SHA-256:         {hashlib.sha256(result.stats).hexdigest()}")


def _print_source_header(source: SourceData) -> None:
    print(f"Requested input:        {source.requested_path}")
    if source.display_name != str(source.requested_path):
        print(f"Selected source:        {source.display_name}")
    print(f"On-disk member size:    {source.on_disk_size} bytes")
    print(f"Decoded size:           {len(source.data)} bytes (0x{len(source.data):x})")
    print(f"Source encoding:        {source.source_encoding}")


def cmd_identify(args: argparse.Namespace) -> None:
    source = load_source(args.file)
    _print_source_header(source)
    data = source.data
    print(f"Detected format:        {identify_source(data)}")
    if len(data) == IWM_CONTAINER_SIZE:
        print(f"Signature:              {bytes(data[:4])!r}")
        print(f"Seed:                   0x{struct.unpack_from('<I', data, IWM_SEED_OFFSET)[0]:08x}")
    if len(data) == IWM_CONTAINER_SIZE and data[:4] == b"iwm0" and not args.decrypt:
        print("Decryption:             not attempted (add --decrypt)")
        return
    try:
        result = extract_with_available_keys(
            data,
            source.source_encoding,
            args,
            prompt_if_needed=args.decrypt,
        )
    except UnlockStatsError as exc:
        print(f"Extraction:             {exc}")
        return
    print()
    _print_import_summary(Path(source.display_name), result)


def _backup_path(target: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = target.with_name(f"{target.name}.backup-{stamp}")
    counter = 1
    while candidate.exists():
        candidate = target.with_name(f"{target.name}.backup-{stamp}-{counter}")
        counter += 1
    return candidate


def install_stats_bytes(stats: bytes | bytearray, target: Path) -> Path | None:
    data = bytes(stats)
    if len(data) != FILE_SIZE:
        raise UnlockStatsError(f"Install input must be exactly {FILE_SIZE} bytes, got {len(data)}.")
    if stored_crc(data) != calculated_crc(data):
        raise UnlockStatsError("Refusing to install an unlockstats_mp file with an invalid CRC-32.")

    target = target.expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    if target.exists():
        try:
            existing = target.read_bytes()
        except OSError as exc:
            raise UnlockStatsError(f"Could not read existing target {target}: {exc}") from exc
        if existing == data:
            print(f"Install target already matches exactly: {target}")
            return None
        backup = _backup_path(target)
        try:
            shutil.copy2(target, backup)
        except OSError as exc:
            raise UnlockStatsError(f"Could not back up existing target to {backup}: {exc}") from exc

    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, target)
        if target.read_bytes() != data:
            raise UnlockStatsError(f"Read-back verification failed after writing {target}.")
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise UnlockStatsError(f"Could not install {target}: {exc}") from exc
    return backup


def cmd_import_mpdata(args: argparse.Namespace) -> None:
    if args.target and not args.install:
        raise UnlockStatsError("--target is valid only together with --install.")
    source = load_source(args.file)
    data = source.data
    result = extract_with_available_keys(
        data,
        source.source_encoding,
        args,
        prompt_if_needed=True,
    )
    _print_source_header(source)
    print()
    _print_import_summary(Path(source.display_name), result)

    if not result.inner_crc_valid:
        if not args.repair_inner_crc:
            raise UnlockStatsError(
                "The extracted 0x2000 player-stat block has a bad inner CRC-32. "
                "The source may already be corrupt. Add --repair-inner-crc only if you deliberately "
                "want to recalculate it without changing any other bytes."
            )
        old_crc = result.inner_crc_stored
        new_crc = update_crc(result.stats)
        result.inner_crc_stored = new_crc
        result.inner_crc_calculated = new_crc
        print(f"Inner CRC repaired:     0x{old_crc:08x} -> 0x{new_crc:08x}")

    if args.install:
        target = Path(args.target).expanduser() if args.target else default_plutonium_target()
        backup = install_stats_bytes(result.stats, target)
        print(f"Installed current file: {target}")
        if backup:
            print(f"Backed up old template: {backup}")
    else:
        output_path = Path(args.output).expanduser() if args.output else default_output_path(source.requested_path)
        write_output(result.stats, source.requested_path, output_path, args.force)
        print(f"Output size:            {len(result.stats)} bytes (0x{len(result.stats):x})")
        print(f"Wrote Plutonium import: {output_path}")

    print("The complete 0x2000 player-stat payload was preserved, including rank, unlocks, challenges, and class loadouts.")
    print("The generated unlockstats_mp file is an import template; run /unlockall once to write it into the active profile MPData.")
    print("Custom class names do not transfer to Plutonium and must be renamed in-game after import.")


def cmd_install(args: argparse.Namespace) -> None:
    source_path = Path(args.file).expanduser()
    stats = load_file(source_path)
    require_valid_or_warn(stats, False)
    target = Path(args.target).expanduser() if args.target else default_plutonium_target()
    backup = install_stats_bytes(stats, target)
    print(f"Source:                 {source_path}")
    print(f"Installed current file: {target}")
    if backup:
        print(f"Backed up old template: {backup}")
    print("Start or return to Plutonium T4 Multiplayer, make sure the intended profile is active, then run /unlockall once.")


def _print_first_stat_differences(left: bytes | bytearray, right: bytes | bytearray, limit: int = 25) -> int:
    count = 0
    for index in range(MAX_STAT_INDEX + 1):
        left_value = get_stat_unsigned(left, index)
        right_value = get_stat_unsigned(right, index)
        if left_value == right_value:
            continue
        count += 1
        if count <= limit:
            name = display_name(index) or "UNKNOWN"
            print(f"  stat {index:4d} {name:<30} source={left_value} target={right_value}")
    return count


def cmd_verify_transfer(args: argparse.Namespace) -> None:
    source = load_source(args.source)
    result = extract_with_available_keys(
        source.data,
        source.source_encoding,
        args,
        prompt_if_needed=True,
    )
    if not result.inner_crc_valid:
        raise UnlockStatsError("The decrypted source MPData has an invalid inner CRC-32.")
    target_path = Path(args.unlockstats_mp).expanduser()
    target = load_file(target_path)
    require_valid_or_warn(target, False)

    _print_source_header(source)
    print(f"Comparison target:      {target_path}")
    print(f"Source stats SHA-256:   {hashlib.sha256(result.stats).hexdigest()}")
    print(f"Target stats SHA-256:   {hashlib.sha256(target).hexdigest()}")
    if bytes(result.stats) == bytes(target):
        print("Exact payload match:    YES")
        print("All 8,192 bytes, all 3,498 addressable stats, the checksum, and the trailing region match exactly.")
        return

    byte_differences = sum(a != b for a, b in zip(result.stats, target))
    print("Exact payload match:    NO")
    print(f"Differing bytes:        {byte_differences}")
    stat_differences = _print_first_stat_differences(result.stats, target)
    print(f"Differing stat slots:   {stat_differences}")
    tail_differences = sum(
        result.stats[offset] != target[offset]
        for offset in range(TAIL_OFFSET, FILE_SIZE)
    )
    print(f"Trailing-byte changes:  {tail_differences}")
    raise UnlockStatsError("The target is valid but is not the exact player-stat block extracted from the source MPData.")


def cmd_self_test(args: argparse.Namespace) -> None:
    vectors = {
        b"": "31d6cfe0d16ae931b73c59d7e0c089c0",
        b"a": "bde52cb31de33e46245e05fbdbd6fb24",
        b"abc": "a448017aaf21d8525fc10ae87aa6729d",
        b"message digest": "d9130a8164549fe818874806e1c7014b",
    }
    for message, expected in vectors.items():
        actual = md4(message).hex()
        if actual != expected:
            raise UnlockStatsError(f"MD4 self-test failed for {message!r}: {actual} != {expected}")

    sample = bytearray(FILE_SIZE)
    sample[4:] = bytes((index * 37 + 11) & 0xFF for index in range(FILE_SIZE - 4))
    update_crc(sample)
    key = "AAAABBBBCCCCDDDDEEEE"
    seed = 0x12345678
    container = build_iwm0_container(sample, key, seed=seed, fs_game_path="mods/test")
    result = decrypt_iwm0_container(container, key)
    if result.stats != sample or not result.inner_crc_valid:
        raise UnlockStatsError("IWM encrypt/decrypt round-trip self-test failed.")

    separated_key_result = decrypt_iwm0_container(container, "AAAA-BBBB-CCCC-DDDD-EEEE")
    if separated_key_result.stats != sample:
        raise UnlockStatsError("CD-key separator normalization self-test failed.")

    try:
        decrypt_iwm0_container(container, "WRONGWRONGWRONGWRONG")
    except UnlockStatsError:
        pass
    else:
        raise UnlockStatsError("Wrong-key rejection self-test failed.")

    decoded, encoding = _decode_hex_wrapped_input(bytes(sample).hex().encode("ascii"))
    if decoded != sample or encoding != "ASCII hexadecimal":
        raise UnlockStatsError("ASCII-hex input self-test failed.")

    print("MD4 vectors:           PASS")
    print("IWM round trip:        PASS")
    print("Key normalization:     PASS")
    print("Wrong-key rejection:   PASS")
    print("Inner CRC validation:  PASS")
    print("ASCII-hex decoding:    PASS")


def cmd_info(args: argparse.Namespace) -> None:
    path = Path(args.file)
    data = load_file(path)
    sha256 = hashlib.sha256(data).hexdigest()
    stored = stored_crc(data)
    calc = calculated_crc(data)
    nonzero = sum(1 for value in data if value)
    print(f"File:                 {path}")
    print(f"Size:                 {len(data)} bytes (0x{len(data):x})")
    print(f"SHA-256:              {sha256}")
    print(f"Stored CRC-32:        0x{stored:08x}")
    print(f"Calculated CRC-32:    0x{calc:08x}")
    print(f"Checksum valid:       {'YES' if stored == calc else 'NO'}")
    print(f"Nonzero bytes:        {nonzero} ({nonzero / len(data):.2%})")
    print()
    print("Layout:")
    print("  0x0000..0x0003  checksum (little-endian CRC-32 of 0x0004..0x1fff)")
    print("  0x0004..0x07d3  2000 byte stats, indices 0..1999")
    print("  0x07d4..0x1f3b  1498 little-endian dword stats, indices 2000..3497")
    print("  0x1f3c..0x1fff  196-byte trailing/unknown area")
    print()
    print("Decoded core fields (values are raw stored integers):")
    print("index  offset  type name                                value")
    print("-----  ------  ---- ----------------------------------  -------------------------------")
    for index in CORE_INFO_STATS:
        print(format_stat(data, index))


def cmd_get(args: argparse.Namespace) -> None:
    data = load_file(Path(args.file))
    require_valid_or_warn(data, args.allow_bad_crc)
    index = parse_stat_identifier(args.stat)
    print(format_stat(data, index))


def parse_assignment(text: str) -> tuple[int, int]:
    if "=" not in text:
        raise UnlockStatsError(
            f"Invalid assignment {text!r}; expected STAT=VALUE, for example RANKXP=153950"
        )
    stat_text, value_text = text.split("=", 1)
    return parse_stat_identifier(stat_text), parse_int(value_text)


def print_change(index: int, old_u: int, new_u: int) -> None:
    name = display_name(index) or "UNKNOWN"
    if stat_width(index) == 1:
        print(f"  {index:4d} {name:<30} {old_u} -> {new_u}")
    else:
        old_s = unsigned_to_signed32(old_u)
        new_s = unsigned_to_signed32(new_u)
        print(
            f"  {index:4d} {name:<30} "
            f"u32 {old_u} -> {new_u}  signed {old_s} -> {new_s}"
        )


def cmd_set(args: argparse.Namespace) -> None:
    input_path = Path(args.file)
    output_path = Path(args.output)
    data = load_file(input_path)
    require_valid_or_warn(data, args.allow_bad_crc)
    index = parse_stat_identifier(args.stat)
    value = parse_int(args.value)
    old_u, new_u = set_stat(data, index, value)
    crc = update_crc(data)
    write_output(data, input_path, output_path, args.force)
    print("Changed:")
    print_change(index, old_u, new_u)
    print(f"New checksum: 0x{crc:08x}")
    print(f"Wrote: {output_path}")


def cmd_patch(args: argparse.Namespace) -> None:
    input_path = Path(args.file)
    output_path = Path(args.output)
    data = load_file(input_path)
    require_valid_or_warn(data, args.allow_bad_crc)
    changes: list[tuple[int, int, int]] = []
    for assignment in args.assignments:
        index, value = parse_assignment(assignment)
        old_u, new_u = set_stat(data, index, value)
        if old_u != new_u:
            changes.append((index, old_u, new_u))

    if args.sync_rank:
        rank_u = get_stat_unsigned(data, 2350)
        if rank_u > 255:
            raise UnlockStatsError(
                f"Cannot sync rank mirrors: RANK is {rank_u}, outside byte range 0..255"
            )
        for index in (251, 252):
            old_u, new_u = set_stat(data, index, rank_u)
            if old_u != new_u:
                changes.append((index, old_u, new_u))

    crc = update_crc(data)
    write_output(data, input_path, output_path, args.force)
    if changes:
        print("Changed:")
        for index, old_u, new_u in changes:
            print_change(index, old_u, new_u)
    else:
        print("No stat values changed; checksum was still recalculated.")
    print(f"New checksum: 0x{crc:08x}")
    print(f"Wrote: {output_path}")


def cmd_repair(args: argparse.Namespace) -> None:
    input_path = Path(args.file)
    output_path = Path(args.output)
    data = load_file(input_path)
    old = stored_crc(data)
    new = update_crc(data)
    write_output(data, input_path, output_path, args.force)
    print(f"Checksum: 0x{old:08x} -> 0x{new:08x}")
    print(f"Wrote: {output_path}")


def iter_dump_rows(
    data: bytes | bytearray,
    known_only: bool,
    nonzero_only: bool,
) -> Iterable[list[str | int]]:
    for index in range(MAX_STAT_INDEX + 1):
        name = display_name(index)
        if known_only and not name:
            continue
        value_u = get_stat_unsigned(data, index)
        if nonzero_only and value_u == 0:
            continue
        width = stat_width(index)
        value_s = value_u if width == 1 else unsigned_to_signed32(value_u)
        yield [
            index,
            name,
            "byte" if width == 1 else "dword",
            f"0x{stat_offset(index):04x}",
            width,
            value_u,
            value_s,
            f"0x{value_u:0{width * 2}x}",
            1 if value_u else 0,
        ]


def cmd_dump(args: argparse.Namespace) -> None:
    input_path = Path(args.file)
    output_path = Path(args.output)
    data = load_file(input_path)
    require_valid_or_warn(data, args.allow_bad_crc)
    if output_path.exists() and not args.force:
        raise UnlockStatsError(
            f"Output already exists: {output_path}. Add --force to replace it."
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow([
                "stat_index",
                "name",
                "storage",
                "file_offset",
                "width_bytes",
                "unsigned_value",
                "signed_value",
                "hex_value",
                "nonzero",
            ])
            count = 0
            for row in iter_dump_rows(data, args.known_only, args.nonzero):
                writer.writerow(row)
                count += 1
    except OSError as exc:
        raise UnlockStatsError(f"Could not write {output_path}: {exc}") from exc
    print(f"Wrote {count} stat rows to {output_path}")


def cmd_diff(args: argparse.Namespace) -> None:
    left_path = Path(args.left)
    right_path = Path(args.right)
    left = load_file(left_path)
    right = load_file(right_path)
    print(f"Left checksum:  stored=0x{stored_crc(left):08x} calculated=0x{calculated_crc(left):08x}")
    print(f"Right checksum: stored=0x{stored_crc(right):08x} calculated=0x{calculated_crc(right):08x}")
    print()
    changed = 0
    for index in range(MAX_STAT_INDEX + 1):
        old_u = get_stat_unsigned(left, index)
        new_u = get_stat_unsigned(right, index)
        if old_u != new_u:
            print_change(index, old_u, new_u)
            changed += 1
    tail_changes = [
        TAIL_OFFSET + offset
        for offset, (a, b) in enumerate(zip(left[TAIL_OFFSET:], right[TAIL_OFFSET:]))
        if a != b
    ]
    print()
    print(f"Changed stat indices: {changed}")
    print(f"Changed trailing bytes: {len(tail_changes)}")
    if tail_changes:
        preview = ", ".join(f"0x{offset:04x}" for offset in tail_changes[:32])
        if len(tail_changes) > 32:
            preview += ", ..."
        print(f"Trailing byte offsets: {preview}")


def cmd_list_names(args: argparse.Namespace) -> None:
    needle = normalize_name(args.filter) if args.filter else ""
    for index in sorted(KNOWN_STATS):
        name = KNOWN_STATS[index]
        if needle and needle not in normalize_name(name):
            continue
        print(f"{index:4d}  {name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert WaW MPData to the current Plutonium T4 unlockstats_mp import template, then inspect or edit raw stats."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    identify = sub.add_parser("identify", help="Detect an MPData/playerstats/unlockstats_mp input; folders and ZIPs are supported")
    identify.add_argument("file")
    identify.add_argument("--decrypt", action="store_true", help="Attempt encrypted iwm0 decryption and prompt for a key if needed")
    identify.add_argument("--cd-key", help="World at War CD key; prefer --key-file or WAW_CD_KEY to avoid shell history")
    identify.add_argument("--key-file", help="Text file whose first line contains the World at War CD key")
    identify.add_argument("--no-registry", action="store_true", help="Do not search the Windows registry for codkey")
    identify.set_defaults(func=cmd_identify)

    convert = sub.add_parser("convert", aliases=["import-mpdata"], help="Create the current Plutonium unlockstats_mp import template from MPData")
    convert.add_argument("file", help="mpdata, mpdatabk0000, .corrupt MPData, profile folder, or ZIP archive")
    destination = convert.add_mutually_exclusive_group()
    destination.add_argument("-o", "--output", help="Output path (default: unlockstats_mp beside the input)")
    destination.add_argument("--install", action="store_true", help="Install directly to the current Plutonium t4\\plutonium\\unlockstats_mp target")
    convert.add_argument("--target", help="Override install target; valid only with --install")
    convert.add_argument("--cd-key", help="World at War CD key; prefer --key-file or WAW_CD_KEY to avoid shell history")
    convert.add_argument("--key-file", help="Text file whose first line contains the World at War CD key")
    convert.add_argument("--no-registry", action="store_true", help="Do not search the Windows registry for codkey")
    convert.add_argument("--repair-inner-crc", action="store_true", help="Recalculate a bad inner stats CRC instead of rejecting the source")
    convert.add_argument("--force", action="store_true")
    convert.set_defaults(func=cmd_import_mpdata)

    install = sub.add_parser("install", help="Back up and install a valid unlockstats_mp into the current Plutonium T4 folder")
    install.add_argument("file", help="Valid 8,192-byte unlockstats_mp file")
    install.add_argument("--target", help="Override target path (default: %%LOCALAPPDATA%%\\Plutonium\\storage\\t4\\plutonium\\unlockstats_mp)")
    install.set_defaults(func=cmd_install)

    verify = sub.add_parser("verify-transfer", help="Decrypt MPData and prove that an unlockstats_mp file is an exact 8,192-byte match")
    verify.add_argument("source", help="mpdata, profile folder, ZIP, or .corrupt MPData")
    verify.add_argument("unlockstats_mp", help="Generated or installed raw file to compare")
    verify.add_argument("--cd-key", help="World at War CD key; prefer --key-file or WAW_CD_KEY to avoid shell history")
    verify.add_argument("--key-file", help="Text file whose first line contains the World at War CD key")
    verify.add_argument("--no-registry", action="store_true", help="Do not search the Windows registry for codkey")
    verify.set_defaults(func=cmd_verify_transfer)

    self_test = sub.add_parser("self-test", help="Run built-in MD4, encryption, and CRC tests")
    self_test.set_defaults(func=cmd_self_test)

    info = sub.add_parser("info", help="Validate and display decoded core fields")
    info.add_argument("file")
    info.set_defaults(func=cmd_info)

    get = sub.add_parser("get", help="Read one stat by numeric index or known name")
    get.add_argument("file")
    get.add_argument("stat")
    get.add_argument("--allow-bad-crc", action="store_true")
    get.set_defaults(func=cmd_get)

    set_cmd = sub.add_parser("set", help="Change one stat and write a new file")
    set_cmd.add_argument("file")
    set_cmd.add_argument("stat")
    set_cmd.add_argument("value")
    set_cmd.add_argument("-o", "--output", required=True)
    set_cmd.add_argument("--allow-bad-crc", action="store_true")
    set_cmd.add_argument("--force", action="store_true")
    set_cmd.set_defaults(func=cmd_set)

    patch = sub.add_parser("patch", help="Apply several STAT=VALUE changes at once")
    patch.add_argument("file")
    patch.add_argument(
        "--set",
        dest="assignments",
        action="append",
        required=True,
        metavar="STAT=VALUE",
        help="May be supplied more than once",
    )
    patch.add_argument("-o", "--output", required=True)
    patch.add_argument(
        "--sync-rank",
        action="store_true",
        help="Copy dword RANK (2350) to byte stats 251 and 252",
    )
    patch.add_argument("--allow-bad-crc", action="store_true")
    patch.add_argument("--force", action="store_true")
    patch.set_defaults(func=cmd_patch)

    repair = sub.add_parser("repair", help="Recalculate only the checksum into a new file")
    repair.add_argument("file")
    repair.add_argument("-o", "--output", required=True)
    repair.add_argument("--force", action="store_true")
    repair.set_defaults(func=cmd_repair)

    dump = sub.add_parser("dump", help="Write stat values to CSV")
    dump.add_argument("file")
    dump.add_argument("-o", "--output", required=True)
    dump.add_argument("--known-only", action="store_true")
    dump.add_argument("--nonzero", action="store_true")
    dump.add_argument("--allow-bad-crc", action="store_true")
    dump.add_argument("--force", action="store_true")
    dump.set_defaults(func=cmd_dump)

    diff = sub.add_parser("diff", help="Compare two unlockstats_mp files by stat index")
    diff.add_argument("left")
    diff.add_argument("right")
    diff.set_defaults(func=cmd_diff)

    names = sub.add_parser("list-names", help="List known stat names and indices")
    names.add_argument("--filter")
    names.set_defaults(func=cmd_list_names)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except UnlockStatsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
