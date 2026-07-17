#!/usr/bin/env python3
"""Read and safely modify Plutonium T4 / CoD: World at War unlockstats_mp files.

The observed Plutonium unlockstats_mp format is exactly 0x2000 bytes:

    0x0000  4 bytes   little-endian CRC-32 of bytes 0x0004..0x1fff
    0x0004  2000      one-byte stats, stat indices 0..1999
    0x07d4  5992      1498 little-endian dword stats, indices 2000..3497
    0x1f3c  196       trailing/unknown data

This program never overwrites the input file. Every modifying command requires an
output path and recalculates the checksum automatically.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import struct
import sys
import zlib
from pathlib import Path
from typing import Iterable

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


class UnlockStatsError(Exception):
    """A user-facing unlockstats_mp error."""


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
        description="Inspect and checksum-safely edit Plutonium T4/WaW unlockstats_mp files."
    )
    sub = parser.add_subparsers(dest="command", required=True)

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
