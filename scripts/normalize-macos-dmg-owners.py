#!/usr/bin/env python3
"""Normalize HFS+ catalog owners in a new DMG without mounting or rewriting app files.

Only the ownerID and groupID fields of HFSPlusCatalogFile/Folder records are
changed. Unsupported disk layouts fail closed. The caller signs the resulting
outer DMG using its existing signing context; this tool never signs an app.
"""

import argparse
import hashlib
import json
import os
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path


class ImageRejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise ImageRejected(message)


def number(data, offset, fmt):
    size = struct.calcsize(fmt)
    need(0 <= offset <= len(data) - size, "truncated image structure")
    return struct.unpack_from(fmt, data, offset)[0]


def be16(data, offset):
    return number(data, offset, ">H")


def be32(data, offset):
    return number(data, offset, ">I")


def be64(data, offset):
    return number(data, offset, ">Q")


def le32(data, offset):
    return number(data, offset, "<I")


def le64(data, offset):
    return number(data, offset, "<Q")


def gpt_partition(raw):
    import zlib

    sector_count = len(raw) // 512
    need(len(raw) % 512 == 0 and sector_count >= 100, "invalid GPT image size")

    def header(lba):
        offset = lba * 512
        need(raw[offset:offset + 8] == b"EFI PART", "missing GPT header")
        size = le32(raw, offset + 12)
        need(92 <= size <= 512, "unsupported GPT header size")
        copy = bytearray(raw[offset:offset + size])
        crc = le32(copy, 16)
        copy[16:20] = b"\0" * 4
        need(zlib.crc32(copy) == crc, "GPT header CRC mismatch")
        need(le64(raw, offset + 24) == lba, "GPT header LBA mismatch")
        other = le64(raw, offset + 32)
        first, last = le64(raw, offset + 40), le64(raw, offset + 48)
        count, entry_size = le32(raw, offset + 80), le32(raw, offset + 84)
        need(1 <= count <= 128 and entry_size == 128, "unsupported GPT entry layout")
        table_lba = le64(raw, offset + 72)
        table_start = table_lba * 512
        table_end = table_start + count * entry_size
        need(0 <= table_start < table_end <= len(raw), "GPT table out of bounds")
        entries = raw[table_start:table_end]
        need(zlib.crc32(entries) == le32(raw, offset + 88), "GPT table CRC mismatch")
        return other, first, last, entries, bytes(raw[offset + 56:offset + 72])

    primary = header(1)
    need(primary[0] == sector_count - 1, "GPT alternate header location mismatch")
    backup = header(sector_count - 1)
    need(backup[0] == 1 and primary[1:] == backup[1:], "GPT backup differs")
    first_usable, last_usable, entries = primary[1], primary[2], primary[3]
    need(34 <= first_usable <= last_usable < sector_count - 1, "GPT usable range invalid")
    hfs_guid = bytes.fromhex("005346480000aa11aa1100306543ecac")
    parts = []
    occupied = []
    for i in range(len(entries) // 128):
        entry = entries[i * 128:(i + 1) * 128]
        if entry[:16] == b"\0" * 16:
            continue
        first, last = le64(entry, 32), le64(entry, 40)
        need(first_usable <= first <= last <= last_usable, "GPT partition out of bounds")
        occupied.append((first, last))
        if entry[:16] == hfs_guid:
            parts.append((first * 512, (last + 1) * 512))
    occupied.sort()
    need(all(a[1] < b[0] for a, b in zip(occupied, occupied[1:])), "overlapping GPT partitions")
    need(len(parts) == 1, "expected exactly one GPT HFS+ partition")
    return "GPT", parts[0]


def apm_partition(raw):
    need(raw[:2] == b"ER", "unknown partition scheme")
    block_size = be16(raw, 2)
    need(block_size in (512, 1024, 2048, 4096), "unsupported APM block size")
    need(len(raw) % block_size == 0, "invalid APM image size")

    def map_at(sector):
        first = raw[sector:sector + 512]
        if first[:2] != b"PM":
            return None
        count = be32(first, 4)
        need(1 <= count <= 128, "unsupported APM entry count")
        found = []
        for i in range(1, count + 1):
            entry = raw[i * sector:i * sector + 512]
            need(len(entry) == 512 and entry[:2] == b"PM" and be32(entry, 4) == count,
                 "corrupt APM entry")
            if entry[48:80].split(b"\0", 1)[0] == b"Apple_HFS":
                start, blocks = be32(entry, 8), be32(entry, 12)
                need(blocks > 0 and (start + blocks) * sector <= len(raw),
                     "APM HFS+ partition out of bounds")
                found.append((start * sector, (start + blocks) * sector))
        need(len(found) == 1, "expected exactly one APM HFS+ partition")
        return found[0]

    primary = map_at(block_size)
    need(primary is not None, "missing APM partition map")
    if block_size != 512:
        secondary = map_at(512)
        need(secondary is None or secondary == primary, "APM map views disagree")
    return "APM", primary


def image_layout(raw):
    need(0 < len(raw) <= 1024 * 1024 * 1024, "raw image exceeds supported size")
    scheme, (start, end) = (gpt_partition(raw) if raw[512:520] == b"EFI PART"
                            else apm_partition(raw))
    need(0 <= start < end <= len(raw), "HFS+ partition out of bounds")
    volume = memoryview(raw)[start:end]
    need(len(volume) >= 2048, "truncated HFS+ volume")
    header = volume[1024:1536]
    alternate = volume[-1024:-512]
    need(bytes(header[:4]) == b"H+\0\x04" and bytes(alternate[:4]) == b"H+\0\x04",
         "unsupported HFS+ header or version")
    need(bytes(header[4:8]) == bytes(alternate[4:8]) and
         bytes(header[40:48]) == bytes(alternate[40:48]) and
         bytes(header[272:352]) == bytes(alternate[272:352]),
         "HFS+ primary/alternate geometry or catalog differs")
    need(be32(header, 4) & 0x2000 == 0 and be32(header, 12) == 0,
         "journaled HFS+ is unsupported")
    block_size, total_blocks = be32(header, 40), be32(header, 44)
    need(block_size >= 512 and block_size & (block_size - 1) == 0 and
         block_size * total_blocks == len(volume), "HFS+ geometry invalid")
    return scheme, start, volume, header, block_size, total_blocks


def read_fork(volume, block_size, total_blocks, descriptor):
    need(len(descriptor) == 80, "invalid HFS+ fork descriptor")
    logical, allocated = be64(descriptor, 0), be32(descriptor, 12)
    extents = []
    stopped = False
    for i in range(8):
        first, count = be32(descriptor, 16 + i * 8), be32(descriptor, 20 + i * 8)
        if count == 0:
            need(first == 0, "invalid empty HFS+ extent")
            stopped = True
            continue
        need(not stopped and first > 0 and first + count <= total_blocks,
             "invalid or overflowed HFS+ extent")
        extents.append((first * block_size, count * block_size))
    need(sum(length for _, length in extents) == allocated * block_size and
         logical <= allocated * block_size, "HFS+ fork allocation mismatch")
    ordered = sorted(extents)
    need(all(a[0] + a[1] <= b[0] for a, b in zip(ordered, ordered[1:])),
         "overlapping HFS+ fork extents")
    contents = b"".join(bytes(volume[offset:offset + length]) for offset, length in extents)
    return contents[:logical], extents


def parse_raw(raw):
    scheme, start, volume, header, block_size, total_blocks = image_layout(raw)
    catalog, cat_extents = read_fork(volume, block_size, total_blocks, header[272:352])

    def reject_catalog_overlap(extents, label):
        for other_start, other_length in extents:
            for cat_start, cat_length in cat_extents:
                need(other_start + other_length <= cat_start or
                     cat_start + cat_length <= other_start,
                     label + " overlaps HFS+ catalog")

    reject_catalog_overlap([(1024, 512), (len(volume) - 1024, 512)], "volume header")
    for descriptor_start, label in ((112, "allocation fork"), (192, "extents fork"),
                                    (352, "attributes fork"), (432, "startup fork")):
        _, system_extents = read_fork(volume, block_size, total_blocks,
                                      header[descriptor_start:descriptor_start + 80])
        reject_catalog_overlap(system_extents, label)
    need(len(catalog) >= 512 and catalog[8:10] == b"\x01\0", "invalid catalog header node")
    need(be16(catalog, 10) == 3, "unsupported catalog header records")
    node_size, total_nodes = be16(catalog, 32), be32(catalog, 36)
    need(node_size >= 512 and node_size & (node_size - 1) == 0 and
         node_size * total_nodes == len(catalog), "invalid catalog node geometry")
    first_leaf, last_leaf, expected_leaves = be32(catalog, 24), be32(catalog, 28), be32(catalog, 20)
    need(first_leaf > 0 and last_leaf > 0 and expected_leaves > 0,
         "empty or unsupported catalog")

    def file_fork(descriptor):
        contents, extents = read_fork(volume, block_size, total_blocks, descriptor)
        reject_catalog_overlap(extents, "file fork")
        return contents

    def physical(logical_offset, length):
        need(0 <= logical_offset and logical_offset + length <= len(catalog),
             "catalog owner field out of bounds")
        remaining = logical_offset
        for offset, extent_length in cat_extents:
            if remaining < extent_length:
                need(remaining + length <= extent_length, "catalog owner field crosses extent")
                return start + offset + remaining
            remaining -= extent_length
        raise ImageRejected("catalog owner field outside extents")

    records = []
    leaf_count = 0
    seen = set()
    previous = 0
    node_id = first_leaf
    while node_id:
        need(node_id < total_nodes and node_id not in seen, "catalog leaf cycle/out of bounds")
        seen.add(node_id)
        node = catalog[node_id * node_size:(node_id + 1) * node_size]
        need(node[8:10] == b"\xff\x01" and be32(node, 4) == previous,
             "invalid catalog leaf chain")
        count = be16(node, 10)
        need(count > 0 and count + 1 <= (node_size - 14) // 2,
             "invalid catalog leaf record count")
        offsets = [be16(node, node_size - 2 * (i + 1)) for i in range(count + 1)]
        need(offsets[0] == 14 and offsets == sorted(set(offsets)) and
             offsets[-1] <= node_size - 2 * (count + 1), "invalid catalog record offsets")
        for i in range(count):
            leaf_count += 1
            record = node[offsets[i]:offsets[i + 1]]
            key_length = be16(record, 0)
            name_length = be16(record, 6)
            need(key_length == 6 + 2 * name_length and 2 + key_length + 2 <= len(record),
                 "invalid catalog key length")
            parent = be32(record, 2)
            try:
                name = record[8:8 + 2 * name_length].decode("utf-16be")
            except UnicodeDecodeError as exc:
                raise ImageRejected("invalid catalog Unicode name") from exc
            data_offset = 2 + key_length
            data = record[data_offset:]
            kind = be16(data, 0)
            need(kind in (1, 2, 3, 4), "unsupported catalog record type")
            need("/" not in name and ("\0" not in name or
                 (kind == 1 and name == "\0\0\0\0HFS+ Private Data")),
                 "invalid catalog path component")
            if kind in (3, 4):
                need(len(data) >= 10 and len(data) == 10 + 2 * be16(data, 8),
                     "invalid catalog thread record")
                continue
            need(len(data) == (88 if kind == 1 else 248), "invalid catalog object length")
            cnid, mode = be32(data, 8), be16(data, 42)
            need(cnid >= 2 and ((kind == 1 and stat.S_IFMT(mode) == stat.S_IFDIR) or
                                (kind == 2 and stat.S_IFMT(mode) in (stat.S_IFREG, stat.S_IFLNK))),
                 "unsupported catalog object type")
            owner_offset = physical(node_id * node_size + offsets[i] + data_offset + 32, 8)
            item = {"cnid": cnid, "parent": parent, "name": name, "kind": kind,
                    "mode": mode, "uid": be32(data, 32), "gid": be32(data, 36),
                    "owner_offset": owner_offset}
            if kind == 2:
                item["data"] = file_fork(data[88:168])
                item["resource"] = file_fork(data[168:248])
            records.append(item)
        previous = node_id
        node_id = be32(node, 0)
    need(previous == last_leaf and leaf_count == expected_leaves,
         "catalog leaf count or tail mismatch")
    need(sum(r["kind"] == 2 for r in records) == be32(header, 32) and
         sum(r["kind"] == 1 for r in records) == be32(header, 36) + 1,
         "catalog object counts mismatch")
    by_id = {r["cnid"]: r for r in records}
    need(len(by_id) == len(records) and 2 in by_id and by_id[2]["parent"] == 1 and
         by_id[2]["kind"] == 1, "invalid catalog root or duplicate CNID")
    paths = set()
    for item in records:
        names = []
        parent = item["parent"]
        ancestors = set()
        while parent != 1:
            need(parent in by_id and parent not in ancestors and by_id[parent]["kind"] == 1,
                 "invalid catalog ancestry")
            ancestors.add(parent)
            if parent != 2:
                names.append(by_id[parent]["name"])
            parent = by_id[parent]["parent"]
        need(item["cnid"] == 2 or 2 in ancestors, "catalog object outside root")
        relative = ("" if item["cnid"] == 2 else
                    "/".join(list(reversed(names)) + [item["name"]]))
        item["relative"] = unicodedata.normalize("NFC", relative)
        need(item["relative"] not in paths, "duplicate normalized catalog path")
        paths.add(item["relative"])
    need("" in paths, "missing catalog root")
    return {"scheme": scheme, "records": records, "leaf_records": leaf_count,
            "catalog_extents": len(cat_extents), "volume_bytes": len(volume)}


def compare_source_tree(parsed, source, source_relative):
    need(source.is_dir() and not source.is_symlink(), "source tree must be a real directory")
    prefix = unicodedata.normalize("NFC", source_relative.strip("/"))
    if prefix == ".":
        prefix = ""
    need(prefix == "" or (".." not in prefix.split("/") and "\0" not in prefix),
         "invalid source-relative path")
    actual = {}
    for item in parsed["records"]:
        relative = item["relative"]
        if relative == prefix:
            local_relative = ""
        elif prefix and relative.startswith(prefix + "/"):
            local_relative = relative[len(prefix) + 1:]
        elif not prefix:
            local_relative = relative
        else:
            continue
        need(local_relative not in actual, "duplicate source-relative catalog path")
        actual[local_relative] = item
    need("" in actual, "source tree absent from image")
    expected = {"": source}
    for local in source.rglob("*"):
        relative = unicodedata.normalize("NFC", local.relative_to(source).as_posix())
        need(relative not in expected, "duplicate normalized source path")
        expected[relative] = local
    need(set(actual) == set(expected), "source tree and image entries differ")
    files = links = 0
    digest = hashlib.sha256()
    for relative in sorted(expected):
        item = actual[relative]
        local = expected[relative]
        local_stat = local.lstat()
        need(stat.S_IFMT(local_stat.st_mode) == stat.S_IFMT(item["mode"]) and
             stat.S_IMODE(local_stat.st_mode) == stat.S_IMODE(item["mode"]),
             "source tree mode differs from image")
        if item["kind"] == 1:
            need(stat.S_ISDIR(local_stat.st_mode), "source directory type mismatch")
            content = b""
        elif stat.S_ISLNK(local_stat.st_mode):
            content = os.readlink(local).encode("utf-8")
            need(item["data"] == content, "source symlink target differs from image")
            links += 1
        else:
            content = local.read_bytes()
            need(item["data"] == content, "source file differs from image")
            files += 1
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(struct.pack(">H", item["mode"]))
        digest.update(hashlib.sha256(content).digest())
    return {"entries": len(actual), "files": files, "links": links,
            "manifestSha256": digest.hexdigest()}


def only_owner_bytes_changed(before, after, offsets):
    need(len(before) == len(after), "raw image size changed")
    previous = 0
    for offset in sorted(offsets):
        need(previous <= offset and offset + 8 <= len(before), "overlapping owner fields")
        need(before[previous:offset] == after[previous:offset] and
             after[offset:offset + 8] == b"\0" * 8, "non-owner image bytes changed")
        previous = offset + 8
    need(before[previous:] == after[previous:], "non-owner image bytes changed")


def normalize_raw(raw, source=None, source_relative="."):
    parsed = parse_raw(raw)
    source_manifest = compare_source_tree(parsed, source, source_relative) if source else None
    offsets = [item["owner_offset"] for item in parsed["records"]]
    changed = sum(item["uid"] != 0 or item["gid"] != 0 for item in parsed["records"])
    patched = bytearray(raw)
    for offset in offsets:
        patched[offset:offset + 8] = b"\0" * 8
    patched = bytes(patched)
    only_owner_bytes_changed(raw, patched, offsets)
    reparsed = parse_raw(patched)
    need(len(reparsed["records"]) == len(offsets) and
         all(item["uid"] == item["gid"] == 0 for item in reparsed["records"]),
         "owner normalization verification failed")
    need([(r["relative"], r["kind"], r["mode"], r.get("data"), r.get("resource"))
          for r in parsed["records"]] ==
         [(r["relative"], r["kind"], r["mode"], r.get("data"), r.get("resource"))
          for r in reparsed["records"]],
         "catalog paths, modes, or file forks changed")
    if source:
        need(compare_source_tree(reparsed, source, source_relative) == source_manifest,
             "source tree changed during normalization")
    report = {"partitionScheme": parsed["scheme"], "catalogObjects": len(offsets),
              "catalogLeafRecords": parsed["leaf_records"],
              "noncanonicalObjectsBefore": changed, "allOwnersZeroAfter": True,
              "onlyCatalogOwnerGroupFieldsChanged": True,
              "allFileForksPreserved": True,
              "sourceTree": source_manifest,
              "inputRawSha256": hashlib.sha256(raw).hexdigest(),
              "normalizedRawSha256": hashlib.sha256(patched).hexdigest()}
    return patched, report


def run_hdiutil(*args):
    result = subprocess.run(["/usr/bin/hdiutil", *map(str, args)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    need(result.returncode == 0, "hdiutil command failed")
    return result.stdout


def image_info(path):
    try:
        info = plistlib.loads(run_hdiutil("imageinfo", "-plist", path))
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise ImageRejected("cannot read hdiutil image information") from exc
    need(info.get("Format") == "UDZO" and info.get("Properties", {}).get("Encrypted") is False,
         "input/output must be unencrypted UDZO")
    need(len(info.get("Segments", [])) == 1, "segmented DMG is unsupported")
    return info


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def normalize_dmg(input_path, output_path, source):
    need(sys.platform == "darwin", "macOS hdiutil is required")
    need(input_path.is_file() and not input_path.is_symlink(), "input DMG must be a regular file")
    need(output_path.parent.is_dir() and not output_path.exists() and not output_path.is_symlink(),
         "output path must be new in an existing directory")
    need(source.is_dir() and not source.is_symlink() and source.name.endswith(".app"),
         "source must be a built .app directory")
    image_info(input_path)
    input_digest = sha256_file(input_path)
    with tempfile.TemporaryDirectory(prefix="dmg-owner-normalize-", dir=output_path.parent) as tmp:
        temp = Path(tmp)
        original_raw = temp / "original.cdr"
        patched_raw = temp / "canonical.cdr"
        candidate = temp / "candidate.dmg"
        roundtrip_raw = temp / "roundtrip.cdr"
        run_hdiutil("convert", input_path, "-format", "UDTO", "-o", original_raw)
        raw = original_raw.read_bytes()
        patched, report = normalize_raw(raw, source, source.name)
        with patched_raw.open("xb") as stream:
            stream.write(patched)
        run_hdiutil("convert", patched_raw, "-format", "UDZO", "-o", candidate)
        image_info(candidate)
        run_hdiutil("verify", candidate)
        run_hdiutil("convert", candidate, "-format", "UDTO", "-o", roundtrip_raw)
        need(roundtrip_raw.read_bytes() == patched, "UDZO roundtrip changed raw image")
        need(sha256_file(input_path) == input_digest,
             "input DMG changed during normalization")
        report["roundtripRawExact"] = True
        report["inputDmgSha256"] = input_digest
        report["outputDmgSha256"] = sha256_file(candidate)
        report["hdiutilVerified"] = True
        report["outputSigned"] = False
        # Hard-link creation is atomic and refuses an output that appeared meanwhile.
        os.link(candidate, output_path)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dmg", type=Path)
    parser.add_argument("output_dmg", type=Path)
    parser.add_argument("source_app", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        need(args.evidence.parent.is_dir() and not args.evidence.exists() and
             not args.evidence.is_symlink(), "evidence path must be new")
        report = normalize_dmg(args.input_dmg, args.output_dmg, args.source_app)
        try:
            with args.evidence.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, sort_keys=True, indent=2)
                stream.write("\n")
        except Exception:
            args.output_dmg.unlink(missing_ok=True)
            raise
        print(json.dumps(report, sort_keys=True))
    except (ImageRejected, OSError) as exc:
        print("DMG owner normalization refused: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
