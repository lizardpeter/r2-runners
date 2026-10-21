#!/usr/bin/env python3
"""Read original IW6 path nodes directly from an authenticated FastFile.

Evidence-only: does not invent navigation links, collision or server spawns.
Runs on the ephemeral r2-runners checkout with the owner's real R2 source.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import zlib

if len(sys.argv) < 3:
    raise SystemExit("usage: iw6_pathdata_source.py <research/tools/fastfile> <original_path.ff>")
sys.path.insert(0, sys.argv[1])
from probe_asset_directory import directory, pointer_kind  # noqa: E402
from probe_zone import outer_header, verified_authenticated_chunks, direct_chunks, StreamStats  # noqa: E402


def read_original(ff: Path) -> tuple[bytes, int]:
    stats = StreamStats()
    with ff.open("rb") as f:
        header = outer_header(f)
        chunks = (verified_authenticated_chunks(f, header.stream_offset, stats)
                  if header.envelope == "sha256-master-blocks"
                  else direct_chunks(f, header.stream_offset, stats))
        inflater = zlib.decompressobj()
        data = bytearray()
        for chunk in chunks:
            if inflater.eof:
                continue
            data.extend(inflater.decompress(chunk))
            if len(data) > 256 * 1024 * 1024:
                raise ValueError("PathData decoded file above safe 256 MiB bound")
        if not inflater.eof:
            raise ValueError("IW6 original zlib stream incomplete")
    if header.envelope != "sha256-master-blocks":
        raise ValueError("PathData probe only accepts authenticated original Ghosts zones")
    return bytes(data), stats.sha256_blocks


def inspect_path_nodes(data: bytes) -> dict:
    layout = directory(data)
    if layout["asset_count"] != 2 or layout["first_16_asset_types"] != ["pathdata", "rawfile"]:
        raise ValueError("not the authenticated two-entry original PathData zone")
    hdr_off = layout["exact_asset_table_offset"] + 32
    hdr = data[hdr_off:hdr_off + 136]
    if len(hdr) != 136:
        raise ValueError("original PathData header truncated")
    node_count = struct.unpack_from("<I", hdr, 8)[0]
    ptr_name = pointer_kind(struct.unpack_from("<Q", hdr, 0)[0])
    ptr_nodes = pointer_kind(struct.unpack_from("<Q", hdr, 16)[0])
    if not 0 < node_count <= 1_000_000:
        raise ValueError("PathData node count out of range")
    if ptr_nodes not in ("follows", "insert"):
        raise ValueError(f"Original PathData node array not inline: {ptr_nodes}")
    pos = hdr_off + 136
    if ptr_name in ("follows", "insert"):
        term = data.find(bytes([0]), pos, pos + 4096)
        if term < 0:
            raise ValueError("Original PathData name is not terminated")
        pos = term + 1
    array_size = node_count * 176
    end = pos + array_size
    if end > len(data):
        raise ValueError("Original path node array exceeds decoded zone")
    kinds: Counter[str] = Counter()
    link_kinds: Counter[str] = Counter()
    links = 0
    linked_nodes = 0
    link_declarations: list[tuple[int,str]] = []
    invalid_origins = 0
    bounds_min = [math.inf] * 3
    bounds_max = [-math.inf] * 3
    for i in range(node_count):
        off = pos + i * 176
        kind = struct.unpack_from("<H", data, off)[0]
        count = struct.unpack_from("<H", data, off + 68)[0]
        ptr = pointer_kind(struct.unpack_from("<Q", data, off + 72)[0])
        xyz = struct.unpack_from("<fff", data, off + 32)
        if all(math.isfinite(v) for v in xyz):
            for axis, value in enumerate(xyz):
                bounds_min[axis] = min(bounds_min[axis], value)
                bounds_max[axis] = max(bounds_max[axis], value)
        else:
            invalid_origins += 1
        if count > 8192:
            raise ValueError(f"Original path node {i} has implausible {count} links")
        if count and ptr == "null":
            raise ValueError(f"Original path node {i} has {count} links without source reference")
        kinds[str(kind)] += 1
        link_kinds[ptr] += 1
        links += count
        linked_nodes += int(count != 0)
        link_declarations.append((count,ptr))
    # Source-derived candidate: original node link arrays are serialized
    # immediately following all fixed 176-byte pathnode_t records. Validate
    # every real link target/distance before accepting this layout.
    link_cursor = end
    invalid_targets = 0
    invalid_distances = 0
    self_links = 0
    decoded_links = 0
    link_max_distance = 0.0
    for source_node, (count,kind) in enumerate(link_declarations):
        if kind not in ("follows","insert"):
            if count:
                raise ValueError(f"node {source_node}: missing link pointer")
            continue
        link_cursor = (link_cursor + 3) & ~3
        next_offset = link_cursor + 12*count
        if next_offset > len(data):
            raise ValueError("PathData link source extends beyond authenticated XFile")
        for off in range(link_cursor,next_offset,12):
            distance,target,disconnect,negotiation,flags=struct.unpack_from("<fHBBB3x",data,off)
            invalid_targets += int(target >= node_count)
            invalid_distances += int(not math.isfinite(distance) or distance < 0)
            self_links += int(target == source_node)
            if math.isfinite(distance):
                link_max_distance=max(link_max_distance,distance)
            decoded_links += 1
        link_cursor = next_offset
    accepted=(decoded_links == links and invalid_targets==0 and invalid_distances==0)
    return {
        "status": "original_IW6_path_links_validated" if accepted else "original_IW6_path_links_not_validated",
        "candidate_source_link_end":link_cursor,
        "decoded_link_slots":decoded_links,
        "invalid_target_indices":invalid_targets,
        "invalid_link_distances":invalid_distances,
        "self_link_count":self_links,
        "max_link_distance":link_max_distance,
        "source_link_layout_accepted":accepted,

        "pathdata_header_source_offset": hdr_off,
        "path_node_array_file_offset": pos,
        "path_node_array_end": end,
        "node_count": node_count,
        "source_node_bytes": array_size,
        "linked_nodes": linked_nodes,
        "authored_link_count_declared": links,
        "node_types": dict(kinds.most_common(24)),
        "link_pointer_classes": dict(link_kinds),
        "nonfinite_node_origins": invalid_origins,
        "bounds_min": bounds_min if invalid_origins != node_count else None,
        "bounds_max": bounds_max if invalid_origins != node_count else None,
        "links_decoded": accepted,
        "navigation_graph_ready": False,
    }


if __name__ == "__main__":
    source = Path(sys.argv[2])
    decoded, blocks = read_original(source)
    result = inspect_path_nodes(decoded)
    result["authenticated_blocks"] = blocks
    result["decoded_sha256"] = hashlib.sha256(decoded).hexdigest()
    print(json.dumps(result, sort_keys=True))
