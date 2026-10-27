"""Independent source-byte H1 rigid-world renderer-batch closure.

This is NOT a material alias, ClipMap collision, or GPU rendering verifier.
Its sole job is to prove that splitting genuine 40B GfxSurface records into
bounded, original-order draws drops no authored face, mutates no index, and
does not invent any vertex. The Rust importer uses the same map-independent
policy. No original retail payload bytes leave the ephemeral runner.
"""
import hashlib
import struct
from mwr_h1_world_vertex_verify import extract_source_window

MAX_TRIANGLES_PER_DRAW = 65_535
H1_SURFACE_BYTES = 40


def verify_array_draw_batches(index_bytes, surface_bytes, vertex_count,
                              declared_index_count, max_triangles=MAX_TRIANGLES_PER_DRAW):
    if max_triangles < 1 or max_triangles > 65_535:
        raise ValueError("invalid H1 diagnostic renderer batch size")
    if len(index_bytes) != declared_index_count * 2 or len(surface_bytes) % H1_SURFACE_BYTES:
        raise ValueError("H1 draw batch source span size/count mismatch")
    if not surface_bytes or declared_index_count == 0 or declared_index_count % 3:
        raise ValueError("H1 draw batch input has no complete authored triangles")
    batches = []
    batch_vertices = set()
    batch_tris = 0
    batch_first = 0
    batch_faces = 0
    referenced_words = 0
    source_ranges = []
    for ordinal in range(len(surface_bytes) // H1_SURFACE_BYTES):
        at = ordinal * H1_SURFACE_BYTES
        first_vertex = struct.unpack_from("<I", surface_bytes, at + 4)[0]
        surface_vertex_count, surface_triangles = struct.unpack_from(
            "<HH", surface_bytes, at + 16)
        base = struct.unpack_from("<I", surface_bytes, at + 20)[0]
        count = surface_triangles * 3
        if surface_triangles == 0 or surface_vertex_count == 0:
            raise ValueError(f"H1 original surface {ordinal} has no authored faces or vertices")
        if surface_triangles > max_triangles:
            raise ValueError(f"H1 original surface {ordinal} exceeds draw policy cap")
        if first_vertex + surface_vertex_count > vertex_count:
            raise ValueError(f"H1 original surface {ordinal} vertex span outside world")
        if base + count > declared_index_count:
            raise ValueError(f"H1 original surface {ordinal} index span outside world")
        if batch_tris and batch_tris + surface_triangles > max_triangles:
            batches.append({
                "start_source_surface": batch_first,
                "end_source_surface_exclusive": ordinal,
                "original_triangles": batch_tris,
                "distinct_original_vertex_ids": len(batch_vertices),
            })
            batch_faces += batch_tris
            batch_tris = 0
            batch_vertices.clear()
            batch_first = ordinal
        words = memoryview(index_bytes)[base * 2:(base + count) * 2]
        for (local,) in struct.iter_unpack("<H", words):
            if local >= surface_vertex_count:
                raise ValueError(f"H1 original surface {ordinal} references nonlocal vertex")
            batch_vertices.add(first_vertex + local)
        source_ranges.append((base, base + count))
        batch_tris += surface_triangles
        referenced_words += count
    if batch_tris:
        batches.append({
            "start_source_surface": batch_first,
            "end_source_surface_exclusive": len(surface_bytes) // H1_SURFACE_BYTES,
            "original_triangles": batch_tris,
            "distinct_original_vertex_ids": len(batch_vertices),
        })
        batch_faces += batch_tris
    cursor = 0
    for start, end in sorted(source_ranges):
        if start != cursor:
            raise ValueError(f"H1 draw batch source index partition gap/overlap at {cursor}")
        cursor = end
    if cursor != declared_index_count or referenced_words != declared_index_count:
        raise ValueError("H1 draw batch source index coverage/count incomplete")
    if batch_faces * 3 != declared_index_count:
        raise ValueError("H1 draw batch triangle count is not the original count")
    if any(batch["original_triangles"] > max_triangles for batch in batches):
        raise ValueError("H1 draw batch larger than policy limit")
    if sum(batch["end_source_surface_exclusive"] - batch["start_source_surface"]
           for batch in batches) != len(source_ranges):
        raise ValueError("H1 draw batch did not cover every source surface")
    return {
        "status": "fully_closed_source_order_renderer_draw_batches",
        "source_indices_sha256": hashlib.sha256(index_bytes).hexdigest(),
        "original_source_surfaces_preserved": len(source_ranges),
        "original_index_words_preserved": declared_index_count,
        "original_triangles_preserved": batch_faces,
        "renderer_batch_triangle_budget": max_triangles,
        "diagnostic_renderer_batches": len(batches),
        "batched_source_vertex_references": sum(x["distinct_original_vertex_ids"] for x in batches),
        "largest_batch_triangles": max(x["original_triangles"] for x in batches),
        "largest_batch_unique_vertices": max(x["distinct_original_vertex_ids"] for x in batches),
        "first_12_source_batches": batches[:12],
        "original_materials_and_clip_collision_not_verified": True,
    }


def inspect_original_draw_batch_source(ff, header, stream_class, world,
                                       vertices, surfaces, validated_indices):
    if validated_indices.get("status") != "complete_original_index_array_verified":
        return {"status": "refused_unverified_original_indices"}
    if vertices.get("status") != "complete" or surfaces.get("status") != "complete_original_surface_struct_array_verified":
        return {"status": "refused_unverified_original_vertices_or_surfaces"}
    index_first = validated_indices["decoded_index_start"]
    index_end = validated_indices["decoded_index_end"]
    surface_first = surfaces["complete_source_surface_start"]
    surface_end = surfaces["complete_source_surface_end"]
    if not 0 <= index_first < index_end <= surface_first < surface_end:
        raise ValueError("H1 original draw spans violate authored serializer order")
    if index_end - index_first != world["index_count"] * 2:
        raise ValueError("H1 decoded original index range is inconsistent with GfxWorld")
    if surface_end - surface_first != world["surface_count"] * H1_SURFACE_BYTES:
        raise ValueError("H1 decoded original surface extent is inconsistent with GfxWorld")
    blob = extract_source_window(ff, header, stream_class, index_first, surface_end)
    indices = blob[:index_end - index_first]
    surface_bytes = blob[surface_first - index_first:]
    sha = hashlib.sha256(indices).hexdigest()
    if sha != validated_indices.get("source_index_sha256"):
        raise ValueError("H1 original index bytes changed between independent source reads")
    return inspect_or_raise(indices, surface_bytes, world)


def inspect_or_raise(indices, surface_bytes, world):
    result = verify_array_draw_batches(
        indices, surface_bytes, world["vertex_count"], world["index_count"])
    if result["original_source_surfaces_preserved"] != world["surface_count"]:
        raise ValueError("H1 source surface count changed during batching")
    return result
