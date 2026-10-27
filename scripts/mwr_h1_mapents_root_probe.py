"""Scan native H1 0x128 MapEnts source body candidates in signed retail streams.

This is not XAsset ownership or gameplay spawn admission. The sole original
XAsset type-29 record, if present, is only a count/type guard; serializer
placement, alias relocation and source spawn semantics need separate proof.
No entity text or retail bytes are uploaded to logs/artifacts.
"""
import struct

ROOT_SIZE = 0x128
INLINE = 0xFDFDFDFFFFFFFFFF
SHARED = 0xFDFDFDFFFFFFFFFE
MAX_NAME = 256
CARRY = ROOT_SIZE + MAX_NAME + 16
MARKER = struct.pack("<Q", INLINE)


def pointer_class(raw):
    if raw == 0:
        return "null"
    if raw == INLINE:
        return "inline_owned"
    if raw == SHARED:
        return "inline_shared"
    if 0xFDFDFDF0 <= raw >> 32 <= 0xFDFDFDF6:
        return "virtual_block_candidate"
    return "unrecognized"


def source_mapents_candidate(blob, at):
    if at < 0 or at + ROOT_SIZE + 8 > len(blob):
        return None
    if struct.unpack_from("<Q", blob, at)[0] != INLINE:
        return None
    entity_ptr = struct.unpack_from("<Q", blob, at + 8)[0]
    entity_bytes = struct.unpack_from("<I", blob, at + 16)[0]
    spawn_count = struct.unpack_from("<H", blob, at + 264)[0]
    spawn_ptr = struct.unpack_from("<Q", blob, at + 272)[0]
    if not 0 < entity_bytes <= 64 * 1024 * 1024:
        return None
    if not 0 <= spawn_count <= 16384:
        return None
    if pointer_class(entity_ptr) == "unrecognized" or entity_ptr == 0:
        return None
    if pointer_class(spawn_ptr) == "unrecognized":
        return None
    if spawn_count and spawn_ptr == 0:
        return None
    tail = blob[at + ROOT_SIZE:at + ROOT_SIZE + MAX_NAME + 1]
    end = tail.find(b"\0")
    if not 3 <= end <= MAX_NAME:
        return None
    raw = tail[:end]
    if not all(32 <= b < 127 for b in raw):
        return None
    name = raw.decode("ascii")
    # The source name qualifies this as a native H1 MapEnts candidate;
    # a name alone never proves the XAssetList's actual type-29 owner.
    if not name.startswith("maps/") and not name.endswith(".d3dbsp"):
        return None
    return {
        "original_name": name,
        "source_native_root_bytes": ROOT_SIZE,
        "declared_entity_text_bytes": entity_bytes,
        "entity_text_pointer_kind": pointer_class(entity_ptr),
        "source_spawn_record_count": spawn_count,
        "source_spawn_record_pointer_kind": pointer_class(spawn_ptr),
        "source_name_end_relative_to_root": ROOT_SIZE + end + 1,
        "not_authenticated_as_type29_XAsset_owner": True,
    }


class H1MapEntsBodyScanner:
    def __init__(self):
        self.decoded = 0
        self.carry = b""
        self.hits = {}

    def push(self, chunk):
        blob = self.carry + chunk
        base = self.decoded - len(self.carry)
        cursor = 0
        while True:
            at = blob.find(MARKER, cursor)
            if at < 0:
                break
            cursor = at + 1
            found = source_mapents_candidate(blob, at)
            if found is not None and base + at >= 0:
                self.hits[base + at] = found
        self.decoded += len(chunk)
        self.carry = blob[-CARRY:]

    def report(self):
        hits = sorted(self.hits.items())
        return {
            "status": "structural_H1_MapEnts_roots_only_not_XAsset_owned",
            "original_decoded_bytes_scanned": self.decoded,
            "source_structural_candidate_count": len(hits),
            "first_16": [{"original_source_offset": at, **details}
                         for at, details in hits[:16]],
            "original_entity_and_spawn_payloads_not_admitted": True,
        }
