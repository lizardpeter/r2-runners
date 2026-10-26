#!/usr/bin/env python3
"""Exact-source H1 FastFile research probe for a private, networked CI runner.

Only reads original bytes; does not dump or publish proprietary source files.
Map names are parameters, not codec branches. Source files are kept in local
runner temporary storage during probing and cleaned by the runner afterward.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
from urllib.request import Request, urlopen
from urllib.parse import quote
from mwr_h1_asset_directory import inspect_prefix
from mwr_h1_asset_runs import AssetRunScanner
from mwr_h1_image_streams import analyze_stream_table
from mwr_h1_gfxworld_probe import GfxWorldCandidateScanner
from mwr_h1_world_geometry_root import GfxWorldGeometryScanner
from mwr_h1_world_vertex_probe import WorldVertexRunScanner
from mwr_h1_world_vertex_verify import verify_source_vertex_array
from mwr_h1_index_candidate_probe import probe_original_index_array
from mwr_h1_surface_probe import H1SurfaceSourceScanner
from mwr_h1_surface_verify import verify_source_surface_array
from mwr_h1_index_surface_verify import verify_original_index_bytes
from mwr_h1_static_models_probe import H1StaticModelDrawScanner
from mwr_h1_asset_body_probe import H1TypedBodyScanner
from mwr_h1_static_model_window_verify import inspect_retained_draw_window
from mwr_h1_material_window_probe import inspect_material_source_windows
from mwr_h1_dxbc_probe import H1DXBCSourceScanner
from mwr_h1_dxbc_verify import verify_retail_dxbc_samples
from mwr_h1_clipmap_named_scanner import H1NamedClipMapScanner
from mwr_h1_shader_ownership_probe import verify_dxbc_shader_ownership_windows

CHUNK = 1 << 20
# The research target is selected by --stem; never embed map-specific codec paths.
AUTH_REGION = 0x8000
MAX_STREAM_ROWS = 262_144


def download(base: str, key: str, root: Path) -> tuple[Path, str]:
    assert ".." not in key.split("/") and key and not key.startswith("/")
    url = base.rstrip("/") + "/" + quote(key, safe="/")
    destination = root.joinpath(*key.split("/"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with urlopen(Request(url, headers={"User-Agent": "Rust-test-MWR-retail-probe/1.0",
                                      "Accept-Encoding": "identity"}), timeout=180) as response:
        if response.url.split("/", 3)[:3] != url.split("/", 3)[:3]:
            raise ValueError("Unexpected redirect outside the original source origin")
        with destination.open("wb") as f:
            while True:
                data = response.read(CHUNK)
                if not data:
                    break
                digest.update(data)
                f.write(data)
    return destination, digest.hexdigest()


def probe_header(file: Path) -> dict:
    actual = file.stat().st_size
    with file.open("rb") as f:
        prefix = f.read(28)
        if len(prefix) < 28:
            raise ValueError(f"{file.name}: truncated H1 header")
        magic, version, _misc, _time, rows = struct.unpack("<8sI4s8sI", prefix)
        if magic not in (b"S1ff0100", b"S1ffu100"):
            raise ValueError(f"{file.name}: unsupported magic {magic!r}")
        if version != 0x42:
            raise ValueError(f"{file.name}: H1 version {version:#x} differs from verified 0x42")
        if rows > MAX_STREAM_ROWS:
            raise ValueError(f"{file.name}: unbounded stream row count {rows}")
        offsets = 28 + rows * 24
        f.seek(offsets)
        sizes = f.read(16)
        if len(sizes) < 16:
            raise ValueError(f"{file.name}: truncated size pair")
        base_size, total_size = struct.unpack("<QQ", sizes)
        auth_offset = offsets + 16
        signed = magic == b"S1ff0100"
        f.seek(auth_offset)
        auth_magic = f.read(8) if signed else b""
        if signed and auth_magic != b"S1ffs100":
            raise ValueError(f"{file.name}: incorrect signed auth marker {auth_magic!r} at {auth_offset:#x}")
        if base_size != actual:
            raise ValueError(f"{file.name}: base size {base_size} != original file size {actual}")
        if total_size < base_size:
            raise ValueError(f"{file.name}: total size smaller than base")
        potential_stream = auth_offset + (AUTH_REGION if signed else 0)
        f.seek(potential_stream)
        payload_head = f.read(128)
        data = {
            "magic": magic.decode(), "version": version,
            "header_flags_raw_hex": _misc.hex(),
            "rows": rows, "actual_bytes": actual,
            "base_file_len": base_size, "total_file_len": total_size,
            "auth_offset": auth_offset, "auth_magic": auth_magic.decode() if signed else None,
            "candidate_stream_offset": potential_stream,
            "candidate_stream_prefix_hex": payload_head[:64].hex(" "),
            "candidate_stream_u32": struct.unpack("<8I",payload_head[:32]) if len(payload_head) >= 32 else [],
        }
        # The following is only a candidate LZ4 framing test. The signed
        # hash-block layout and compression header must be verified per source.
        if len(payload_head) >= 4:
            blocks = struct.unpack_from("<I", payload_head, 0)[0]
            data["candidate_lz4_block_count"] = blocks
        return data


def scan_lz4_first_block(file: Path, potential_stream: int) -> dict:
    try:
        import lz4.block
    except ImportError:
        return {"status": "lz4_library_unavailable"}
    with file.open("rb") as f:
        f.seek(potential_stream)
        sample = f.read(min(2 * 1024 * 1024, file.stat().st_size-potential_stream))
    results = []
    # Various signed S1 variants place a block-count and tiny preamble
    # before [compressed length, uncompressed length, LZ4 bytes].
    for offset in range(0, min(8192,len(sample)-8), 2):
        compressed, decompressed = struct.unpack_from("<II",sample,offset)
        if not (8 <= compressed <= 1024*1024 and 8 <= decompressed <= 16*1024*1024):
            continue
        if offset + 8 + compressed > len(sample):
            continue
        packed = sample[offset+8:offset+8+compressed]
        try:
            raw = lz4.block.decompress(packed, uncompressed_size=decompressed)
        except Exception:  # Native lz4.block.LZ4BlockError is not a RuntimeError
            continue
        if len(raw)==decompressed:
            results.append({
                "relative_header_offset":offset,
                "compressed_bytes":compressed,
                "decompressed_bytes":decompressed,
                "decoded_prefix_hex":raw[:48].hex(" "),
                "decoded_ascii_preview":"".join(chr(c) if 32<=c<127 else "." for c in raw[:48]),
            })
            if len(results)>=3:
                break
    return {"status":"matching_candidate" if results else "no_candidate_yet","candidates":results}



class LogicalSignedStream:
    """Read signed H1 stream excluding 16KiB auth hash chunks every 8MiB."""
    DATA_SPAN = 0x800000
    HASH_SPAN = 0x4000

    def __init__(self, file, origin: int):
        self.file = file
        self.origin = origin
        self.logical = 0

    def read(self, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining:
            group, within = divmod(self.logical, self.DATA_SPAN)
            physical = self.origin + self.logical + group * self.HASH_SPAN
            usable = min(remaining, self.DATA_SPAN-within)
            self.file.seek(physical)
            data = self.file.read(usable)
            if len(data) != usable:
                raise EOFError(f"signed stream truncated at logical offset {self.logical:#x}")
            chunks.append(data)
            self.logical += usable
            remaining -= usable
        return b"".join(chunks)

    def align4(self) -> None:
        padding = (-self.logical) & 3
        if padding:
            self.read(padding)


def decode_lz4_zone(file: Path, header: dict, analyze_directory=False, gfx_stem=None,
                    inspect_typed_assets=False) -> dict:
    """Bounded, streaming H1 decompression; never writes decoded retail assets."""
    import lz4.block
    with file.open("rb") as f:
        stream = LogicalSignedStream(f, header["candidate_stream_offset"])
        prologue = stream.read(12)
        expected_bytes, flags = struct.unpack("<QI",prologue)
        if expected_bytes <= 0 or expected_bytes > 8*1024**3:
            raise ValueError(f"implausible decoded zone size: {expected_bytes}")
        if flags != 0x04010000:
            raise ValueError(f"unknown H1 LZ4 stream flags {flags:#x}")
        count = 0
        decoded = 0
        digest = hashlib.sha256()
        leading = b""
        sample = bytearray()
        asset_scanner = AssetRunScanner() if analyze_directory else None
        gfx_scanner = GfxWorldCandidateScanner(gfx_stem) if gfx_stem is not None else None
        geometry_scanner=GfxWorldGeometryScanner() if gfx_stem is not None else None
        vertex_scanner=WorldVertexRunScanner() if gfx_stem is not None else None
        surface_scanner=H1SurfaceSourceScanner() if gfx_stem is not None else None
        static_draw_scanner=H1StaticModelDrawScanner() if gfx_stem is not None else None
        typed_asset_scanner=H1TypedBodyScanner() if (gfx_stem is not None or inspect_typed_assets) else None
        dxbc_scanner=H1DXBCSourceScanner() if inspect_typed_assets else None
        named_clipmap_scanner=H1NamedClipMapScanner() if gfx_stem is not None else None
        while decoded < expected_bytes:
            if count >= 200_000:
                raise ValueError("H1 exceeds maximum block count")
            compressed, raw_size = struct.unpack("<II",stream.read(8))
            if compressed == 0 or compressed > 8*1024**2:
                raise ValueError(f"block {count} invalid compressed length {compressed} at {stream.logical:#x}")
            if raw_size == 0 or raw_size > 1024**2:
                raise ValueError(f"block {count} invalid uncompressed length {raw_size}")
            block = stream.read(compressed)
            raw = lz4.block.decompress(block, uncompressed_size=raw_size)
            if len(raw) != raw_size or decoded + raw_size > expected_bytes:
                raise ValueError(f"block {count} decoded length mismatch")
            if not leading:
                leading=raw[:144]
            if analyze_directory and len(sample) < 2*1024*1024:
                sample.extend(raw[:2*1024*1024-len(sample)])
            if asset_scanner is not None:
                asset_scanner.push(raw)
            if gfx_scanner is not None:
                gfx_scanner.push(raw)
            if geometry_scanner is not None:
                geometry_scanner.push(raw)
            if vertex_scanner is not None:
                vertex_scanner.push(raw)
            if surface_scanner is not None:
                roots=list(geometry_scanner.hits.values())
                if len(roots)==1 and surface_scanner.expected_surface_count is None:
                    surface_scanner.bind_root(roots[0])
                surface_scanner.push(raw)
            if static_draw_scanner is not None:
                roots=list(geometry_scanner.hits.values())
                if len(roots)==1 and static_draw_scanner.expected_count is None:
                    static_draw_scanner.bind_root(roots[0])
                static_draw_scanner.push(raw)
            if typed_asset_scanner is not None:
                typed_asset_scanner.push(raw)
            if dxbc_scanner is not None:
                dxbc_scanner.push(raw)
            if named_clipmap_scanner is not None:
                named_clipmap_scanner.push(raw)
            digest.update(raw)
            decoded += raw_size
            count += 1
            stream.align4()
        if decoded != expected_bytes:
            raise ValueError(f"partial H1 decode {decoded}/{expected_bytes}")
        result = {
            "status":"full_zone_decoded",
            "decoded_bytes":decoded,
            "block_count":count,
            "logical_stream_bytes_used":stream.logical,
            "decoded_sha256":digest.hexdigest(),
            "decoded_header_first144_hex":leading.hex(" "),
            "xfile_header_u64":list(struct.unpack("<9Q",leading[:72])) if len(leading)>=72 else [],
            "xfile_payload_len_matches":(struct.unpack_from("<Q",leading,0)[0]+72==decoded) if len(leading)>=72 else False,
        }
        if gfx_scanner is not None:
            result["gfxworld_source_scan"]=gfx_scanner.report()
            geometry=geometry_scanner.report()
            result["gfxworld_geometry_source_root_scan"]=geometry
            roots=geometry["candidates"]
            if len(roots)==1:
                vertex_scanner.expected_count=roots[0]["vertex_count"]
            result["gfxworld_vertex_source_candidate_scan"]=vertex_scanner.report()
            result["gfxworld_surface_source_candidate_scan"]=surface_scanner.report()
            result["gfxworld_static_model_draw_source_scan"]=static_draw_scanner.report()

        if typed_asset_scanner is not None:
            result["typed_original_asset_body_source_scan"]=typed_asset_scanner.report()
        if dxbc_scanner is not None:
            result["original_DXBC_shader_bytecode_container_census"]=dxbc_scanner.report()
        if named_clipmap_scanner is not None:
            result["original_named_ClipMap_source_root_candidates"]=named_clipmap_scanner.report()
        if analyze_directory:
            result["asset_directory_evidence"] = inspect_prefix(bytes(sample))
            result["complete_zone_asset_run_scan"] = asset_scanner.report()
        return result

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--stem",default="mp_crash_snow")
    p.add_argument("--origin",default="https://r2.houseofkublai.com")
    p.add_argument("--r2-prefix",default="h1/h1_full_files/zone")
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--include-primary",action="store_true")
    p.add_argument("--full-decode",action="store_true")
    p.add_argument("--analyze-directory",action="store_true")
    p.add_argument("--probe-gfxworld",action="store_true")
    p.add_argument("--report",type=Path,required=True)
    args=p.parse_args()
    stem=args.stem
    if not stem.startswith("mp_") or not stem.replace("_","").isalnum():
        p.error("stem must be a simple mp_* identifier")
    files=[f"{stem}_load.ff",f"{stem}_path.ff",f"patch_{stem}.ff",
           f"english/eng_{stem}.ff",f"english/eng_patch_{stem}.ff",
           f"techsets_{stem}.ff"]
    if args.include_primary:
        files.insert(0,f"{stem}.ff")
    objects={}
    for name in files:
        key=f"{args.r2_prefix.rstrip('/')}/{name}"
        try:
            local,sha=download(args.origin,key,args.output_dir)
            header=probe_header(local)
            header["sha256"]=sha
            if header["rows"]>0:
                header["streamed_image_table_evidence"]=analyze_stream_table(local)
            # Probe the main and smaller path archive with real raw LZ4
            # candidates, but never claim decompression success without bytes.
            if name in (f"{stem}.ff",f"{stem}_path.ff"):
                header["lz4_probe"]=scan_lz4_first_block(local,header["candidate_stream_offset"])
            if args.full_decode:
                try:
                    header["whole_zone_decode"]=decode_lz4_zone(
                        local,header,args.analyze_directory,
                        stem if args.probe_gfxworld and name==f"{stem}.ff" else None,
                        inspect_typed_assets=(name==f"techsets_{stem}.ff"))
                    if name==f"techsets_{stem}.ff":
                        dxbc=header["whole_zone_decode"].get(
                            "original_DXBC_shader_bytecode_container_census",{})
                        header["whole_zone_decode"]["verified_source_shader_DXBC_samples"]=(
                            verify_retail_dxbc_samples(
                                local,header,LogicalSignedStream,dxbc))
                        header["whole_zone_decode"]["original_shader_source_header_linkage_probe"]=(
                            verify_dxbc_shader_ownership_windows(
                                local,header,LogicalSignedStream,dxbc))
                        typed=header["whole_zone_decode"].get(
                            "typed_original_asset_body_source_scan",{})
                        samples=typed.get("candidates",{}).get("material",{}).get("first_30",[])
                        header["whole_zone_decode"]["original_material_texture_source_windows"]=(
                            inspect_material_source_windows(
                                local,header,LogicalSignedStream,samples))
                    if args.probe_gfxworld and name==f"{stem}.ff":
                        scanned=header["whole_zone_decode"]
                        roots=scanned["gfxworld_geometry_source_root_scan"]["candidates"]
                        if len(roots)==1:
                            scanned["world_vertex_exact_window_verification"]=verify_source_vertex_array(
                                local,header,LogicalSignedStream,
                                scanned["gfxworld_vertex_source_candidate_scan"],
                                roots[0]["vertex_count"])
                            checked=scanned["world_vertex_exact_window_verification"]
                            if checked.get("status")=="complete":
                                scanned["world_index_source_order_candidates"]=probe_original_index_array(
                                    local,header,LogicalSignedStream,checked,roots[0])
                            scanned["world_surface_exact_window_verification"]=verify_source_surface_array(
                                local,header,LogicalSignedStream,
                                scanned["gfxworld_surface_source_candidate_scan"],roots[0],
                                scanned["xfile_header_u64"][2:])
                            surfaces=scanned["world_surface_exact_window_verification"]
                            if checked.get("status")=="complete" and surfaces.get("status")=="complete_original_surface_struct_array_verified":
                                scanned["world_index_all_surfaces_linked_verification"]=verify_original_index_bytes(
                                    local,header,LogicalSignedStream,roots[0],checked,surfaces)
                            scanned["original_static_draw_full_count_followup"]=inspect_retained_draw_window(
                                local,header,LogicalSignedStream,roots[0],
                                scanned["gfxworld_static_model_draw_source_scan"])
                except Exception as exc:
                    header["whole_zone_decode"]={"status":"failed","reason":str(exc)}
                    print(f"H1 full decode not yet validated for {name}: {exc}",file=sys.stderr,flush=True)
            objects[name]=header
            print(f"{name} {header['actual_bytes']} bytes sha256={sha} "
                  f"magic={header['magic']} version={header['version']:#x} "
                  f"stream_rows={header['rows']} candidate={header['candidate_stream_offset']:#x}",flush=True)
        except Exception as exc:
            objects[name]={"ERROR":str(exc)}
            print(f"FAILED {name}: {exc}",file=sys.stderr,flush=True)
    report={"game":"MWR/H1","source_stem":stem,
            "file_count":len(files),"source_files":objects}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+"\n")
    return 1 if any("ERROR" in v or (args.full_decode and v.get("whole_zone_decode",{}).get("status") != "full_zone_decoded") for v in objects.values()) else 0

if __name__=="__main__":
    sys.exit(main())
