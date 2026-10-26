"""Source-window-safe H1 original DXBC shader bytecode header census.

Scans actual decompressed signed FastFile bytes for DXBC container signatures
and verifies the D3D11 container header, count and chunk-offset bounds.
This is source bytecode evidence, NOT an H1 MaterialPass/Technique alias or
an executable Vulkan shader translation. No bytecode is printed or uploaded.
"""
import struct

MAGIC=b"DXBC"
MAX_PROGRAM=16*1024*1024
HEADER_MIN=32
CARRY=2048

class H1DXBCSourceScanner:
    def __init__(self):
        self.decoded_bytes=0
        self.carry=b""
        self.candidates={}
        self.total_magic_hits=0

    @staticmethod
    def probe(blob,at):
        if at<0 or at+HEADER_MIN>len(blob):
            return None
        if blob[at:at+4]!=MAGIC:
            return None
        one,size,chunks=struct.unpack_from("<III",blob,at+20)
        if one!=1 or not (HEADER_MIN<=size<=MAX_PROGRAM) or not (1<=chunks<=256):
            return None
        header_bytes=32+4*chunks
        if size<header_bytes or at+header_bytes>len(blob):
            return None
        offsets=struct.unpack_from("<"+str(chunks)+"I",blob,at+32)
        if any(o<header_bytes or o+8>size for o in offsets):
            return None
        # Source bytes after the header are likely available at the first
        # chunk start; use its FourCC only as a source observation.
        first=at+offsets[0]
        chunk_name=None
        if first+4<=len(blob):
            candidate=blob[first:first+4]
            if all(32<=v<127 for v in candidate):
                chunk_name=candidate.decode("ascii")
        return {"declared_shader_container_bytes":size,
                "source_chunk_count":chunks,
                "first_source_chunk_type":chunk_name}

    def push(self,chunk):
        blob=self.carry+chunk
        base=self.decoded_bytes-len(self.carry)
        start=0
        while True:
            hit=blob.find(MAGIC,start)
            if hit<0:break
            start=hit+4
            at=base+hit
            if at<0:continue
            self.total_magic_hits+=1
            finding=self.probe(blob,hit)
            if finding is not None:
                self.candidates[at]=finding
        self.decoded_bytes+=len(chunk)
        self.carry=blob[-CARRY:]

    def report(self):
        return {
            "status":"DXBC_source_container_headers_not_shader_asset_aliases",
            "decoded_bytes_scanned":self.decoded_bytes,
            "fourcc_source_hits":self.total_magic_hits,
            "source_header_verified_candidates":len(self.candidates),
            "first_24_source_headers":[{"source_offset":at,**entry}
              for at,entry in sorted(self.candidates.items())[:24]],
            "WARNING":"Requires authentic MaterialPass compiled shader pointer resolution, bytecode container completeness and shader-stage matching.",
        }
