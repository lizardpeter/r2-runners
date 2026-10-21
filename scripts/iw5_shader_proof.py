#!/usr/bin/env python3
"""Audit actual retail IW5 shader bytecode and CTAB bindings.

The only accepted input is the *original* 256 KiB signed IW5 source
sample from the isolated R2 runner. Every complete source block is SHA256
checked against the source-owned master BEFORE inflation. No synthetic,
name-inferred, or reauthored shader bytecode is counted.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import zlib

SOURCE_NAME = "10_pluto_iw5_full_game_zone_dlc_mp_aground_ss.ff"
BLOCK = 8192
RETAIL_NAMES = re.compile(rb'([a-zA-Z0-9_,/$.-]{5,160}\.hlsl)\x00')
D3D9_VERSIONS = {0xfffe0300: "vertex", 0xffff0300: "pixel"}
MAX_SHADER_BYTES = 2 * 1024 * 1024

def word(b, pos):
    if pos + 4 > len(b):
        raise ValueError(f"truncated original source DWORD at {pos}")
    return struct.unpack_from("<I", b, pos)[0]

def original_verified_prefix(path):
    source = path.read_bytes()
    if source[:8] != b"IWff0100" or word(source,8) != 1 or source[21:29] != b"IWffs100":
        raise ValueError("original IW5 signed source header mismatch")
    master = source[21+BLOCK:21+2*BLOCK]
    data_at = 21+2*BLOCK
    checked = 0
    compressed = bytearray()
    for n in range(BLOCK//32):
        data = source[data_at+n*BLOCK:data_at+(n+1)*BLOCK]
        if len(data) < BLOCK:
            break
        if hashlib.sha256(data).digest() != master[n*32:(n+1)*32]:
            raise ValueError("original IW5 source SHA256 mismatch at block "+str(n))
        compressed.extend(data)
        checked += 1
    if checked == 0:
        raise ValueError("source has no authenticated blocks")
    z = zlib.decompressobj()
    decoded = z.decompress(bytes(compressed), 16 * 1024 * 1024)
    if len(decoded) <= 100_000:
        raise ValueError("source decoded prefix unexpectedly small")
    return decoded,checked

def shader_end(buf, pos):
    cursor = pos + 4
    while cursor+4 <= len(buf) and cursor-pos <= MAX_SHADER_BYTES:
        token = word(buf,cursor)
        if token == 0xffff:
            return cursor+4
        opcode = token & 0xffff
        count = (token>>16)&0x7fff if opcode == 0xfffe else (token>>24)&15
        cursor += (count+1)*4
    raise ValueError("source shader stream truncated or exceeds bound")

def ctab_bindings(shader):
    if len(shader)<12 or (word(shader,4)&0xffff)!=0xfffe or shader[8:12]!=b"CTAB":
        return None
    comment_words = (word(shader,4)>>16)&0x7fff
    cap = 8+4*comment_words
    base = 12
    if cap>len(shader):
        raise ValueError("source D3D9 shader CTAB comment truncated")
    size,creator,version,entries,info,flags,target = struct.unpack_from("<7I",shader,base)
    if size!=28 or version!=word(shader,0) or entries>512 or base+info+entries*20>cap:
        raise ValueError("D3D9 source CTAB header/cap mismatch")
    def string_at(off):
        start=base+off
        end=shader.find(b"\x00",start,min(start+8192,cap))
        if end<0:
            raise ValueError("source CTAB string is truncated")
        return shader[start:end].decode("latin-1")
    bindings=[]
    for n in range(entries):
        name,regset,index,count,res,type_info,default=struct.unpack_from(
            "<IHHHHII",shader,base+info+20*n)
        if regset>3 or count==0: raise ValueError("source CTAB register invalid")
        bindings.append({"name":string_at(name),"register_set":regset,
                         "register":index,"register_count":count})
    return {"creator":string_at(creator),"target":string_at(target),
            "bindings":bindings}


# Exact opcode and register declaration acceptance survey for IW5's 1,021
# retail PC SM3 shader streams. All counts derive from SHA-256-authenticated
# source bytes, not shader names or the material PBR fallback.
IW5_RETAIL_OPS = {
    1: 1, 2: 2, 4: 3, 5: 2, 6: 1, 7: 1, 8: 2,
    9: 2, 11: 2, 14: 1, 15: 1, 18: 3, 19: 1,
    32: 2, 36: 1, 66: 2, 88: 3, 91: 1, 92: 1, 95: 2,
}
def retail_sm3_ir_survey(shader_bytes, stage):
    code=struct.unpack("<" + "I"*(len(shader_bytes)//4),shader_bytes)
    opcodes=collections.Counter()
    declaration_count=0
    sampler_dimensions=collections.Counter()
    defined_constants=0
    declared_samplers=set()
    read_samplers=set()
    i=1
    while i<len(code)-1:
        raw=code[i]
        opcode=raw & 65535
        if opcode==0xfffe:
            count=(raw>>16)&0x7fff
        else:
            count=(raw>>24)&15
            opcodes[opcode]+=1
        if i+1+count>len(code)-1:
            raise ValueError("IW5 source SM3 instruction exceeds shader end")
        args=code[i+1:i+1+count]
        if opcode==31:
            if count!=2:raise ValueError("D3D9 original DCL operands invalid")
            info,register=args
            typ=((register>>28)&7)|((register>>8)&24)
            index=register&0x7ff
            if typ==10:
                dimension=(info>>27)&15
                if dimension not in (2,3,4):
                    raise ValueError("IW5 original source sampler dimension unsupported")
                sampler_dimensions[{2:"2D",3:"Cube",4:"Volume"}[dimension]]+=1
                declared_samplers.add(index)
            declaration_count+=1
        elif opcode==81:
            if count!=5:
                raise ValueError("IW5 original DEF requires 4 literal DWORDs")
            defined_constants+=1
        elif opcode!=0xfffe:
            if opcode not in IW5_RETAIL_OPS or count!=IW5_RETAIL_OPS[opcode]+1:
                raise ValueError(f"unsupported original IW5 opcode {opcode}, length {count}")
            for index,parameter in enumerate(args):
                if not parameter&0x80000000:
                    raise ValueError("IW5 D3D9 parameter marker missing")
                register_type=((parameter>>28)&7)|((parameter>>8)&24)
                if register_type>18:
                    raise ValueError("IW5 source D3D9 unknown register type")
                if index!=0 and register_type==10:
                    read_samplers.add(parameter&0x7ff)
        i+=1+count
    if i!=len(code)-1:
        raise ValueError("IW5 original D3D9 source stream alignment mismatch")
    if not read_samplers.issubset(declared_samplers):
        raise ValueError("IW5 source shader sampled undeclared original sampler")
    return opcodes,declaration_count,sampler_dimensions,defined_constants,read_samplers

def inspect(buf):
    records=[]
    tally=collections.Counter()
    bindcount=collections.Counter()
    bindings_unique=set()
    no_ctab=[]
    truncated_at_end=[]
    all_original_opcodes=collections.Counter()
    source_sampler_shapes=collections.Counter()
    total_declarations=0
    total_source_definitions=0
    shader_sampler_use=0
    for match in RETAIL_NAMES.finditer(buf):
        offset=match.end()
        version=word(buf,offset) if offset+4<=len(buf) else None
        if version not in D3D9_VERSIONS: continue
        try:
            end=shader_end(buf,offset)
        except ValueError:
            # The artifact is an authenticated *prefix* of a much larger
            # signed multiplayer FastFile. A bytecode program clipped by
            # its final authenticated source block is not counted as full.
            if len(buf)-offset<8192:
                truncated_at_end.append(match.group(1).decode("ascii"))
                continue
            raise
        program=buf[offset:end]
        if word(program,len(program)-4)!=0xffff:
            raise ValueError("missing retail D3D9 END token")
        table=ctab_bindings(program)
        stage=D3D9_VERSIONS[version]
        native_ops,dcls,shapes,defs,sampled=retail_sm3_ir_survey(program,stage)
        all_original_opcodes.update(native_ops)
        source_sampler_shapes.update(shapes)
        total_declarations+=dcls
        total_source_definitions+=defs
        shader_sampler_use+=len(sampled)
        name=match.group(1).decode("ascii")
        if table is None:
            no_ctab.append(name)
        else:
            for item in table["bindings"]:
                key=(stage,item["name"],item["register_set"],item["register"])
                bindcount[key]+=1
                bindings_unique.add(key)
        tally[stage]+=1
        records.append({"name":name,"stage":stage,
                        "source_byte_offset":offset,"bytes":len(program),
                        "ctab_bindings":table["bindings"] if table else []})
    return {"source_shaders":len(records),"stage_counts":dict(tally),
            "total_source_program_bytes":sum(r["bytes"] for r in records),
            "source_instruction_count":sum(all_original_opcodes.values()),
            "source_opcode_histogram":dict(sorted(all_original_opcodes.items())),
            "source_declarations":total_declarations,
            "source_declared_sampler_dimensions":dict(source_sampler_shapes),
            "source_defined_float4_constants":total_source_definitions,
            "source_used_sampler_registers":shader_sampler_use,
            "total_ctab_bindings":sum(bindcount.values()),
            "unique_name_register_mappings":len(bindings_unique),
            "no_ctab_names":no_ctab,
            "source_prefix_truncated_shaders":truncated_at_end,
            "top_source_bindings":[{
                "stage":k[0],"name":k[1],"register_set":k[2],
                "register":k[3],"shader_count":v
                } for k,v in bindcount.most_common(80)],
            "examples":records[:5],
            "source_programs":records}

def main(samples,path):
    verified,checks=original_verified_prefix(samples/SOURCE_NAME)
    data=inspect(verified)
    data["sha256_source_blocks"]=checks
    if checks!=29 or data["source_shaders"]!=1021:
        raise ValueError("IW5 original shader bytecode sample count mismatch")
    if len(data["source_prefix_truncated_shaders"])!=1:
        raise ValueError("IW5 original signed shader source truncation boundary changed")
    if data["stage_counts"]!={"pixel":768,"vertex":253}:
        raise ValueError("IW5 original source shader stage counts mismatch")
    if data["total_ctab_bindings"]!=15626 or data["unique_name_register_mappings"]!=110:
        raise ValueError("IW5 retail D3D9 CTAB source binding coverage regression")
    if data["source_instruction_count"]!=88902 or data["source_declarations"]!=13014:
        raise ValueError("IW5 original native D3D9 instruction census regression")
    if set(map(int,data["source_opcode_histogram"]))!=set(IW5_RETAIL_OPS)|{31,81}:
        raise ValueError("IW5 native SM3 22-opcode source coverage changed")
    if data["source_declared_sampler_dimensions"]!={"2D":3303,"Cube":370,"Volume":718}:
        raise ValueError("IW5 original source sampler shape census regression")
    data["source"] = SOURCE_NAME
    path.mkdir(parents=True,exist_ok=True)
    (path/"iw5_original_shader_bindings.json").write_text(
        json.dumps(data,indent=2)+"\n")
    print(json.dumps({key:value for key,value in data.items()
                      if key!="source_programs"},indent=2))
    print("PASS: exact retail shader bytes and all CTAB register bindings")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--samples",type=pathlib.Path,required=True)
    parser.add_argument("--out",type=pathlib.Path,required=True)
    args=parser.parse_args()
    main(args.samples,args.out)
