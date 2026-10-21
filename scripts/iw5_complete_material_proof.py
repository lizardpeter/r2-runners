#!/usr/bin/env python3
"""Byte-exact IW5 PC retail material fixture from an ORIGINAL complete FF.

This is an isolated validation fixture for the SINGLE generic MW3 importer,
not another production importer or an in-game fallback. Fixed offsets below
are intentionally pinned to the SHA256 hash of this one original complete
FastFile. Production Rust code accepts arbitrary IW5 Material structures.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import zlib

FILENAME="02_pluto_iw5_full_game_zone_dlc_english_so_coop_vlad_ep01.ff"
SOURCE_SHA="ad3697e0174dc77db164eb5e0187fa369d8a014eb3a4c5b0d8a0201637f79c12"
XFILE_SHA="049677a6da32c5a9804c24889abfa90723109f0034267b9bb64a78f253645e46"
INLINE=0xffffffff
MAT=46145
TECH=45218
VS=45356
PS=45860
MAT_NAME=b"hud_fofbox_self_sp"
IMAGE_NAME=b"friendorfoe_self_sp"

def require(test,message):
    if not test:raise ValueError("Retail IW5 material proof: "+message)

def word(blob,at):
    return struct.unpack_from("<I",blob,at)[0]

def checked_name(blob,at,name):
    require(blob[at:at+len(name)+1]==name+b"\x00",
            f"expected original name {name!r} at source byte {at}")

def shader_audit(blob,at,expected_stage,expected_dwords):
    # Real IW5 Material{Vertex,Pixel}Shader 32-bit layout:
    # name ptr, runtime D3D handle, source data ptr, u16 DWORD count,
    # u16 loadForRenderer.
    header=struct.unpack_from("<IIIHH",blob,at)
    require(header[1]==0 and header[2]==INLINE,
            "original compiled shader program must be inline")
    require(header[3]==expected_dwords and header[4]==0,
            "original shader program DWORD size")
    if expected_stage=="vertex":
        require(header[0]==INLINE,"original vertex shader source name inline")
        checked_name(blob,at+16,b"trivial_vertcol_simple.hlsl")
        program_at=at+16+len(b"trivial_vertcol_simple.hlsl")+1
    else:
        require(header[0]==0x3000a43b,"original pixel shader name packed reference")
        program_at=at+16
    shader=blob[program_at:program_at+expected_dwords*4]
    require(len(shader)==expected_dwords*4 and
            word(shader,0)==({"vertex":0xfffe0300,"pixel":0xffff0300}[expected_stage])
            and word(shader,len(shader)-4)==65535,
            "original compiled D3D9 bytecode version and END tokens")
    n=1
    ops={}
    declarations=[]
    while n<len(shader)//4-1:
        token=word(shader,n*4)
        kind=token&65535
        count=(token>>16)&32767 if kind==65534 else (token>>24)&15
        if kind!=65534:
            ops[str(kind)]=ops.get(str(kind),0)+1
            if kind==31:
                require(count==2,"source D3D9 declaration operand count")
                declarations.append(struct.unpack_from("<II",shader,(n+1)*4))
        n+=count+1
    require(n==len(shader)//4-1,"source shader instruction stream alignment")
    return {"stage":expected_stage,"dwords":expected_dwords,
            "program_byte_offset":program_at,"shader_sha256":hashlib.sha256(shader).hexdigest(),
            "opcodes":ops,
            "source_dcl_registers":[[hex(a),hex(b)] for a,b in declarations]}

def verify(source_path):
    original=source_path.read_bytes()
    require(hashlib.sha256(original).hexdigest()==SOURCE_SHA,
            "retail FF provenance SHA256 differs")
    require(original[:8]==b"IWffu100" and word(original,8)==1,
            "unsigned original retail FastFile magic/version")
    inflated=zlib.decompress(original[21:])
    require(hashlib.sha256(inflated).hexdigest()==XFILE_SHA,
            "retail XFile decompression/CRC mismatch")
    require(word(inflated,0)==len(inflated)-44,
            "original XFile size mismatch")
    require(word(inflated,52)==296 and word(inflated,56)==INLINE,
            "original XAsset directory changed")
    end=60+296*8
    types=[word(inflated,60+i*8) for i in range(296)]
    require(types[-3:]==[9,5,38] and
            (types.count(9),types.count(5),types.count(38))==(1,1,1),
            "original technique/material/raw asset directory order changed")
    require(all(word(inflated,60+i*8+4)==INLINE for i in range(293,296)),
            "original final asset source pointers are not inline")
    # First and only original render technique in this short source zone.
    require(struct.unpack_from("<IHH",inflated,TECH)==(INLINE,0,1),
            "original MaterialTechnique header incorrect")
    vdecl,vs,ps,perprim,perobj,stable,custom,arguments=struct.unpack_from(
        "<III4BI",inflated,TECH+8)
    require((vdecl,vs,ps,arguments)==(INLINE,)*4 and
            (perprim,perobj,stable,custom)==(1,1,1,0),
            "original source VS/PS/declaration/argument pointers changed")
    decl=inflated[TECH+28:TECH+28+100]
    require(len(decl)==100 and
            struct.unpack_from("<I",decl)[0]==INLINE
            and tuple(decl[4:6])==(3,0)
            and decl[8:14]==bytes([0,0,1,2,2,5]),
            "original vertex stream routing not POSITION/COLOR/UV0")
    checked_name(inflated,45346,b"ppcc0t0t0")
    vsdata=shader_audit(inflated,VS,"vertex",115)
    psdata=shader_audit(inflated,PS,"pixel",55)
    arguments=[
        struct.unpack_from("<HHI",inflated,46096+i*8)
        for i in range(3)
    ]
    require(arguments==[
        (4,4,0x0400006a),(4,0,0x0400005e),(3,0,0xa0ab1041)],
        "retail MaterialShaderArgument constants and pixel texture binding changed")
    checked_name(inflated,46120,b"trivial_vertcol_simple2d")
    # 104-byte original Material root, including 24-byte MaterialInfo, 54
    # source stateBitsEntry bytes, five one-byte counters, 1 padding byte,
    # and five 32-bit source pointers (last pointer at byte100).
    mat=inflated[MAT:MAT+104]
    require(len(mat)==104 and word(mat,0)==INLINE,
            "original 104-byte Material root missing")
    counts=tuple(mat[78:83])
    require(counts==(1,0,1,3,4),
            "original material counters and flags differ")
    technique_pointer,table_pointer,constant_pointer,state_pointer,sub_pointer=struct.unpack_from(
        "<5I",mat,84)
    require((technique_pointer,table_pointer,constant_pointer,state_pointer,sub_pointer)
            ==(0x3000092d,INLINE,0,INLINE,0),
            "source material technique/texture/state pointer identities changed")
    checked_name(inflated,MAT+104,MAT_NAME)
    texture_off=MAT+104+len(MAT_NAME)+1
    namehash,first,last,sampler,semantic,image_pointer=struct.unpack_from(
        "<IBBBBI",inflated,texture_off)
    require((namehash,first,last,sampler,semantic,image_pointer)
            ==(0xa0ab1041,ord('c'),ord('p'),0xe2,0,INLINE),
            "original colorMap texture hash/sampler/inline GfxImage mismatch")
    image_off=texture_off+12
    require(word(inflated,image_off)==0xfffffffe,
            "retail GfxImage source pointer insertion sentinel differs")
    image=inflated[image_off:image_off+32]
    require((image[4],image[5],image[6],image[7])==(3,0,3,2)
            and struct.unpack_from("<HHH",image,20)==(32,32,1)
            and word(image,28)==INLINE,
            "original GfxImage 32x32 2D source header differs")
    checked_name(inflated,image_off+32,IMAGE_NAME)
    load_off=image_off+32+len(IMAGE_NAME)+1
    level,flags,d3d_format,resource_bytes=struct.unpack_from("<Iiii",inflated,load_off)
    require(level==1 and flags==2 and d3d_format==int.from_bytes(b"DXT3","little")
            and resource_bytes==0,
            "original DXT3 image is external/zero inline bytes")
    state_off=load_off+16
    state=struct.unpack_from("<II",inflated,state_off)
    require(state==(0x18259125,0xe00e0002),
            "original source fixed state bits not retained")
    return {
        "source_file":source_path.name,"source_sha256":SOURCE_SHA,
        "xfile_bytes":len(inflated),
        "source_zone_has_complete_material_and_shaders":True,
        "original_material_name":MAT_NAME.decode(),"material_struct_bytes":104,
        "original_material_technique_pointer":hex(technique_pointer),
        "technique":"trivial_vertcol_simple2d",
        "vertex_declaration":"ppcc0t0t0",
        "vertex_stream_routes":[["position","position"],["color","color0"],
                                ["texcoord0","texcoord0"]],
        "original_vertex_shader":vsdata,"original_pixel_shader":psdata,
        "original_pass_shader_arguments":[
            {"type":a,"destination":b,"source_value":hex(c)} for a,b,c in arguments],
        "original_source_material_texture":{
            "name_hash":hex(namehash),"name_start":"c","name_end":"p",
            "semantic":semantic,"sampler_byte":hex(sampler),
            "image_name":IMAGE_NAME.decode(),"image_size":[32,32],
            "image_format":"DXT3","inline_image_bytes":0,
            "external_iwd_needed_for_pixels":True,
        },
        "original_fixed_function_state_words":[hex(x) for x in state],
    }
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--samples",type=pathlib.Path,required=True)
    p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args()
    result=verify(a.samples/FILENAME)
    a.out.mkdir(parents=True,exist_ok=True)
    (a.out/"iw5_complete_original_material_proof.json").write_text(
        json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    print("PASS original 104-byte material, two complete shaders, exact texture and render state")

if __name__=="__main__":
    main()
