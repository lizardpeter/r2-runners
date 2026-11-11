#!/usr/bin/env python3
"""Validate IW5 original source bytecode TEXLD/MUL and real original BC2 pixels.

This CI audit uses SHA256-authenticated retail FastFile and recovered
original IWD image bytes. It is NOT a new importer or renderer and does NOT
claim the D3D9 partial-precision or native blend/depth state is GPU-parity.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import zlib

FF_NAME="02_pluto_iw5_full_game_zone_dlc_english_so_coop_vlad_ep01.ff"
SOURCE_SHA="ad3697e0174dc77db164eb5e0187fa369d8a014eb3a4c5b0d8a0201637f79c12"
IWI_SHA="10534c8887f50b3e2741ee32d617464179682698a132364accbcac00697b584a"
STAGE_PIXEL_OFFSET=45876
STAGE_PIXEL_DWORDS=55
def require(value,error):
    if not value:
        raise ValueError("IW5 authentic pixel source proof: "+error)
def dword(b,at):
    return struct.unpack_from("<I",b,at)[0]
def rgb565(value):
    return (((value>>11)&31)*255//31,((value>>5)&63)*255//63,
            (value&31)*255//31)
def bc2_texel(src,x,y,width=32):
    blocks_w=(width+3)//4
    at=32+((y//4)*blocks_w+x//4)*16
    block=src[at:at+16]
    require(len(block)==16,"original BC2 source block is truncated")
    lane=(y%4)*4+x%4
    alpha=(int.from_bytes(block[:8],"little")>>(4*lane)&15)*17
    c0,c1=struct.unpack_from("<HH",block,8)
    pal0,pal1=rgb565(c0),rgb565(c1)
    palette=[
        pal0,pal1,
        tuple((2*a+b)//3 for a,b in zip(pal0,pal1)),
        tuple((a+2*b)//3 for a,b in zip(pal0,pal1)),
    ]
    selector=(dword(block,12)>>(2*lane))&3
    return palette[selector]+(alpha,)
def source_pixel_instructions(program):
    words=struct.unpack("<"+"I"*(len(program)//4),program)
    require(words[0]==0xffff0300 and words[-1]==65535,
            "not a complete original ps_3_0 stream")
    i=1
    ops=[]
    declarations=[]
    while i<len(words)-1:
        token=words[i]
        op=token&65535
        n=(token>>16)&32767 if op==65534 else (token>>24)&15
        operands=words[i+1:i+1+n]
        require(len(operands)==n,"original instruction operands truncated")
        if op==31:declarations.append((operands[0],operands[1]))
        if op!=65534 and op!=31:
            ops.append((op,operands))
        i+=n+1
    require(i==len(words)-1,"source original PS instruction end misaligned")
    return ops,declarations

def main(samples,iwd,out):
    ff=(samples/FF_NAME).read_bytes()
    require(hashlib.sha256(ff).hexdigest()==SOURCE_SHA,
            "original source FF SHA256 mismatch")
    decoded=zlib.decompress(ff[21:])
    program=decoded[STAGE_PIXEL_OFFSET:STAGE_PIXEL_OFFSET+STAGE_PIXEL_DWORDS*4]
    ops,declarations=source_pixel_instructions(program)
    require([o[0] for o in ops]==[66,5],
            "original pixel shader is not TEXLD then MUL")
    require(len(declarations)==3,"original PS input/sampler declarations mismatch")
    tex,modulate=ops
    # Actual compiled ps_3_0: texld r0, v1, s0;
    # mul oC0, r0, v0. Precision hint (dest modifier 2) retained.
    require(tuple(tex[1])==(0x802f0000,0x90e40001,0xa0e40800),
            "TEXLD source register / sampler / pixel precision changed")
    require(tuple(modulate[1])==(0x802f0800,0x80e40000,0x90e40000),
            "MUL source register / interpolated colour changed")
    original=(iwd/"friendorfoe_self_sp.original.iwi").read_bytes()
    require(hashlib.sha256(original).hexdigest()==IWI_SHA,
            "original IWI source pixels SHA256 mismatch")
    assert original[:4]==b"IWi\x08"
    pixels=[(0,0),(15,15),(16,16),(31,31)]
    rgba={f"{x},{y}":bc2_texel(original,x,y) for x,y in pixels}
    require(rgba["15,15"]==(32,44,32,255),
            "actual original BC2 source texel regression")
    # Representative varying colour, not claimed retail game input.
    # Compare original shader arithmetic, not fixed-function blending.
    vertex=(0.5,0.75,0.25,0.8)
    original_texel=rgba["15,15"]
    shader_rgba=[round((original_texel[i]/255)*vertex[i],8)
                 for i in range(4)]
    require(shader_rgba==[
        round(32/255*0.5,8),round(44/255*0.75,8),
        round(32/255*0.25,8),0.8],
        "original PS TEXLD/MUL reference result changed")
    out.mkdir(parents=True,exist_ok=True)
    result={
        "source_ff_sha256":SOURCE_SHA,
        "original_ps_instruction_sequence":["TEXLD","MUL"],
        "original_sampler":"s0","original_texcoord":"v1.xy",
        "original_colour_input":"v0.rgba",
        "original_source_precision_hint":"partial precision, not simulated",
        "original_iwi_sha256":IWI_SHA,
        "original_bc2_texels":rgba,
        "example_vertex_colour":vertex,
        "reference_sample_modulated_rgba":shader_rgba,
        "shader_source_math_verified":True,
        "raster_blend_depth_vertex_transform_gpu_parity_verified":False,
    }
    (out/"iw5_original_pixel_math.json").write_text(
        json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--samples",type=pathlib.Path,required=True)
    p.add_argument("--iwd",type=pathlib.Path,required=True)
    p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args()
    main(a.samples,a.iwd,a.out)
