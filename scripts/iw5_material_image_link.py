#!/usr/bin/env python3
"""Verify that the original FF Material points to exact original IWD image bytes."""
import argparse,hashlib,json,struct
from pathlib import Path
TARGET_SHA="10534c8887f50b3e2741ee32d617464179682698a132364accbcac00697b584a"
def verify(proofs:Path,iwd:Path,out:Path):
    mat=json.loads((proofs/"iw5_complete_original_material_proof.json").read_text())
    found=json.loads((iwd/"original_iwd_image_report.json").read_text())["found"]
    texture=mat["original_source_material_texture"]
    assert (texture["image_name"],texture["image_format"],texture["image_size"])==(
        "friendorfoe_self_sp","DXT3",[32,32])
    assert texture["name_hash"]=="0xa0ab1041" and texture["inline_image_bytes"]==0
    assert len(found)==1 and found[0]["inner_member"]=="images/friendorfoe_self_sp.iwi"
    b=(iwd/found[0]["artifact_file"]).read_bytes()
    assert len(b)==1056 and hashlib.sha256(b).hexdigest()==TARGET_SHA
    assert found[0]["sha256"]==TARGET_SHA and b[:4]==b"IWi\\x08".replace(b"\\x08",b"\x08")
    flags=struct.unpack_from("<I",b,4)[0]
    fmt,width,height,depth=struct.unpack_from("<BxHHH",b,8)
    assert (flags,fmt,width,height,depth)==(0x173,12,32,32,1)
    assert all(struct.unpack_from("<I",b,16+4*n)[0]==1056 for n in range(4))
    assert (width//4)*(height//4)*16==len(b)-32
    result=dict(material=mat["original_material_name"],pixel_shader_dwords=55,
        pixel_sampler="s0",image_name=texture["image_name"],
        iwd=found[0]["outer_member"],iwi_sha256=TARGET_SHA,
        original_iwi_bytes=len(b),original_bc2_blocks=len(b)-32,
        source_material_image_bytes_verified=True,game_draw_verified=False)
    out.mkdir(parents=True,exist_ok=True)
    (out/"iw5_original_material_image_link.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--proofs",type=Path,required=True)
    p.add_argument("--iwd",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();verify(a.proofs,a.iwd,a.out)
