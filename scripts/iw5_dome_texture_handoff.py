import os, io, zipfile, requests, hashlib, gzip, base64, concurrent.futures, json, pathlib, re, zlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
BITS=gzip.decompress(base64.b64decode(os.environ["SELECTION"]))
assert len(BITS)==2048
def selected(n):
    h=hashlib.sha256(n.lower().encode()).digest()
    return n == "floodlight_beam"
class Remote(io.RawIOBase):
    def __init__(self,url):
        self.s=requests.Session()
        self.s.mount("https://",HTTPAdapter(max_retries=Retry(total=4,backoff_factor=.5,status_forcelist=[429,500,502,503,504])))
        self.url=url
        r=self.s.head(url,timeout=60,allow_redirects=True); r.raise_for_status()
        self.size=int(r.headers["Content-Length"]); self.p=0; self.start=-1; self.cache=b""
    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self.p
    def seek(self,offset,whence=0):
        self.p=offset if whence==0 else (self.p if whence==1 else self.size)+offset
        if self.p<0: raise ValueError("negative seek")
        return self.p
    def read(self,n=-1):
        if n<0:n=self.size-self.p
        n=min(n,self.size-self.p)
        if n<=0:return b""
        p=self.p; self.p+=n
        if p>=self.start and p+n<=self.start+len(self.cache):return self.cache[p-self.start:p-self.start+n]
        e=min(self.size,p+max(n,65536))-1
        r=self.s.get(self.url,headers={"Range":f"bytes={p}-{e}","Accept-Encoding":"identity"},timeout=100,stream=True)
        try:
            if r.status_code!=206 or r.headers.get("Content-Range")!=f"bytes {p}-{e}/{self.size}":raise RuntimeError("invalid range response")
            data=r.content
            if len(data)!=e-p+1:raise RuntimeError("range length mismatch")
        finally:r.close()
        self.start=p; self.cache=data
        return data[:n]
    def close(self):
        self.s.close(); super().close()
base="https://r2.houseofkublai.com/mw3/DUMP/main/"
out=pathlib.Path("bundle");out.mkdir(exist_ok=True)
def one(name):
    rows=[]
    with Remote(base+name) as remote, zipfile.ZipFile(remote) as src:
        chosen=[]
        for x in src.infolist():
            n=x.filename.replace("\\","/").lower()
            if n.startswith("images/") and n.endswith(".iwi") and selected(n[7:-4]):chosen.append(x)
        if chosen:
            with zipfile.ZipFile(out/name,"w",compression=zipfile.ZIP_STORED) as dst:
                seen=set()
                for x in chosen:
                    if x.filename in seen:raise RuntimeError("duplicate original ZIP member")
                    seen.add(x.filename)
                    data=src.read(x)
                    assert zlib.crc32(data)&0xffffffff==x.CRC
                    dst.writestr(x.filename,data)
                    rows.append({"archive":name,"archive_bytes":remote.size,"member":x.filename,"size":len(data),"crc32":x.CRC,"sha256":hashlib.sha256(data).hexdigest()})
    print(name,len(rows),sum(x["size"] for x in rows),flush=True)
    return rows
names=["iw_01.iwd"]
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    rows=[r for group in pool.map(one,names) for r in group]
(out/"provenance.json").write_text(json.dumps(rows,indent=2))
print("Selected original members",len(rows),"bytes",sum(x["size"] for x in rows),flush=True)
