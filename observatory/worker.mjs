
/**
 * Source Coverage Observatory v1.
 * Metadata only. Source bytes never leave R2 through this Worker.
 * An R2 listing proves inventory presence, not decoding or semantic coverage.
 */
const GAMES = [
  { id: "bo1", name: "Black Ops", prefix: "bo1/", observed: 133 },
  { id: "bo2", name: "Black Ops II · T6", prefix: "bo2/", observed: 1287 },
  { id: "bo3", name: "Black Ops III", prefix: "bo3/", observed: 76 },
  { id: "destiny", name: "Destiny", prefix: "destiny/", observed: 2156 },
  { id: "ghosts", name: "Call of Duty: Ghosts", prefix: "ghosts/", observed: 7539 },
  { id: "h1", name: "Modern Warfare Remastered", prefix: "h1/", observed: 7 },
  { id: "fortnite", name: "Fortnite", prefix: "Fortnite/", observed: 352 },
  { id: "smg", name: "Super Mario Galaxy", prefix: "super-mario-galaxy/", observed: 2426 }
];
const asJson = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "same-origin"
  }
});
// Only trust the pinned public code branch as a source of provenance metadata.
// Reports contain SHA-256 and byte-range metadata, never original game binaries.
const PROOF_BASES = [
 "https://raw.githubusercontent.com/lizardpeter/r2-runners/feature/source-coverage-observatory-v1/observatory/reports/t6/",
 "https://raw.githubusercontent.com/lizardpeter/r2-runners/main/observatory/reports/t6/"
];
async function getProof(name) {
  if (!/^[a-z0-9_-]+\.json$/.test(name)) throw new Error("Invalid proof file name");
  for (const base of PROOF_BASES) {
    const response = await fetch(base + name, {headers: {"Accept":"application/json"}});
    if (!response.ok) continue;
    const content = await response.text();
    if(content.length > 6_000_000) throw new Error("Proof document is unexpectedly large");
    return JSON.parse(content);
  }
  return null;
}
const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Source Observatory · Asset Coverage</title>
<style>
:root{color-scheme:dark;--bg:#090e18;--surface:#111929;--surface2:#182338;--border:#29344b;--text:#edf3ff;--muted:#91a1be;--blue:#7db1ff;--mint:#77debe;--amber:#f3c980}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 78% 0,#142a4a 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{padding:30px 36px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:18px}h1{font-size:30px;line-height:1.15;margin:5px 0 8px;letter-spacing:-.9px}h2{font-size:17px;margin:0 0 15px;letter-spacing:-.3px}p{margin:0}small,.muted{color:var(--muted)}.eyebrow{text-transform:uppercase;font-size:11px;letter-spacing:2.5px;color:var(--mint);font-weight:800}.live{border:1px solid #245a53;background:#10332f;border-radius:999px;padding:7px 13px;color:#9df2d5;white-space:nowrap;font-size:12px}
.app{display:grid;grid-template-columns:238px minmax(0,1fr);min-height:calc(100vh - 112px)}aside{border-right:1px solid var(--border);padding:25px 14px 40px}aside h2{padding:0 12px}nav button{display:flex;width:100%;justify-content:space-between;align-items:center;text-align:left;background:transparent;color:var(--muted);border:1px solid transparent;padding:12px 12px;border-radius:10px;cursor:pointer;font:inherit;margin:3px 0}nav button.active,nav button:hover{background:#1b2e4c;border-color:#375177;color:var(--text)}.count{font-size:12px;color:#8b9cb7;font-variant-numeric:tabular-nums}
main{min-width:0;padding:26px 32px 45px;max-width:1600px;width:100%;margin:auto}
.banner{background:#1b2436;border:1px solid var(--border);border-left:3px solid var(--amber);padding:13px 16px;border-radius:9px;color:#ccd8ea;margin:0 0 20px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}.stat{border:1px solid var(--border);background:var(--surface);border-radius:12px;padding:18px}.stat .k{font-size:12px;color:var(--muted)}.stat .v{font-size:27px;font-weight:700;font-variant-numeric:tabular-nums;margin-top:5px;letter-spacing:-.8px}
.panels{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:17px}.panel{border:1px solid var(--border);background:var(--surface);border-radius:12px;padding:20px;min-width:0}.controls{display:flex;gap:10px;margin:0 0 13px;align-items:center;flex-wrap:wrap}input,select{background:#0b1425;color:var(--text);border:1px solid #34435b;padding:11px 13px;border-radius:8px;font:inherit}input{flex:1;min-width:150px}select{min-width:110px}
table{width:100%;border-collapse:collapse}th{font-weight:600;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;text-align:left;border-bottom:1px solid var(--border);padding:10px 9px}td{border-bottom:1px solid #222e41;padding:11px 9px;vertical-align:middle}td.path{max-width:520px;overflow-wrap:anywhere;color:#dbe8ff}tr.pick{cursor:pointer}tr.pick:hover,tr.selected{background:#1a2b46}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.pill{display:inline-block;border:1px solid #3a516c;background:#1a2e49;color:#b8d8ff;border-radius:6px;padding:2px 7px;font-size:11px;font-weight:700}.tag{font-size:11px;color:var(--amber)}.bars{display:grid;gap:12px}.track{height:7px;border-radius:8px;background:#344058;margin-top:5px;overflow:hidden}.track span{height:100%;display:block;background:var(--mint)}.measure{display:flex;justify-content:space-between;font-size:12px;gap:12px}.details{overflow-wrap:anywhere}.detailrow{border-bottom:1px solid var(--border);padding:12px 0}.detailrow:last-child{border:0}.detailrow .k{font-size:12px;color:var(--muted);margin-bottom:3px}.detailrow .v{font-variant-numeric:tabular-nums}.types{margin-top:20px}.typerow{display:grid;grid-template-columns:65px 1fr 38px;align-items:center;gap:10px;font-size:12px;margin:10px 0}.typerow .track{margin:0}.proof{margin-top:20px;padding:18px;border:1px solid #37536b;border-radius:12px;background:#102333}.proof h3{font-size:16px;margin:0 0 7px}.proof p{font-size:12px;color:#bacbde}.proofbar{display:flex;width:100%;height:16px;border-radius:6px;background:#423c42;overflow:hidden;margin:12px 0}.proofbar .understood{background:#64c5ac}.proofbar .unknown{background:#987b56}.proofmetrics{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.proofmetrics>div{background:#162b40;border-radius:8px;padding:9px}.proofmetrics strong{display:block;font-size:17px;font-variant-numeric:tabular-nums}.proofmetrics small{font-size:10px}.scrollproof{max-height:310px;overflow:auto}.scrollproof table td{font-size:11px}.proofclick{cursor:pointer;color:#a9d5ff}.prooferr{font-size:12px;color:var(--amber)}.assetlist{font-size:11px;color:#a9c8db;max-height:120px;overflow:auto}
button.more{border:1px solid #425b7f;background:#21416b;color:#f0f6ff;border-radius:9px;padding:11px 18px;cursor:pointer;margin-top:17px;font:inherit}button.more:disabled{cursor:not-allowed;opacity:.5}
.foot{font-size:12px;color:var(--muted);margin-top:16px}.empty{padding:35px;text-align:center;color:var(--muted)}a{color:#9dc5ff}
@media(max-width:1050px){.panels{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:700px){.app{grid-template-columns:1fr}aside{border-right:0;border-bottom:1px solid var(--border);padding:12px}nav{display:flex;gap:5px;overflow-x:auto}nav button{min-width:150px}header{padding:25px 18px}main{padding:18px 12px}.stats{grid-template-columns:repeat(2,1fr)}h1{font-size:25px}.live{display:none}.panel{padding:13px}th:nth-child(3),td:nth-child(3){display:none}}
</style></head><body>
<header><div><div class="eyebrow">Original source · Evidence tracker</div><h1>Source Observatory</h1><p class="muted">One explorer for every indexed source file, archive, and future byte-level proof.</p></div><div class="live">● Live Cloudflare R2 listing</div></header>
<div class="app"><aside><h2>Source collections</h2><nav id="games"></nav><p class="foot" style="padding:13px">Inventories reflect the original R2 keys, not files nested inside containers. Counts are verified snapshots from October 27, 2026.</p></aside>
<main><div class="banner"><strong>Proof boundary:</strong> listed ≠ parsed ≠ semantically understood. Every file begins as <strong>metadata indexed</strong>. No byte or semantic completion is asserted without source-range evidence.</div>
<div class="stats"><div class="stat"><div class="k">R2 objects · all 8 collections</div><div class="v" id="total">13,976</div></div><div class="stat"><div class="k">Selected collection</div><div class="v" id="observed">—</div></div><div class="stat"><div class="k">File records loaded in browser</div><div class="v" id="loaded">0</div></div><div class="stat"><div class="k">Byte-level semantic proof</div><div class="v" style="font-size:19px;color:var(--amber)">Not measured</div></div></div>
<div class="panels"><section class="panel"><h2 id="heading">Files</h2><div class="controls"><input id="find" type="search" placeholder="Filter loaded files by name or path" aria-label="Filter loaded files"><select id="type" aria-label="File type"><option value="">All extensions</option></select><select id="family" aria-label="T6 source family"><option value="">All T6 families</option><option value="client">Client zones</option><option value="server_pc">PC server</option><option value="server_ps3">PS3 server</option><option value="server_xbox360">Xbox 360 server</option><option value="server_wiiu">Wii U server</option><option value="other">Other BO2 files</option></select><select id="xasset" aria-label="T6 XAsset type"><option value="">All XAsset types</option></select></div>
<div style="overflow-x:auto"><table><thead><tr><th>File / path</th><th>Type</th><th>Size</th><th>Evidence</th></tr></thead><tbody id="rows"></tbody></table></div>
<div id="empty" class="empty" hidden>No matching files on loaded pages.</div>
<button class="more" id="more">Load next 400 files</button><div class="foot" id="pageNote">Search applies to loaded pages. Use “Load next” to inspect the whole collection.</div>
</section><div><section class="panel details"><h2>File inspector</h2><div id="inspector" class="muted">Select a file to inspect its source identity and coverage status.</div></section><section id="proofPanel" class="proof" style="display:none"><h3>Authenticated T6 evidence</h3><div id="proofContent">Choose a verified FastFile to see its original hashes and byte accountability.</div></section><section class="panel types" id="t6TypesPanel" style="display:none"><h2>Original T6 XAsset types · all 571 zones</h2><p class="foot">Verified directory ordinals; not semantic body completion. Click a type to filter matching FastFiles.</p><div id="t6TypeBars"></div></section><section class="panel types"><h2>File types · loaded pages only</h2><div id="typeBars"></div></section></div></div>
<div class="foot">Source bytes are never served by this site. R2 metadata proves file presence and physical size only. Future authenticated audit manifests will add signatures, decompression, XAsset ordinals, field ranges, and independent P0–P8 proof statuses.</div></main></div>
<script>
const games=[{id:"bo1",name:"Black Ops",observed:133},{id:"bo2",name:"Black Ops II · T6",observed:1287},{id:"bo3",name:"Black Ops III",observed:76},{id:"destiny",name:"Destiny",observed:2156},{id:"ghosts",name:"Call of Duty: Ghosts",observed:7539},{id:"h1",name:"Modern Warfare Remastered",observed:7},{id:"fortnite",name:"Fortnite",observed:352},{id:"smg",name:"Super Mario Galaxy",observed:2426}];
const $=id=>document.getElementById(id), fmt=n=>Number(n||0).toLocaleString(), pretty=n=>n>=1073741824?(n/1073741824).toFixed(2)+" GiB":n>=1048576?(n/1048576).toFixed(2)+" MiB":n>=1024?(n/1024).toFixed(1)+" KiB":fmt(n)+" B";
let game="bo2",items=[],cursor=null,hasMore=true,busy=false,chosen=null,proofIndex={},proofLoaded=false,headerIndex={},headerSurveyComplete=false,clientIndex={},clientOverview=null,serverIndex={},serverOverview=null,typeInventory=null,sourceHeaderIndex={},sourceHeaderOverview=null,ipakIndex={},soundIndex={},wadIndex={},wadFullIndex={};
async function loadNestedDirectories(){
 ipakIndex={};soundIndex={};wadIndex={};wadFullIndex={};
 if(game!=="bo2")return;
 const sources=[["/api/t6/ipaks","source-observatory/t6-ipak-index/v1","ipak"],
                ["/api/t6/sound-banks","source-observatory/t6-sound-bank-index/v1","sound"],
                ["/api/t6/wads","source-observatory/t6-wad-index/v1","wad"],
                ["/api/t6/wads/full","source-observatory/t6-wad-full-byte-accounting/v1","wadfull"]];
 for(const [url,schema,kind] of sources){
  try{const res=await fetch(url,{cache:"no-store"});if(!res.ok)continue;
    const d=await res.json();if(d.schema!==schema)continue;
    for(const row of d.files||[]){if(kind==="ipak")ipakIndex[row.source_key]=row;else if(kind==="sound")soundIndex[row.source_key]=row;else if(kind==="wad")wadIndex[row.source_key]=row;else wadFullIndex[row.source_key]=row}
  }catch(e){console.warn("Nested source directory not yet available",e)}
 }
 if(chosen)inspect(chosen);
 render();
}
function renderFullWad(p,item){
 const panel=$("proofPanel"),box=$("proofContent");panel.style.display="block";box.replaceChildren();
 const success=p.state==="full_original_wad_byte_ownership_and_zlib_verified";
 box.append(el("p","",success?"Full original WAD transport/byte ownership verified. Each physical byte is assigned without gaps or overlap; all indexed zlib streams decoded and hashed. Nested application semantics are NOT established.":"Original source WAD remains unresolved at full-byte scope."));
 const metric=(k,v)=>{const d=el("div");d.append(el("small","",k),el("strong","",v));return d};
 const fields=el("div","proofmetrics");
 fields.append(metric("Original bytes owned",success?pretty(p.source_fully_accounted_bytes):"Not proven"),
 metric("Nested zlib streams",fmt(p.zlib_streams_verified||0)),
 metric("Expanded nested bytes",pretty(p.expanded_total_bytes||0)),
 metric("Physical unknown gaps",success?"0":"Not measured"));
 box.append(fields);
 box.append(el("h3","","Exact original file SHA-256"));
 box.append(el("p","mono assetlist",p.source_sha256||"Not verified"));
 const entries=p.nested_entries||[];
 box.append(el("h3","","Decompressed nested file entries"));
 const search=el("input");search.placeholder="Filter nested filenames";search.setAttribute("aria-label","Filter WAD nested files");search.style.cssText="width:100%;margin:8px 0";
 const holder=el("div","scrollproof"),table=el("table"),body=el("tbody");table.append(body);holder.append(table);box.append(search,holder);
 const draw=()=>{body.replaceChildren();const q=search.value.toLowerCase().trim();
 for(const entry of entries.filter(x=>!q||x.name.toLowerCase().includes(q)).slice(0,120)){
  const row=el("tr"),status=entry.json_syntax==="invalid"?"JSON syntax issue":entry.json_syntax==="valid"?"JSON syntax valid":"Decoded payload";
  row.append(el("td","mono",entry.name),el("td","mono",pretty(entry.expanded_bytes)),el("td","",status));row.title="Expanded SHA256: "+entry.expanded_sha256+" | original offset "+entry.original_offset;body.append(row);
 }};
 search.oninput=draw;draw();
 const invalid=entries.filter(x=>x.json_syntax==="invalid");
 if(invalid.length)box.append(el("p","prooferr",invalid.length+" original nested .json document(s) fail strict JSON syntax; zlib transport and exact byte hashes still verified. This does not establish whether the original game accepts their syntax."));
 if(p.error)box.append(el("p","prooferr",p.error));
 box.append(el("p","foot","A complete physical/compression proof is not equivalent to knowing every field in the decompressed nested files."));
}
function renderNestedProof(p,item,kind){
 const panel=$("proofPanel"),box=$("proofContent");panel.style.display="block";box.replaceChildren();
 const verified=kind==="ipak"?p.status==="ipak_index_validated":kind==="sound"?p.status==="bank_entry_index_validated":p.status==="wad_directory_validated";
 const count=kind==="ipak"?p.index_entry_count:p.entry_count;
 const intro=el("p","",(kind==="ipak"?"IPAK index":kind==="sound"?"Sound bank index":"T3w WAD nested directory")+" — "+(verified?"structure verified":"not fully verified")+
 ". Actual original R2 byte ranges were checked, but payload contents were not downloaded or semantically decoded.");
 box.append(intro);
 const cells=el("div","proofmetrics");const metric=(k,v)=>{const d=el("div");d.append(el("small","",k),el("strong","",v));return d};
 cells.append(metric("Original file",pretty(p.original_r2_size)),metric("Indexed records",count===undefined?"Unresolved":fmt(count)),
 metric("Validated index bytes",pretty(kind==="ipak"?(p.index_entry_table_bytes||0):(kind==="sound"?(p.entry_directory_bytes||0):(p.entry_table_bytes||0)))),
 metric("Full original SHA256","Not collected in range audit"));box.append(cells);
 if(p.sections){
  box.append(el("h3","","Physical source sections"));
  const sc=el("div","scrollproof"),tab=el("table"),body=el("tbody");
  for(const section of p.sections){const row=el("tr");row.append(el("td","mono","Type "+section.type),
      el("td","mono",fmt(section.offset)+"–"+fmt(section.offset+section.size)),
      el("td","mono",fmt(section.item_count)+" rows"));body.append(row)}
  tab.append(body);sc.append(tab);box.append(sc);
 }
 if(p.audio_format_code_counts){
  box.append(el("h3","","Observed sound format codes"));
  const list=el("div","scrollproof"),tab=el("table"),body=el("tbody");
  for(const [fmtCode,n] of Object.entries(p.audio_format_code_counts)){const row=el("tr");row.append(el("td","mono","Code "+fmtCode),el("td","mono",fmt(n)+" indexed clips"));body.append(row)}
  tab.append(body);list.append(tab);box.append(list);
 }
 if(p.entries_sample?.length){
  box.append(el("h3","","Original WAD nested filenames (sample)"));
  const scroll=el("div","scrollproof"),table=el("table"),body=el("tbody");
  for(const entry of p.entries_sample){const tr=el("tr");
   tr.append(el("td","mono",entry.name),el("td","mono",pretty(entry.compressed_bytes)),el("td","mono",fmt(entry.source_offset)));
   body.append(tr)}table.append(body);scroll.append(table);box.append(scroll);
  if(p.entries_sample_truncated)box.append(el("p","foot","Showing first "+p.entries_sample.length+" indexed entries; full table validated on original R2."));
 }
 if(p.error)box.append(el("p","prooferr",p.error));
 box.append(el("h3","","Source evidence"));
 box.append(el("p","mono assetlist",p.source_key));
 box.append(el("p","","Only header/directory ranges were read from original R2; texture/audio payloads and complete byte semantics remain unevaluated."));
}
async function loadSourceHeaders(){
 sourceHeaderIndex={};sourceHeaderOverview=null;
 if(game!=="bo2")return;
 try{const r=await fetch("/api/t6/source-headers",{cache:"no-store"});if(!r.ok)return;
   const j=await r.json();if(j.schema!=="source-observatory/original-r2-signature-corpus/v1"||!j.complete_signature_survey||j.files?.length!==1287)return;
   for(const f of j.files)sourceHeaderIndex[f.r2_key]=f;
   sourceHeaderOverview=j;
   if(chosen)inspect(chosen);
   render();
 }catch(e){console.warn("T6 full source header verification unavailable",e)}
}
async function loadTypeInventory(){
 typeInventory=null;
 if(game!=="bo2")return;
 try{const r=await fetch("/api/t6/types",{cache:"no-store"});if(!r.ok)return;const j=await r.json();
   if(j.schema!=="source-observatory/t6-asset-types/v1"||j.files_with_eligible_directory_scan!==571)return;
   typeInventory=j;
   const menu=$("xasset"),current=menu.value;menu.replaceChildren();
   const first=el("option","","All XAsset types");first.value="";menu.append(first);
   j.types.forEach(t=>{const opt=el("option","",t.type+" ("+fmt(t.entries)+")");opt.value=t.type;menu.append(opt)});
   menu.value=j.types.some(x=>x.type===current)?current:"";
   render();
 }catch(e){console.warn("Original T6 XAsset type inventory unavailable",e)}
}
function renderTypeInventory(){
 const panel=$("t6TypesPanel"),container=$("t6TypeBars");
 panel.style.display=game==="bo2"&&typeInventory?"block":"none";container.replaceChildren();
 if(!typeInventory)return;
 const biggest=Math.max(1,...typeInventory.types.map(x=>x.entries));
 typeInventory.types.slice(0,16).forEach(t=>{
   const b=el("button","typerow");b.style.cssText="width:100%;border:0;background:transparent;color:inherit;text-align:left;padding:5px 0;cursor:pointer";
   b.title=t.type+": "+fmt(t.entries)+" entries in "+fmt(t.files)+" FastFiles; click to filter";
   const label=el("span","mono",t.type);label.style.cssText="overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
   const track=el("span","track");track.style.display="block";const fill=el("span");fill.style.width=(100*t.entries/biggest)+"%";track.append(fill);
   const number=el("span","mono",fmt(t.entries));b.style.gridTemplateColumns="120px 1fr 67px";b.append(label,track,number);
   b.onclick=()=>{$("xasset").value=t.type;render();$("heading").scrollIntoView({behavior:"smooth",block:"start"})};
   container.append(b);
 });
 container.append(el("p","foot",fmt(typeInventory.observed_types)+" types observed / "+fmt(typeInventory.xasset_registry_types)+" registered. "+fmt(typeInventory.total_directory_entries)+" directory entries, including duplicates/patches."));
}
function familyOf(item){
 const k=item.key;
 if(k.startsWith("bo2/zone/"))return "client";
 if(k.includes("/PC Server/"))return "server_pc";
 if(k.includes("/PS3 Server/"))return "server_ps3";
 if(k.includes("/Xbox 360 Server/"))return "server_xbox360";
 if(k.includes("/WiiU Server/"))return "server_wiiu";
 return "other";
}
async function loadServerCorpus(){
 serverIndex={};serverOverview=null;
 if(game!=="bo2")return;
 try{const res=await fetch("/api/t6/server-corpus",{cache:"no-store"});if(!res.ok)return;
 const d=await res.json();
 if(d.schema!=="source-observatory/t6-server-corpus/v1"||!d.complete_source_listing||d.files?.length!==356)return;
 for(const f of d.files)serverIndex[f.source_key]=f;
 serverOverview=d;
 if(chosen)inspect(chosen);
 render();
 }catch(e){console.warn("Unsigned server proof not available",e)}
}
async function loadClientCorpus(){
 clientIndex={};clientOverview=null;
 if(game!=="bo2")return;
 try{const r=await fetch("/api/t6/client-corpus",{cache:"no-store"});if(!r.ok)return;
   const d=await r.json();
   if(d.schema!=="source-observatory/t6-client-corpus/v1"||!d.complete_source_listing||d.files?.length!==215)return;
   for(const f of d.files||[])clientIndex[f.source_key]=f;
   clientOverview=d;
   if(chosen)inspect(chosen);
   render();
 }catch(e){console.warn("Client corpus unavailable",e)}
}
async function loadHeaderSurvey(){
 headerIndex={};headerSurveyComplete=false;
 if(game!=="bo2")return;
 try{const r=await fetch("/api/t6/headers",{cache:"no-store"});if(!r.ok)return;const d=await r.json();
  if(d.schema!=="source-observatory/t6-header-survey/v1"||!d.complete_range_survey)return;
  for(const f of d.files||[])headerIndex[f.r2_key]=f;
  headerSurveyComplete=true;render();
 }catch(e){console.warn("Signature survey unavailable",e)}
}
async function loadProofIndex(){
 proofIndex={}; proofLoaded=false;
 if(game!=="bo2")return;
 try {const r=await fetch("/api/t6/index",{cache:"no-store"}); if(!r.ok)return;const d=await r.json();
 if(d.schema!=="source-observatory/t6-index/v1")return;
 for(const f of d.files||[])proofIndex[f.source_key]=f;
 proofLoaded=true;render();
 }catch(e){console.warn("T6 evidence unavailable",e)}
}
function renderClientProof(p,item){
 const panel=$("proofPanel"),content=$("proofContent");panel.style.display="block";content.replaceChildren();
 const n=(label,value)=>{const d=el("div");d.append(el("small","",label),el("strong","",value));return d};
 const outcome=el("p","", "This source was analyzed from the original R2 bytes. State: "+p.state+". This is not evidence that the Rust-test production importer decodes or understands the asset bodies.");content.append(outcome);
 const fields=el("div","proofmetrics");
 fields.append(n("Original bytes",pretty(p.actual_original_bytes||p.original_listed_bytes)),n("Expanded XFile bytes",p.expanded_bytes===undefined?"Not expanded":pretty(p.expanded_bytes)),n("XAsset directory entries",p.xasset_count===undefined?"Not verified":fmt(p.xasset_count)),n("Unclassified expanded bytes",p.unknown_expanded_bytes===undefined?"Not measured":pretty(p.unknown_expanded_bytes)));content.append(fields);
 if(p.expanded_bytes>0){const track=el("div","proofbar"),a=el("div","understood"),b=el("div","unknown");a.style.width=100*(p.structural_expanded_bytes||0)/p.expanded_bytes+"%";b.style.width=100*(p.unknown_expanded_bytes||0)/p.expanded_bytes+"%";track.append(a,b);content.append(track)}
 if(p.type_counts && Object.keys(p.type_counts).length){content.append(el("h3","","XAsset type counts (directory only)"));const scroll=el("div","scrollproof"),table=el("table"),body=el("tbody");
  for(const [type,count] of Object.entries(p.type_counts).sort((a,b)=>b[1]-a[1])){const tr=el("tr");tr.append(el("td","mono",type),el("td","mono",fmt(count)));body.append(tr)}table.append(body);scroll.append(table);content.append(scroll)}
 if(p.error)content.append(el("p","prooferr","Parser/transport result: "+p.error));
 content.append(el("h3","","Source verification"));content.append(el("div","mono assetlist","Source key: "+p.source_key+" | Original SHA256: "+(p.original_sha256||"Not verified")+" | Expanded SHA256: "+(p.expanded_sha256||"Not produced")));
 content.append(el("p","","These hashes are calculated from the R2 download during the runner audit. They are not automatically independent historical fixtures. Byte complete: NO. Semantic complete: NO."));
}
function renderProof(p,item){
 const panel=$("proofPanel"),content=$("proofContent");panel.style.display="block";content.replaceChildren();
 if(!p||!item){content.textContent="No independently authenticated report for this original source file. The R2 object is inventoried but its decoded contents have not been evaluated here.";return}
 const source=p.source,expanded=p.expanded,cov=p.coverage;
 const n=(label,value)=>{const d=el("div");d.append(el("small","",label),el("strong","",value));return d};
 const lead=el("p","", "Verified original SHA-256 and "+(expanded.independent_expected_sha256_matched?"independently retained expanded SHA-256.":"expanded stream SHA-256 from this run.")+" Only header and XAsset directory bytes are structurally classified; the remaining asset-body bytes are unknown.");
 content.append(lead);
 const bar=el("div","proofbar"),seen=el("div","understood"),not=el("div","unknown");
 const structural=cov.known_structural_expanded_bytes||0,unknown=cov.unclassified_expanded_bytes||0;
 seen.style.width=100*structural/Math.max(1,expanded.bytes)+"%";not.style.width=100*unknown/Math.max(1,expanded.bytes)+"%";bar.append(seen,not);content.append(bar);
 const m=el("div","proofmetrics");m.append(n("Structurally classified expanded bytes",pretty(structural)),n("Unknown expanded bytes",pretty(unknown)),n("XAsset directory entries",fmt(p.xfile.asset_count)),n("Asset types present",fmt(Object.keys(p.type_counts).length)));content.append(m);
 const h=el("h3","","Nested XAsset type inventory");h.style.marginTop="15px";content.append(h);
 const list=el("div","scrollproof"),table=el("table"),body=el("tbody");
 for(const [t,c] of Object.entries(p.type_counts).sort((a,b)=>b[1]-a[1])){const row=el("tr");row.append(el("td","mono",t),el("td","mono",fmt(c)));body.append(row)}table.append(body);list.append(table);content.append(list);
 if(p.asset_records?.length){
  content.append(el("h3","","XAsset ordinals and source directory offsets"));
  const filter=el("input");filter.placeholder="Search ordinal or type…";filter.setAttribute("aria-label","Filter verified XAsset records");filter.style.width="100%";filter.style.margin="6px 0 10px";
  const holder=el("div","scrollproof"),tab=el("table"),body=el("tbody");tab.append(body);holder.append(tab);content.append(filter,holder);
  const paint=()=>{body.replaceChildren();const q=filter.value.trim().toLowerCase();const selected=p.asset_records.filter(r=>!q||r.type.toLowerCase().includes(q)||String(r.ordinal).includes(q));for(const r of selected.slice(0,90)){const tr=el("tr");tr.append(el("td","mono","#"+r.ordinal),el("td","",r.type),el("td","mono",r.expanded_start+"–"+r.expanded_end));body.append(tr)}
   if(selected.length>90){const tr=el("tr");const td=el("td","muted","Showing 90 of "+selected.length+" matching directory entries");td.colSpan=3;tr.append(td);body.append(tr)}};
  filter.oninput=paint;paint();
 }
 content.append(el("h3","","Byte-range ownership"));
 const ranges=el("div","scrollproof"),rt=el("table"),rb=el("tbody");
 for(const r of p.expanded_ranges){const tr=el("tr");tr.append(el("td","mono",r.start+"–"+r.end),el("td","",r.kind),el("td","",r.name));rb.append(tr)}rt.append(rb);ranges.append(rt);content.append(ranges);
 content.append(el("h3","","Source verification"));
 content.append(el("div","mono assetlist","R2: "+source.r2_key+" | SHA256: "+source.sha256+" | Expanded SHA256: "+expanded.sha256));
 content.append(el("p","","Rust-test production importer: NOT TESTED by this evidence. Byte-complete: NO. Semantic-complete: NO."));
}
async function loadReport(item){
 const key=item.key,panel=$("proofPanel"),content=$("proofContent");panel.style.display="block";content.textContent="Loading authenticated source byte ranges…";
 try{const r=await fetch("/api/t6/report?key="+encodeURIComponent(key),{cache:"no-store"});
 if(key!==chosen?.key||game!=="bo2")return;
 if(!r.ok){renderProof(null,item);return}
 const proof=await r.json();
 if(proof.source?.r2_key!==key||proof.source?.bytes!==item.bytes){content.textContent="Proof/report disagrees with live R2 object identity. Rejecting stale evidence.";return}
 renderProof(proof,item)
 }catch(e){content.textContent="T6 proof report unavailable: "+e.message}
}
function el(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=String(txt);return e}
function nav(){const root=$("games");root.replaceChildren();games.forEach(g=>{const b=el("button",g.id===game?"active":"");b.append(el("span","",g.name),el("span","count",fmt(g.observed)));b.onclick=()=>select(g.id);root.append(b)})}
function inspect(item){chosen=item;
 if(game==="bo2"&&item?.extension==="ff"&&proofIndex[item.key])loadReport(item);
 else if(game==="bo2"&&item?.extension==="ff"&&clientIndex[item.key]&&clientIndex[item.key].original_listed_bytes===item.bytes)renderClientProof(clientIndex[item.key],item);
 else if(game==="bo2"&&item?.extension==="ipak"&&ipakIndex[item.key]&&ipakIndex[item.key].original_r2_size===item.bytes)
   renderNestedProof(ipakIndex[item.key],item,"ipak");
 else if(game==="bo2"&&(item?.extension==="sabs"||item?.extension==="sabl")&&soundIndex[item.key]&&soundIndex[item.key].original_r2_size===item.bytes)
   renderNestedProof(soundIndex[item.key],item,"sound");
 else if(game==="bo2"&&item?.extension==="wad"&&wadFullIndex[item.key]&&wadFullIndex[item.key].original_r2_size===item.bytes)
   renderFullWad(wadFullIndex[item.key],item);
 else if(game==="bo2"&&item?.extension==="wad"&&wadIndex[item.key]&&wadIndex[item.key].original_r2_size===item.bytes)
   renderNestedProof(wadIndex[item.key],item,"wad");
 else if(game==="bo2"&&item?.extension==="ff"&&serverIndex[item.key]&&serverIndex[item.key].original_listed_bytes===item.bytes){
   const proof=serverIndex[item.key];
   renderClientProof({...proof,structural_expanded_bytes:proof.expanded_directory_bytes,unknown_expanded_bytes:proof.expanded_unknown_bytes,actual_original_bytes:proof.original_authenticated_bytes},item);
 }
 else {
  const hdr=headerIndex[item?.key],verified=hdr?.r2_content_range_verified&&hdr?.r2_listed_bytes===item?.bytes;
  $("proofPanel").style.display=game==="bo2"&&item?.extension==="ff"?"block":"none";
  $("proofContent").textContent=verified?
    "Source header checked using original HTTP 206 bytes 0–63. Signature: "+hdr.signature_status+"; version: "+(hdr.version??"unknown")+". Full-file SHA-256, decryption, nested assets, and semantic byte meaning have NOT been checked for this object.":
    "No completed original-source byte audit yet; R2 inventory metadata only.";
 }
 const box=$("inspector");box.replaceChildren();if(!item){box.textContent="Select a file to inspect its source identity and coverage status.";return}const general=sourceHeaderIndex[item.key],authMagic=general?.http_range_verified&&general?.r2_size===item.bytes?general:null,ip=ipakIndex[item.key],snd=soundIndex[item.key],wad=wadIndex[item.key],deep=ip?.original_r2_size===item.bytes?ip:snd?.original_r2_size===item.bytes?snd:wad?.original_r2_size===item.bytes?wad:null;
 const rows=[["Original R2 object key",item.key],["Verified source magic",authMagic?
   (authMagic.signature+" | "+(authMagic.signature8_ascii||"no signature")+" | "+(authMagic.signature8_hex||"")):
   (headerIndex[item.key]?.signature_prefix8_ascii||"Not checked")],["Header evidence",authMagic?"Original bytes 0–"+(authMagic.bytes_sampled-1)+" / HTTP 206 exact Content-Range":"Not evaluated"],["Physical size",fmt(item.bytes)+" bytes"],["Last modified",item.uploaded||"Not supplied"],["R2 ETag",item.etag||"Not supplied (not a SHA-256 proof)"],["Object inventory","Indexed (R2 listing)"],["Container / nested assets",deep?.status==="ipak_index_validated"?"IPAK entries validated: "+fmt(deep.index_entry_count):deep?.status==="bank_entry_index_validated"?"Audio entries validated: "+fmt(deep.entry_count):wadFullIndex[item.key]?.state==="full_original_wad_byte_ownership_and_zlib_verified"?"Full WAD source/transport coverage: "+fmt(wadFullIndex[item.key].zlib_streams_verified)+" nested entries":deep?.status==="wad_directory_validated"?"Nested WAD entries validated: "+fmt(deep.entry_count):"Not audited"],["Byte-range ownership",wadFullIndex[item.key]?.state==="full_original_wad_byte_ownership_and_zlib_verified"?"Every original WAD byte assigned; full zlib streams losslessly decoded":deep?"Header and directory physical ranges identified; payload unknown":"Not audited"],["Meaning of each field","Not audited"],["Cross-fixture validation","Not audited"],["Original source bytes","Not available through this website"]];for(const [key,value] of rows){const d=el("div","detailrow");d.append(el("div","k",key),el("div","v mono",value));box.append(d)}}
function render(){const q=$("find").value.trim().toLowerCase(),type=$("type").value,family=$("family").value,asset=$("xasset").value,filtered=items.filter(x=>(!q||x.path.toLowerCase().includes(q))&&(!type||x.extension===type)&&(!family||familyOf(x)===family)&&(!asset||(clientIndex[x.key]?.type_counts?.[asset]||serverIndex[x.key]?.type_counts?.[asset])));const tbody=$("rows");tbody.replaceChildren();for(const item of filtered.slice(0,500)){const tr=el("tr","pick"+(item.key===chosen?.key?" selected":""));tr.tabIndex=0;const header=headerIndex[item.key],verifiedHeader=header?.r2_content_range_verified&&header?.r2_listed_bytes===item.bytes,clientProof=clientIndex[item.key]?.original_listed_bytes===item.bytes?clientIndex[item.key]:null,serverProof=serverIndex[item.key]?.original_listed_bytes===item.bytes?serverIndex[item.key]:null,sourceHeader=sourceHeaderIndex[item.key]?.http_range_verified&&sourceHeaderIndex[item.key]?.r2_size===item.bytes?sourceHeaderIndex[item.key]:null,ipak=ipakIndex[item.key]?.original_r2_size===item.bytes?ipakIndex[item.key]:null,sound=soundIndex[item.key]?.original_r2_size===item.bytes?soundIndex[item.key]:null,wad=wadIndex[item.key]?.original_r2_size===item.bytes?wadIndex[item.key]:null,wadFull=wadFullIndex[item.key]?.original_r2_size===item.bytes?wadFullIndex[item.key]:null;
 tr.append(el("td","path mono",item.path),el("td","",item.extension),el("td","mono",pretty(item.bytes)),el("td",proofIndex[item.key]||verifiedHeader||clientProof||serverProof||sourceHeader||ipak||sound||wad||wadFull?"pill":"tag",proofIndex[item.key]?"Verified directory":clientProof?.state==="xasset_directory_validated"||serverProof?.state==="xasset_directory_validated"?"Verified directory":clientProof?.state==="empty_expanded_stream"?"Empty expanded":serverProof?.state==="unsigned_xchunks_decoded_directory_unresolved"?"Decompressed":clientProof?.state||serverProof?.state?"Parse issue":ipak?.status==="ipak_index_validated"?"IPAK index":sound?.status==="bank_entry_index_validated"?"Audio index":wadFull?.state==="full_original_wad_byte_ownership_and_zlib_verified"?"WAD bytes owned":wad?.status==="wad_directory_validated"?"WAD directory":ipak||sound||wad?"Index issue":verifiedHeader||sourceHeader?"Header checked":"Indexed only"));tr.onclick=()=>{inspect(item);render()};tr.onkeydown=e=>{if(e.key==="Enter"){inspect(item);render()}};tbody.append(tr)}$("empty").hidden=filtered.length!==0;$("family").style.display=game==="bo2"?"":"none";$("xasset").style.display=game==="bo2"&&typeInventory?"":"none";renderTypeInventory();$("loaded").textContent=fmt(items.length);$("observed").textContent=fmt(games.find(x=>x.id===game).observed);$("heading").textContent=games.find(x=>x.id===game).name+" · original files";$("pageNote").textContent=(filtered.length>500?"Showing first 500 matched rows. ":"")+"Filtering "+fmt(items.length)+" loaded file records; "+fmt(filtered.length)+" match. Full prefix count from Oct 27 snapshot: "+fmt(games.find(x=>x.id===game).observed)+".";
$("more").disabled=!hasMore||busy;$("more").textContent=busy?"Reading R2 listing…":hasMore?"Load next 400 files":"All objects in this collection loaded";
const types={};for(const f of items)types[f.extension]=(types[f.extension]||0)+1;const keys=Object.keys(types).sort((a,b)=>types[b]-types[a]);const current=$("type").value;$("type").replaceChildren();$("type").append(el("option","","All extensions"));$("type").firstChild.value="";keys.sort().forEach(k=>{const o=el("option","",k+" ("+types[k]+")");o.value=k;$("type").append(o)});$("type").value=keys.includes(current)?current:"";
const bars=$("typeBars");bars.replaceChildren();const max=Math.max(1,...Object.values(types));Object.entries(types).sort((a,b)=>b[1]-a[1]).slice(0,12).forEach(([k,n])=>{const row=el("div","typerow");row.append(el("span","mono",k));const track=el("div","track"),fill=el("span");fill.style.width=(n/max*100)+"%";track.append(fill);row.append(track,el("span","mono",fmt(n)));bars.append(row)});if(!items.length)bars.textContent="No files loaded yet."}
async function more(){if(busy||!hasMore)return;const target=game;busy=true;render();
 try{const params=new URLSearchParams({game,limit:"400"});if(cursor)params.set("cursor",cursor);
 const res=await fetch("/api/files?"+params.toString(),{cache:"no-store"});
 if(!res.ok)throw Error("R2 metadata request failed: "+res.status);
 const data=await res.json();if(target!==game)return;
 items.push(...data.files);cursor=data.cursor;hasMore=data.truncated;
 }catch(e){if(target===game)$("pageNote").textContent="R2 metadata request failed: "+e.message;return}
 finally{if(target===game){busy=false;render();if(game==="bo2"&&hasMore)more()}}
}
function select(id){game=id;items=[];cursor=null;hasMore=true;chosen=null;$("find").value="";$("type").value="";$("family").value="";$("xasset").value="";nav();inspect(null);render();loadProofIndex();loadHeaderSurvey();loadClientCorpus();loadServerCorpus();loadTypeInventory();loadSourceHeaders();loadNestedDirectories();more()}
$("find").oninput=render;$("type").onchange=render;$("family").onchange=render;$("xasset").onchange=render;$("more").onclick=more;nav();render();loadProofIndex();loadHeaderSurvey();loadClientCorpus();loadServerCorpus();loadTypeInventory();loadSourceHeaders();loadNestedDirectories();more();
</script></body></html>`;
function fileExtension(key) {
  const name = key.slice(key.lastIndexOf("/") + 1);
  const at = name.lastIndexOf(".");
  return at > 0 ? name.slice(at+1).toLowerCase() : "(none)";
}
export default {
  async fetch(request, env) {
    if(request.method !== "GET") return asJson({error:"Read-only explorer"},405);
    const url = new URL(request.url);
    if(url.pathname==="/api/games") return asJson({schema:"source-observatory/v1",snapshot_date:"2026-10-27",games:GAMES});
    if(url.pathname==="/api/t6/wads/full"){
      try{const j=await getProof("wad-full.json");return j?.schema==="source-observatory/t6-wad-full-byte-accounting/v1"&&j?.files?.length===366?asJson(j):asJson({error:"Complete WAD byte proof not yet published"},404)}
      catch(e){return asJson({error:"Original WAD physical byte report unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/wads"){
      try{const j=await getProof("wad-index.json");return j?.schema==="source-observatory/t6-wad-index/v1"&&j?.files?.length===366?asJson(j):asJson({error:"WAD directory report pending"},404)}
      catch(e){return asJson({error:"WAD directory report unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/ipaks"){
      try{const j=await getProof("ipak-index.json");return j?.schema==="source-observatory/t6-ipak-index/v1"&&j?.files?.length===23?asJson(j):asJson({error:"IPAK proof unavailable"},404)}
      catch(e){return asJson({error:"IPAK index cannot be loaded",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/sound-banks"){
      try{const j=await getProof("sound-bank-index.json");return j?.schema==="source-observatory/t6-sound-bank-index/v1"&&j?.files?.length===116?asJson(j):asJson({error:"Sound bank proof unavailable"},404)}
      catch(e){return asJson({error:"Sound bank index cannot be loaded",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/source-headers"){
      try{const j=await getProof("all-source-headers.json");
      return j?.schema==="source-observatory/original-r2-signature-corpus/v1"&&j?.files?.length===1287?asJson(j):asJson({error:"Full original R2 signature inventory not yet published"},404)}
      catch(e){return asJson({error:"Original source header inventory unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/types"){
      try{const j=await getProof("type-inventory.json");
      return j?.schema==="source-observatory/t6-asset-types/v1"&&j?.files_with_eligible_directory_scan===571?asJson(j):asJson({error:"Full XAsset type inventory not yet published"},404)}
      catch(e){return asJson({error:"T6 type index unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/server-corpus"){
      try{const p=await getProof("server-corpus.json");return p?.schema==="source-observatory/t6-server-corpus/v1"&&p?.files?.length===356?asJson(p):asJson({error:"Remote server corpus evidence not published yet"},404)}
      catch(e){return asJson({error:"Server corpus unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/client-corpus"){
      try{const p=await getProof("client-corpus.json");return p?.schema==="source-observatory/t6-client-corpus/v1"&&p?.files?.length===215?asJson(p):asJson({error:"Remote full-client scan has not published 215 accountable reports yet"},404)}
      catch(e){return asJson({error:"Client corpus unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/headers"){
      try {const p=await getProof("header-survey.json");return p?.schema==="source-observatory/t6-header-survey/v1"?asJson(p):asJson({error:"No complete original R2 signature survey published"},404)}
      catch(e){return asJson({error:"Header survey unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/index"){
      try {const proof=await getProof("index.json");return proof?.schema==="source-observatory/t6-index/v1"?asJson(proof):asJson({error:"No completed runner evidence index has been published"},404)}
      catch(e){return asJson({error:"Source proof index unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/t6/report"){
      const key=url.searchParams.get("key")||"";
      const found=/^bo2\/zone\/all\/([a-z0-9_]+)\.ff$/.exec(key);
      if(!found)return asJson({error:"Only allowlisted T6 source identities accepted"},400);
      try {const idx=await getProof("index.json");const row=idx?.files?.find(x=>x.source_key===key);
        if(!row||row.report_file!==found[1]+".json")return asJson({error:"No verified report for this original R2 object"},404);
        const proof=await getProof(row.report_file);
        if(proof?.schema!=="source-observatory/t6-expanded/v1"||proof.source?.r2_key!==key||proof.source?.sha256!==row.source_sha256)return asJson({error:"Proof identity mismatch"},409);
        return asJson(proof)}
      catch(e){return asJson({error:"Authenticated report unavailable",detail:String(e)},503)}
    }
    if(url.pathname==="/api/files"){
      const game = GAMES.find(x=>x.id===url.searchParams.get("game"));
      if(!game) return asJson({error:"Unknown source collection"},400);
      const limit = Math.min(400,Math.max(1,Number(url.searchParams.get("limit")||400)));
      const cursor = url.searchParams.get("cursor");
      if(cursor && (cursor.length>2048 || !/^[A-Za-z0-9_+=.\/-]+$/.test(cursor))) return asJson({error:"Invalid cursor"},400);
      try{
        const options={prefix:game.prefix,limit,include:[]};
        if(cursor)options.cursor=cursor;
        const result=await env.SOURCES.list(options);
        const files=result.objects.filter(o=>o.key!==game.prefix&&!o.key.endsWith("/")).map(o=>({
          key:o.key,path:o.key.slice(game.prefix.length),bytes:o.size,extension:fileExtension(o.key),
          uploaded:o.uploaded?o.uploaded.toISOString():null,etag:o.etag||null,
          coverage:{inventory:"metadata-indexed",structure:"not-evaluated",byte_ranges:"not-evaluated",semantics:"not-evaluated"}
        }));
        return asJson({schema:"source-observatory/v1",game:game.id,files,truncated:result.truncated,cursor:result.truncated?result.cursor:null,proof_boundary:"Metadata listing only. No original bytes examined."});
      }catch(e){return asJson({error:"R2 listing unavailable; no completeness claim",detail:String(e)},503)}
    }
    if(url.pathname==="/" || url.pathname==="/index.html") return new Response(PAGE,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"public, max-age=300","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"}});
    return new Response("Not found",{status:404});
  }
};
