"use strict";
(()=>{
const CHUNK=4194304, listEl=$("#filelist"), queue=$("#requestlist"), status=$("#vaultstatus"), progress=$("#fileprogress"), pick=$("#filepick"), publish=$("#publish"), player=$("#vaultplayer"), panel=$("#playerpanel");
let generation=0, active=false, host=false, signature="", refreshing=false, pending=null, ticket=null, objectURL=null;
const show=t=>status.textContent=t;
const bytes=n=>{const a=["B","KiB","MiB","GiB","TiB","PiB"];let i=0;while(n>=1024&&i<a.length-1){n/=1024;i++;}return n.toFixed(i?2:0)+" "+a[i];};
function pct(n,total){progress.max=1;progress.value=total?n/total:1;show(bytes(n)+" / "+bytes(total));}
async function request(path,options={}){const r=await fetch(path,{cache:"no-store",credentials:"same-origin",...options});if(!r.ok){let msg="HTTP "+r.status;try{msg=(await r.json()).error||msg;}catch{}throw Error(msg);}return r;}
const post=async(path,d)=>await(await request(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)})).json();
function check(g){if(!room||g!==generation)throw Error("Transfer locked or cancelled");}
function controls(){publish.disabled=!room||active||!!pending;pick.disabled=!room||active||!!pending;publish.textContent=host?"SHARE FILE":"SEND REQUEST";$("#uploadhint").textContent=!room?"Unlock in Keys first.":host?"Choose a file to share.":"Host must approve first.";}
function begin(){if(active)throw Error("Wait for the current transfer");if(!room)throw Error("Unlock in Keys first");active=true;controls();return generation;}
function end(){active=false;controls();progress.value=0;}
function text(tag,t,cls){const el=document.createElement(tag);el.textContent=t;if(cls)el.className=cls;return el;}
function button(t,fn){const b=text("button",t);b.type="button";b.onclick=()=>{try{Promise.resolve(fn()).catch(e=>show(e.message));}catch(e){show(e.message);}};return b;}
function navigate(tab){document.body.dataset.tab=tab;for(const b of document.querySelectorAll("[data-tabtarget]"))b.setAttribute("aria-pressed",String(b.dataset.tabtarget===tab));$("#filevault").hidden=tab!=="files";$("#chatview").hidden=tab!=="chat";$("#keypanelwrap").hidden=tab!=="keys";$("#systemview").hidden=tab!=="system";if(tab==="files")refresh(true);if(tab!=="system"&&$("#quality").value!=="off"){$("#quality").value="off";$("#quality").dispatchEvent(new Event("change"));}}
for(const b of document.querySelectorAll("[data-tabtarget]"))b.onclick=()=>navigate(b.dataset.tabtarget);
async function infoFor(f){if(room)try{return await SCrypto.metadata(f);}catch{}return null;}
async function remove(f){if(!confirm("Delete shared copy or request? Original file stays untouched."))return;await post("/api/vault/"+f.id+"/delete",{});if(pending?.id===f.id){pending=null;controls();}await revoke();signature="";refresh(true);show("Removed.");}
function card(f,info,req){const item=text("article","","filecard"),line=text("div","","fileinfo");line.append(text("span",info?info.meta.name:"ENCRYPTED FILE "+f.id.slice(0,8),"filename"),text("small",bytes(f.size)+" | "+f.owner.toUpperCase()+" | "+(req?f.state.toUpperCase():info?"READY":"LOCKED")));if(req&&info)line.append(text("small","Type: "+info.meta.mime+" | Requested: "+f.created));const actions=text("div","","fileactions");
 if(req){if(host&&f.state==="pending"){if(info)actions.append(button("ACCEPT",async()=>{await post("/api/vault/"+f.id+"/approve",{});signature="";refresh(true);show("Accepted.");}));actions.append(button("REJECT",async()=>{await post("/api/vault/"+f.id+"/reject",{});signature="";refresh(true);}));}else if(f.state==="upload"&&pending?.id!==f.id&&f.owner===me)actions.append(text("small","Cancel and send the request again."));actions.append(button("CANCEL",()=>remove(f)));}
 else{if(info){actions.append(button("DOWNLOAD",()=>download(f,info)),button("PREVIEW",()=>stream(f,info)));}actions.append(button("DELETE",()=>remove(f)));}item.append(line,actions);return item;}
async function refresh(force=false){if(refreshing)return;refreshing=true;const g=generation;try{const d=await(await request("/api/vault")).json();if(g!==generation)return;host=d.host;controls();$("#hostpriv").textContent=host?"HOST":"RECEIVER";$("#requestcount").textContent=String(d.requests.filter(f=>f.state==="pending").length);
 if(pending){const r=d.requests.find(x=>x.id===pending.id);if(r?.state==="upload"&&!active){const p=pending;pending=null;uploadApproved(p).catch(e=>show(e.message));}else if(!r||r.state==="rejected"){pending=null;controls();show("Upload rejected or cancelled.");}}
 const sig=JSON.stringify([d.files,d.requests])+SCrypto.count()+String(!!room);if(!force&&sig===signature)return;signature=sig;
 const a=[],b=[];for(const f of d.files){const info=await infoFor(f);if(g!==generation)return;a.push(card(f,info,false));}for(const f of d.requests){const info=await infoFor(f);if(g!==generation)return;b.push(card(f,info,true));}
 listEl.replaceChildren(...(a.length?a:[text("p","No shared files.","emptyvault")]));queue.replaceChildren(...(b.length?b:[text("p","No pending requests.","emptyvault")]));
 }catch(e){show(e.message);}finally{refreshing=false;}}
async function upload(file){if(!file)return;try{await window.pvSync();}catch(e){show(e.message);return;}const g=begin();let id=null;try{const k=room;id=k.epoch.toString(16).padStart(8,"0")+SCrypto.hex(SCrypto.rnd(12));const fk=await SCrypto.fileKey(k,id);const meta=SCrypto.b64(await SCrypto.encrypt(fk,id,file.size,"meta",SCrypto.enc.encode(JSON.stringify({name:file.name,mime:file.type||"application/octet-stream"}))));check(g);const r=await post("/api/vault/create",{id,size:file.size,meta});check(g);pending={id,file,fk,g};if(r.state==="pending")show("Waiting for approval. Keep this page open.");else show("Preparing file.");}catch(e){show(e.message);}finally{end();refresh(true);}}
async function uploadApproved(p){const g=begin();try{check(p.g);for(let pos=0,i=0;pos<p.file.size;pos+=CHUNK,i++){check(g);const plain=await p.file.slice(pos,pos+CHUNK).arrayBuffer(),encrypted=await SCrypto.encrypt(p.fk,p.id,p.file.size,i,plain);check(g);await request("/api/vault/"+p.id+"/chunk/"+i,{method:"POST",headers:{"Content-Type":"application/octet-stream"},body:encrypted});pct(Math.min(pos+CHUNK,p.file.size),p.file.size);}check(g);await post("/api/vault/"+p.id+"/finish",{});show("File saved on host.");}catch(e){show(e.message+"; cancel the incomplete request before retrying.");}finally{end();pick.value="";signature="";refresh(true);}}
publish.onclick=()=>upload(pick.files[0]).catch(e=>show(e.message));
async function parts(f,info,g,writer){const arr=[];for(let pos=0,i=0;pos<f.size;pos+=CHUNK,i++){check(g);const r=await request("/api/vault/"+f.id+"/chunk/"+i),plain=await SCrypto.decrypt(info.fk,f.id,f.size,i,await r.arrayBuffer());check(g);if(plain.byteLength!==Math.min(CHUNK,f.size-pos))throw Error("Invalid length");if(writer)await writer.write(plain);else arr.push(plain);pct(pos+plain.byteLength,f.size);}return arr;}
function safeName(n){return n.replace(/[<>:"/\\|?*\u0000-\u001f]/g,"_")||"download";}
async function download(f,info){if(false){const g=begin();let writer;try{const handle=await showSaveFilePicker({suggestedName:safeName(info.meta.name)});writer=await handle.createWritable();await parts(f,info,g,writer);check(g);await writer.close();writer=null;show("Download complete.");}catch(e){if(writer)await writer.abort().catch(()=>{});show(e.message);}finally{end();}return;}
 if(f.size<=128*1024*1024){const g=begin();try{const arr=await parts(f,info,g);check(g);const url=URL.createObjectURL(new Blob(arr,{type:"application/octet-stream"})),a=document.createElement("a");a.href=url;a.download=safeName(info.meta.name);document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);show("Download ready.");}finally{end();}return;}
 const t=await authorize(f,info,"download");if(!t)return;const a=document.createElement("a");a.href=t.url;a.referrerPolicy="no-referrer";document.body.append(a);a.click();a.remove();show("Host-assisted download started. File key expires in one hour.");}
async function authorize(f,info,mode){if(!room)throw Error("Load key first");if(!confirm("Host-assisted "+mode+": the host temporarily receives only this file's decryption key in memory. Message and room keys remain private. Use only if you trust the host and have verified its HTTPS certificate. Continue?"))return null;const g=generation,raw=await crypto.subtle.exportKey("raw",info.fk);try{check(g);const t=await post("/api/vault/"+f.id+"/ticket",{key:SCrypto.b64(raw),mode});if(g!==generation){await post("/api/vault/revoke",{token:t.token});throw Error("Locked");}return t;}finally{new Uint8Array(raw).fill(0);}}
async function revoke(){resetPreview();player.pause();player.removeAttribute("src");player.load();panel.hidden=true;if(objectURL){URL.revokeObjectURL(objectURL);objectURL=null;}const old=ticket;ticket=null;if(old)try{await post("/api/vault/revoke",{token:old.token});}catch{}}
let previewEpoch=0,previewAbort=null,previewURL=null,sourceInfo=null,pageNumber=0,pageCount=0,watchdog=0,compatRunning=false;
const previewImage=$("#previewimage"),previewText=$("#previewtext"),previewNote=$("#previewnote"),previewTitle=$("#previewtitle"),pdfTools=$("#pdfnav"),compat=$("#compat"),full=$("#fullscreen");
function note(s){previewNote.textContent=s;show(s);}
function resetPreview(){previewEpoch++;clearTimeout(watchdog);if(previewAbort)previewAbort.abort();previewAbort=null;compatRunning=false;sourceInfo=null;player.pause();player.removeAttribute("src");player.load();player.hidden=true;previewImage.removeAttribute("src");previewImage.hidden=true;previewText.textContent="";previewText.hidden=true;pdfTools.hidden=true;compat.hidden=true;previewTitle.textContent="PLAYER";if(previewURL)URL.revokeObjectURL(previewURL);previewURL=null;}
function previewBlob(blob,element){if(previewURL)URL.revokeObjectURL(previewURL);previewURL=URL.createObjectURL(blob);element.src=previewURL;element.hidden=false;}
const videoExt=/\.(mp4|m4v|mov|mkv|webm|avi|mts|m2ts|mpeg|mpg|ts|wmv|flv|ogv|3gp)$/i;
const audioExt=/\.(mp3|m4a|aac|wav|ogg|opus|flac|aiff|wma)$/i;
const imageTypes={png:"image/png",jpg:"image/jpeg",jpeg:"image/jpeg",gif:"image/gif",webp:"image/webp",avif:"image/avif",bmp:"image/bmp",ico:"image/x-icon"};
const textExt=/\.(txt|csv|tsv|json|xml|html|htm|css|js|ts|py|c|cpp|h|hpp|java|md|log|ini|yaml|yml|sql|sh|bat|ps1|rtf|svg)$/i;
async function compatPlay(){
 if(!sourceInfo||!ticket||compatRunning)return;
 const e=previewEpoch;compatRunning=true;clearTimeout(watchdog);player.pause();player.removeAttribute("src");player.load();player.hidden=true;compat.disabled=true;
 previewAbort=new AbortController();note("Preparing H.264 preview. Original unchanged.");
 try{const r=await request("/api/vault/preview/"+ticket.token,{signal:previewAbort.signal});const b=await r.blob();if(e!==previewEpoch)return;previewBlob(b,player);note("H.264 preview · original file unchanged.");player.play().catch(()=>note("Press play."));}
 catch(err){if(e===previewEpoch)note(err.message);}
 finally{if(e===previewEpoch){compatRunning=false;compat.disabled=false;}}
}
async function pdfPage(n){
 if(!ticket)return;const e=previewEpoch;note("Loading page "+(n+1));const d=await(await request("/api/vault/preview/"+ticket.token+"/"+n)).json();if(e!==previewEpoch)return;
 pageNumber=d.page;pageCount=d.pages;previewImage.src="data:image/png;base64,"+d.png;previewImage.hidden=false;pdfTools.hidden=false;$("#pagecount").textContent=(pageNumber+1)+" / "+pageCount;$("#prevpage").disabled=pageNumber===0;$("#nextpage").disabled=pageNumber+1>=pageCount;note("PDF preview");
}
async function stream(f,info){
 if(!room)throw Error("Unlock first");await revoke();
 const e=previewEpoch;sourceInfo={f,info};const name=info.meta.name,ext=name.split(".").pop().toLowerCase(),mime=info.meta.mime.toLowerCase();previewTitle.textContent=name;panel.hidden=false;panel.scrollIntoView({block:"nearest"});
 if(videoExt.test(name)||mime.startsWith("video/")||audioExt.test(name)||mime.startsWith("audio/")||ext==="pdf"){
  const t=await authorize(f,info,"stream");if(!t||e!==previewEpoch){if(t)await post("/api/vault/revoke",{token:t.token});if(e===previewEpoch)panel.hidden=true;return;}ticket=t;
  if(ext==="pdf"){await pdfPage(0);return;}
  const video=videoExt.test(name)||mime.startsWith("video/");compat.hidden=!video;
  if(video&&!["video/mp4","video/webm","video/ogg"].includes(mime)){await compatPlay();return;}
  player.hidden=false;player.src=t.url;note("Loading original file.");player.play().catch(()=>note("Press play."));
  if(video){watchdog=setTimeout(()=>{if(e===previewEpoch&&!compatRunning&&!player.videoWidth)compatPlay();},2500);}
  return;
 }
 if(imageTypes[ext]&&f.size<=64*1024*1024){
  const g=generation;note("Loading image.");const arr=await parts(f,info,g);if(e!==previewEpoch)return;previewBlob(new Blob(arr,{type:imageTypes[ext]}),previewImage);note("Original image.");return;
 }
 if(textExt.test(name)){
  const g=generation;let p=new Uint8Array();if(f.size){const r=await request("/api/vault/"+f.id+"/chunk/0");p=new Uint8Array(await SCrypto.decrypt(info.fk,f.id,f.size,0,await r.arrayBuffer()));}check(g);if(e!==previewEpoch)return;previewText.textContent=new TextDecoder().decode(p.subarray(0,256*1024));previewText.hidden=false;note(f.size>256*1024?"First 256 KiB shown. Download for full file.":"Original text.");return;
 }
 previewText.textContent=name+"\n"+bytes(f.size)+"\n"+mime+"\n\nNo viewer for this format. Download the original file.";previewText.hidden=false;note("File details");
}
compat.onclick=()=>compatPlay();
full.onclick=()=>{if(document.fullscreenElement){document.exitFullscreen?.();return;}if(panel.requestFullscreen){panel.requestFullscreen().catch(()=>note("Fullscreen unavailable in this browser."));}else if(!player.hidden&&player.webkitEnterFullscreen){player.webkitEnterFullscreen();}else note("Fullscreen unavailable in this browser.");};
$("#prevpage").onclick=()=>pdfPage(pageNumber-1).catch(e=>note(e.message));
$("#nextpage").onclick=()=>pdfPage(pageNumber+1).catch(e=>note(e.message));
$("#closeplayer").onclick=()=>revoke();
player.addEventListener("loadedmetadata",()=>{if(panel.hidden||compatRunning||!sourceInfo)return;const video=videoExt.test(sourceInfo.info.meta.name)||sourceInfo.info.meta.mime.startsWith("video/");if(video&&!player.videoWidth){compatPlay();return;}if(video)note((previewURL?"H.264 preview":"Original video")+" · "+player.videoWidth+" × "+player.videoHeight);else note("Original audio.");});
player.addEventListener("error",()=>{if(panel.hidden||compatRunning||!sourceInfo)return;if(!compat.hidden&&!previewURL)compatPlay();else note("Cannot play this format. Download instead.");});
previewImage.addEventListener("error",()=>{if(!panel.hidden)note("Cannot display this image. Download instead.");});
$("#customkey").onclick=async()=>{try{const p=$("#passphrase").value;$("#passphrase").value="";const k=await SCrypto.custom(p);keyField.type="text";keyField.value=k;keyField.select();hint.textContent="Copy the key. Share it privately.";}catch(e){hint.textContent=e.message;}};
window.vaultLocked=()=>{show("Unlock in Keys first.");$("#keycount").textContent="0 loaded";$("#passphrase").value="";generation++;signature="";pending=null;listEl.replaceChildren();queue.replaceChildren();pick.value="";controls();revoke();refresh(true);};
window.vaultKeyChanged=()=>{show("Ready.");generation++;pending=null;signature="";revoke();refresh(true);$("#keycount").textContent=SCrypto.count()+" loaded";controls();};
$("#openkeys").onclick=()=>navigate("keys");navigate("chat");refresh();setInterval(()=>refresh(),2500);
})();