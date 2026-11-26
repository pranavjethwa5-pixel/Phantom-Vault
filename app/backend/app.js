"use strict";
const $=s=>document.querySelector(s);
const box=$("#messages"), statusEl=$("#status"), identity=$("#identity"), form=$("#compose"), input=$("#message"), keyField=$("#roomkey"), hint=$("#keyhint"), send=$("#send"), count=$("#count"), activity=$("#activity");
let last=0, me="", busy=false, room=null, epoch=0, total=0, sending=false;
function refreshEmpty(){const empty=$("#empty");empty.hidden=total>0;$("#emptytitle").textContent=room?"NO MESSAGES":"CHAT LOCKED";$("#emptydesc").textContent=room?"Send a message.":"Open Keys to unlock chat.";count.textContent=String(total).padStart(3,"0")+" MESSAGES";}
function state(open){document.body.dataset.locked=String(!open);$("#footstate").textContent=open?"KEY LOADED":"KEY LOCKED";input.disabled=!open;send.disabled=!open||sending;}
async function api(path,options={}){const r=await fetch(path,{cache:"no-store",...options});if(!r.ok)throw Error("HTTP "+r.status);return r.json();}
function reset(){epoch++;last=0;total=0;box.replaceChildren();refreshEmpty();}
function locked(){SCrypto.clear();room=null;window.vaultLocked?.();sending=false;reset();state(false);input.value="";keyField.value="";keyField.type="password";$("#reveal").setAttribute("aria-pressed","false");statusEl.textContent="LOCKED";activity.textContent="Unlock first";$("#chars").textContent="0 / 4000";}
function add(m,text){const el=document.createElement("article");el.className="msg"+(m.sender===me?" mine":"");const who=document.createElement("div");who.className="who";who.textContent=m.sender.toUpperCase()+" · "+new Date(m.created).toLocaleString();const body=document.createElement("div");body.className="body";body.textContent=text;el.append(who,body);box.append(el);last=m.id;total++;refreshEmpty();}
async function poll(){if(busy||!room)return;busy=true;const current=epoch,k=room;try{const bottom=box.scrollHeight-box.scrollTop-box.clientHeight<100;let data;do{data=await api("/api/messages?after="+last);if(current!==epoch)return;me=data.user;identity.textContent=me.toUpperCase();for(const m of data.messages){let text;try{text=await SCrypto.open(k,m.sender,m.body);}catch(e){text="[Wrong or missing key.]";}if(current!==epoch)return;add(m,text);}}while(data.messages.length===200);if(bottom)box.scrollTop=box.scrollHeight;statusEl.textContent="CONNECTED";$("#sync").textContent=new Date().toLocaleTimeString();activity.textContent=sending?"Sending…":"Ready";}catch(e){if(current===epoch){statusEl.textContent="OFFLINE";activity.textContent=e.message;}}finally{busy=false;}}
$("#generate").onclick=()=>{if(!isSecureContext||!crypto.subtle){hint.textContent="A trusted HTTPS connection is required.";return;}keyField.type="text";$("#reveal").setAttribute("aria-pressed","true");keyField.value=SCrypto.generate();keyField.focus();keyField.select();hint.textContent="Copy the key. Share it privately. Unlock both devices.";};
$("#reveal").onclick=()=>{const visible=keyField.type==="password";keyField.type=visible?"text":"password";$("#reveal").setAttribute("aria-pressed",String(visible));};
$("#unlock").onclick=async()=>{let revision=++epoch;try{if(!isSecureContext||!crypto.subtle)throw Error("A trusted HTTPS connection is required.");const k=await SCrypto.key(keyField.value);if(revision!==epoch)return;room=k;sending=false;reset();const current=epoch;revision=current;keyField.value="";keyField.type="password";$("#reveal").setAttribute("aria-pressed","false");hint.textContent="Unlocked. Old keys work until you lock.";window.vaultKeyChanged?.();const data=await api("/api/messages?after=0");if(current!==epoch||room!==k)return;me=data.user;identity.textContent=me.toUpperCase();state(true);await poll();input.focus();}catch(e){if(revision===epoch){locked();hint.textContent=e.message;}}};
$("#lock").onclick=()=>{locked();hint.textContent="Locked.";keyField.focus();};
form.addEventListener("submit",async e=>{e.preventDefault();try{await window.pvSync();}catch(err){activity.textContent="Key verification failed: "+err.message;return;}const text=input.value.trim(),k=room,current=epoch;if(!text||!k||!me||sending)return;sending=true;state(true);activity.textContent="Encrypting…";try{const body=await SCrypto.seal(k,me,text);if(current!==epoch)return;activity.textContent="Sending…";await api("/api/messages",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({body})});if(current===epoch){if(input.value.trim()===text)input.value="";$("#chars").textContent=input.value.length+" / 4000";activity.textContent="Sent";await poll();box.scrollTop=box.scrollHeight;}}catch(e){if(current===epoch)activity.textContent="Send failed: "+e.message;}finally{if(current===epoch){sending=false;state(true);input.focus();}}});
input.addEventListener("input",()=>{$("#chars").textContent=input.value.length+" / 4000";});
input.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey&&!e.isComposing){e.preventDefault();form.requestSubmit();}});
keyField.addEventListener("keydown",e=>{if(e.key==="Enter")$("#unlock").click();});
setInterval(poll,1500);function clock(){$("#utc").textContent=new Date().toISOString().slice(11,19)+" UTC";}clock();setInterval(clock,1000);locked();
$("#transport").textContent=isSecureContext?"HTTPS":"UNTRUSTED";




(function hostDisplay(){
const video=$("#scene"), q=$("#quality"), motion=$("#motion"), engine=$("#engine"), fps=$("#fps"), resolution=$("#resolution"), adapter=$("#adapter");
const reduced=matchMedia("(prefers-reduced-motion: reduce)");
let epoch=0, current=null, displayHz=60, mode="lo", timer=0, stopped=false;
function wait(ms){return new Promise(r=>setTimeout(r,ms));}
async function get(url,signal){const r=await fetch(url,{cache:"no-store",signal});if(!r.ok)throw Error("HTTP "+r.status);return r;}
function clear(){if(current){current.abort.abort();if(current.url)URL.revokeObjectURL(current.url);current=null;}video.pause();video.removeAttribute("src");video.load();}
function event(el,name,signal,ms=8000){return new Promise((resolve,reject)=>{const done=()=>{clearTimeout(t);el.removeEventListener(name,ok);el.removeEventListener("error",bad);signal.removeEventListener("abort",bad);};const ok=()=>{done();resolve();};const bad=()=>{done();reject(Error("Media interrupted"));};const t=setTimeout(bad,ms);el.addEventListener(name,ok,{once:true});el.addEventListener("error",bad,{once:true});signal.addEventListener("abort",bad,{once:true});if(signal.aborted)bad();});}
function codec(init){
 const b=new Uint8Array(init);
 for(let i=4;i+27<b.length;i++)if(b[i]===104&&b[i+1]===118&&b[i+2]===99&&b[i+3]===67){
   const p=i+4,profile=b[p+1],space=["","A","B","C"][profile>>6],tier=(profile&32)?"H":"L";
   let compat=0;for(let j=0;j<32;j++)if(b[p+2+(j>>3)]&(128>>(j&7)))compat=(compat|(1<<j))>>>0;
   const constraint=Array.from(b.slice(p+6,p+12));while(constraint.length&&constraint[constraint.length-1]===0)constraint.pop();
   const tail=constraint.map(x=>x.toString(16).toUpperCase()).join(".");
   return 'video/mp4; codecs="hvc1.'+space+(profile&31)+'.'+compat.toString(16).toUpperCase()+'.'+tier+b[p+12]+(tail?'.'+tail:'')+'"';
 }
 throw Error("HEVC configuration absent");
}
function list(text){const init=text.match(/#EXT-X-MAP:URI="(init_[0-9]+_(?:hi|lo)\.mp4)"/)?.[1];const seg=text.split(/\r?\n/).filter(x=>/^seg_[0-9]+_[0-9]{8}\.m4s$/.test(x));return {init,seg};}
let profile=null;
function selected(){if(q.value==="off"||motion.value==="reduced"||(motion.value==="auto"&&reduced.matches))return "off";return profile?.mode||"off";}
async function profileInit(){try{const r=await fetch("/api/display-profile",{cache:"no-store"});if(!r.ok)throw Error("HTTP "+r.status);profile=await r.json();q.options[0].textContent=profile.fps+" FPS · 1080p · HEVC";restart();}catch(e){engine.textContent="VIDEO UNAVAILABLE";setTimeout(profileInit,2500);}}
async function run(which,token){
 clear();mode=which;video.hidden=which==="off";if(which==="off"){engine.textContent="STATIC";return;}
 const abort=new AbortController(),signal=abort.signal,session={abort,url:null};current=session;
 const base="/media/"+which+"/";let ms,sb,last="",initName="",seen=new Set();
 try{
   if(!window.MediaSource)throw Error("MediaSource unavailable");
   engine.textContent="CONNECTING";
   while(token===epoch&&!signal.aborted){
     const playlist=list(await (await get(base+"live.m3u8",signal)).text());
     if(!playlist.init||!playlist.seg.length){await wait(400);continue;}
     if(initName&&initName!==playlist.init)throw Error("Host restarted");
     if(!ms){
       initName=playlist.init;
       const init=await (await get(base+initName,signal)).arrayBuffer(), mime=codec(init);
       if(!MediaSource.isTypeSupported(mime))throw Error("HEVC profile unsupported on this browser");
       ms=new MediaSource();session.url=URL.createObjectURL(ms);const opened=event(ms,"sourceopen",signal);video.src=session.url;await opened;sb=ms.addSourceBuffer(mime);sb.mode="sequence";
       const ready=event(sb,"updateend",signal);sb.appendBuffer(init);await ready;
     }
     let pending=playlist.seg.filter(s=>!seen.has(s));
     if(!last)pending=pending.slice(-2);
     else if(!playlist.seg.includes(last)&&pending.length>3)throw Error("Stream fell behind");
     for(const s of pending){const data=await (await get(base+s,signal)).arrayBuffer();const ready=event(sb,"updateend",signal);sb.appendBuffer(data);await ready;seen.add(s);last=s;}
     for(const old of seen)if(!playlist.seg.includes(old))seen.delete(old);
     if(video.buffered.length){const start=video.buffered.start(0),end=video.buffered.end(video.buffered.length-1);if(video.currentTime<start||end-video.currentTime>3.5)video.currentTime=Math.max(start,end-1.6);
       if(video.paused)video.play().catch(()=>{engine.textContent="PRESS PLAY";});
       if(start+6<video.currentTime&&!sb.updating){const ready=event(sb,"updateend",signal);sb.remove(start,video.currentTime-3);await ready;}
     }
     engine.textContent=which==="hi"?"HEVC · 240 FPS":"HEVC · 120 FPS";
     await wait(550);
   }
 }catch(e){if(token!==epoch||signal.aborted)return;console.warn("Host stream:",e.message);engine.textContent="RECONNECTING";if(e.message.includes("unsupported")||e.message.includes("MediaSource unavailable")){engine.textContent="HEVC NOT SUPPORTED";video.hidden=true;return;}timer=setTimeout(restart,1800);}
}
function restart(){clearTimeout(timer);epoch++;clear();if(document.hidden){video.hidden=true;engine.textContent="PAUSED";return;}run(selected(),epoch);}
q.addEventListener("change",restart);motion.addEventListener("change",()=>{document.body.dataset.motion=motion.value==="reduced"?"reduced":motion.value==="full"?"full":"auto";restart();});reduced.addEventListener("change",restart);document.addEventListener("visibilitychange",restart);
video.addEventListener("click",()=>video.play().catch(()=>{}));
async function telemetry(){try{const s=await (await fetch("/media/stats.json",{cache:"no-store"})).json();if(Date.now()/1000-s.timestamp>8)throw Error("stale");fps.textContent=s.fps.toFixed(1)+" / "+s.target;resolution.textContent=s.width+" × "+s.height;adapter.textContent=s.gpu.replace("/PCIe/SSE2","");}catch(e){fps.textContent="—";resolution.textContent="—";adapter.textContent="Host offline";}}
setInterval(telemetry,2500);telemetry();profileInit();
})();
