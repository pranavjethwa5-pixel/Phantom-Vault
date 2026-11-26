"use strict";
const {app,BrowserWindow,ipcMain,session,clipboard,safeStorage,dialog}=require("electron");
const fs=require("node:fs"),path=require("node:path"),os=require("node:os"),crypto=require("node:crypto"),net=require("node:net"),https=require("node:https");
const {spawn,execFileSync}=require("node:child_process");
const {Channel,selftest,sha:securityHash}=require("./security14.cjs");
const BASE=__dirname, BACK=path.join(BASE,"backend"), PORT=9543, AUDIT=process.argv.includes("--pv-audit"),AUDIT_IPV6=AUDIT&&process.argv.includes("--pv-audit-ipv6");
if(AUDIT)app.setPath("userData",path.join(os.tmpdir(),"pv-audit-"+crypto.randomBytes(8).toString("hex")));
else app.setPath("userData",path.join(process.env.LOCALAPPDATA||app.getPath("appData"),"PhantomVaultDesktop_R14"));
let launcher,child=null,hostWin=null,activeInvite="",closing=false;
const windows=new Set();
const roomDir=()=>path.join(app.getPath("userData"),"room");
const sha=s=>crypto.createHash("sha256").update(s).digest("hex");
const pwHash=(p,s)=>crypto.pbkdf2Sync(p,Buffer.from(s,"hex"),310000,32,"sha256").toString("hex");
function validName(n){if(typeof n!=="string"||!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$/.test(n))throw Error("Use 1-32 letters, numbers, spaces, dots or hyphens for your name.");return n;}
function validPass(p){if(typeof p!=="string"||p.length<12||p.length>128)throw Error("Server password must be 12-128 characters.");return p;}
function validKey(k){if(typeof k!=="string"||! /^[A-Za-z0-9+/]{43}=$/.test(k)||Buffer.from(k,"base64").length!==32||Buffer.from(k,"base64").toString("base64")!==k)throw Error("Enter the complete 32-byte AES key (44 base64 characters).");return k;}
function canonIP(s){if(net.isIP(s)!==6||s.includes("%"))throw Error("Invalid IPv6 address.");return new URL("https://["+s+"]").hostname.slice(1,-1);}
function addresses(){const list=[];try{const cmd="Get-NetIPAddress -AddressFamily IPv6 | Where-Object {$_.AddressState -eq 'Preferred' -and !$_.SkipAsSource -and $_.IPAddress -match '^[23]'} | Sort-Object @{Expression={if($_.SuffixOrigin -eq 'Random'){1}else{0}}} | Select-Object -ExpandProperty IPAddress";for(const x of execFileSync("powershell.exe",["-NoProfile","-NonInteractive","-Command",cmd],{encoding:"utf8",windowsHide:true,timeout:8000}).trim().split(/\r?\n/)){if(x.trim())list.push(canonIP(x.trim()));}}catch{}if(!list.length)for(const group of Object.values(os.networkInterfaces()))for(const a of group||[])if(a.family==="IPv6"&&!a.internal&&/^[23]/.test(a.address))list.push(canonIP(a.address));return [...new Set(list)];}
function makeInvite(ip,port,fp){return "PV2."+Buffer.from(JSON.stringify({ip,port,fp}),"utf8").toString("base64url");}
function parseInvite(s){if(typeof s!=="string"||s.length>1024||!s.startsWith("PV2."))throw Error("Paste the host's Phantom Vault invitation.");let i;try{i=JSON.parse(Buffer.from(s.slice(4),"base64url").toString("utf8"));}catch{throw Error("Invalid invitation.");}i.ip=canonIP(i.ip);if(!Number.isInteger(i.port)||i.port<1024||i.port>65535||! /^[a-f0-9]{64}$/.test(i.fp))throw Error("Invalid invitation details.");return i;}
function tlsFp(file){return securityHash(new crypto.X509Certificate(fs.readFileSync(file)).publicKey.export({format:"der",type:"spki"}));}
function pythonEnv(config){const rt=path.join(BASE,"runtime");return {...process.env,PYTHONHOME:path.join(rt,"python"),PYTHONPATH:path.join(BASE,"pydeps"),PYTHONNOUSERSITE:"1",PYTHONUNBUFFERED:"1",PYTHONOPTIMIZE:"0",PV_ROOM_CONFIG:config,PATH:[path.join(rt,"node"),path.join(rt,"ffmpeg"),process.env.PATH].join(path.delimiter)};}
function spawnPy(script,args,env){return spawn(path.join(BASE,"runtime","python","python.exe"),[path.join(BACK,script),...args],{cwd:BACK,env,windowsHide:true,stdio:["ignore","pipe","pipe"]});}
function waitProc(p){return new Promise((resolve,reject)=>{let err="";p.stderr.on("data",d=>err=(err+d).slice(-3000));p.once("error",reject);p.once("exit",c=>c===0?resolve():reject(Error("Host runtime failed: "+err)));});}
function waitReady(p){return new Promise((resolve,reject)=>{let err="",out="",settled=false;const t=setTimeout(()=>done(Error("Host did not start.")),15000);function done(e){if(settled)return;settled=true;clearTimeout(t);e?reject(e):resolve();}p.stdout.on("data",d=>{out+=d;if(out.includes("PHANTOM READY"))done();});p.stderr.on("data",d=>err=(err+d).slice(-2000));p.once("error",done);p.once("exit",()=>done(Error("Host could not listen: "+err)));});}
function setSavedInvite(s){fs.mkdirSync(app.getPath("userData"),{recursive:true});fs.writeFileSync(path.join(app.getPath("userData"),"last-invite.txt"),s);}
function savedInvite(){try{return fs.readFileSync(path.join(app.getPath("userData"),"last-invite.txt"),"utf8");}catch{return "";}}
function verifySession(ses,info){const target=canonIP(info.ip);ses.setCertificateVerifyProc((req,cb)=>{try{const h=canonIP(req.hostname.replace(/^\\[|\\]$/g,""));const cert=new crypto.X509Certificate(req.certificate.data),fp=securityHash(cert.publicKey.export({format:"der",type:"spki"})),now=Date.now();cb(h===target&&fp===info.fp&&!!cert.checkIP(target)&&cert.verify(cert.publicKey)&&now>=Date.parse(cert.validFrom)&&now<=Date.parse(cert.validTo)?0:-2);}catch{cb(-2);}});}
async function openRoom(info,name,credential,key,role,show=true,identityOverride=null){
    const origin="https://["+info.ip+"]:"+info.port, ses=session.fromPartition("pv-"+crypto.randomUUID(),{cache:false});
    verifySession(ses,info);
    const channel=new Channel({ses,info,name,credential,key,dir:app.getPath("userData"),safeStorage,identityOverride});
    try{await channel.enroll();}catch(e){channel.close();throw e;}
    ses.webRequest.onBeforeRequest((d,cb)=>{try{const u=new URL(d.url);cb({cancel:!["blob:","data:"].includes(u.protocol)&&u.origin!==origin});}catch{cb({cancel:true});}});
    ses.setPermissionRequestHandler((_wc,_p,cb)=>cb(false));ses.setPermissionCheckHandler(()=>false);
    // UI is distributed with the desktop application, never supplied by the remote host.
    const assets={"/":["index.html","text/html; charset=utf-8"],"/style.css":["style.css","text/css; charset=utf-8"],"/app.js":["app.js","application/javascript; charset=utf-8"],"/crypto.js":["crypto.js","application/javascript; charset=utf-8"],"/vault.js":["vault.js","application/javascript; charset=utf-8"],"/security-ui.js":["security-ui.js","application/javascript; charset=utf-8"]};
    const csp="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; media-src 'self' blob:; img-src 'self' blob: data:; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    ses.protocol.handle("https",async req=>{
        const u=new URL(req.url);if(u.origin!==origin)return new Response("Forbidden",{status:403});
        if(req.method==="GET"&&assets[u.pathname]){const [file,type]=assets[u.pathname];return new Response(fs.readFileSync(path.join(BACK,file)),{headers:{"Content-Type":type,"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Content-Security-Policy":csp}});}
        return channel.route(req);
    });
    const w=new BrowserWindow({title:"Phantom Vault R14 | "+role,width:1280,height:880,minWidth:420,minHeight:560,show:false,autoHideMenuBar:true,backgroundColor:"#030303",webPreferences:{session:ses,nodeIntegration:false,contextIsolation:true,sandbox:true,webSecurity:true,allowRunningInsecureContent:false,backgroundThrottling:false,devTools:false}});
    w.pvChannel=channel;
    windows.add(w);w.on("closed",()=>{channel.close();windows.delete(w);if(hostWin===w){hostWin=null;stopHost();}ses.clearStorageData().catch(()=>{});});
    w.webContents.setWindowOpenHandler(()=>({action:"deny"}));
    w.webContents.on("will-navigate",(e,u)=>{if(u!==origin+"/")e.preventDefault();});
    w.webContents.on("login",(e,_details,_auth,cb)=>{e.preventDefault();cb();});
    try{
        let timer;try{await Promise.race([w.loadURL(origin+"/"),new Promise((_,reject)=>timer=setTimeout(()=>reject(Error("Connection timed out.")),15000))]);}finally{clearTimeout(timer);}
        const result=await w.webContents.executeJavaScript("(async()=>{const r=await fetch('/api/messages?after=0',{cache:'no-store'});if(!r.ok)throw Error('Server rejected login: '+r.status);return (await r.json()).user})()");
        if(result!==name)throw Error("Server identity mismatch.");
        await w.webContents.executeJavaScript("window.pvConnect()");
        for(let i=0;i<60;i++){if(await w.webContents.executeJavaScript("!document.querySelector('#message').disabled"))break;if(i===59)throw Error("Unable to unlock the room.");await new Promise(r=>setTimeout(r,100));}
        if(show)w.show();return w;
    }catch(e){if(!w.isDestroyed())w.destroy();throw e;}
}
function stopHost(){if(child){const p=child;child=null;if(p.exitCode===null)p.kill();}activeInvite="";}
async function startHost(data,show=true){
    if(child)throw Error("Host already running.");
    const name=validName(data.name),password=validPass(data.password),key=validKey(data.key);
    const ips=AUDIT&&!AUDIT_IPV6?["::1"]:addresses();if(!ips.length)throw Error("No usable global IPv6 address detected.");
    const dir=roomDir(),config=path.join(dir,"room.json"),port=AUDIT?19443:PORT;
    fs.mkdirSync(dir,{recursive:true});let cfg,token;
    if(fs.existsSync(config)){
        cfg=JSON.parse(fs.readFileSync(config,"utf8"));
        if(cfg.host_name!==name||pwHash(password,cfg.salt)!==cfg.password_hash)throw Error("Existing local room: use its original host name and server password.");
        if(!safeStorage.isEncryptionAvailable())throw Error("Windows credential protection unavailable.");
        token=safeStorage.decryptString(Buffer.from(cfg.protected_host_token,"base64"));
        cfg.ips=ips;cfg.port=port;
    }else{
        if(!safeStorage.isEncryptionAvailable())throw Error("Windows credential protection unavailable.");
        token=crypto.randomBytes(32).toString("base64url");const salt=crypto.randomBytes(16).toString("hex");
        cfg={host_name:name,salt,password_hash:pwHash(password,salt),host_token_hash:sha(token),protected_host_token:safeStorage.encryptString(token).toString("base64"),ips,port};
        const media=path.resolve(BASE,"..","..","..","..","HostRender_R06_HEVC","media");if(fs.existsSync(media))cfg.media=media;

    }
    await waitProc(spawnPy("make_cert.py",[dir,...new Set(["::1",...ips])],pythonEnv(config)));
    cfg.room_id=tlsFp(path.join(dir,"cert.pem"));
    cfg.bind=AUDIT?ips[0]:"::";
    fs.writeFileSync(config,JSON.stringify(cfg,null,2),{encoding:"utf8"});
    const fp=tlsFp(path.join(dir,"cert.pem"));
    child=spawnPy("server_desktop.py",[],pythonEnv(config));const p=child;
    p.on("exit",()=>{if(child===p){child=null;activeInvite="";if(launcher&&!launcher.isDestroyed())launcher.webContents.send("pv:status","Host stopped.");}});
    try{await waitReady(p);hostWin=await openRoom({ip:AUDIT_IPV6?ips[0]:"::1",port,fp},name,token,key,"HOST",show);
        activeInvite=makeInvite(ips[0],port,fp);if(launcher&&!launcher.isDestroyed())launcher.webContents.send("pv:invite",activeInvite);
        return {invite:activeInvite,address:ips[0],port};
    }catch(e){stopHost();throw e;}
}
async function join(data,show=true){const info=parseInvite(data.invite),name=validName(data.name),password=validPass(data.password),key=validKey(data.key);const w=await openRoom(info,name,password,key,"RECEIVER",show);setSavedInvite(data.invite);return w;}
function trusted(event){if(!launcher||event.sender!==launcher.webContents||event.senderFrame.url!==launcher.webContents.getURL())throw Error("Invalid caller");}
function setupIPC(){const handle=(n,f)=>ipcMain.handle("pv:"+n,async(e,d)=>{trusted(e);try{return {ok:true,value:await f(d)}}catch(e){return {ok:false,error:e.message}}});
handle("info",()=>({addresses:addresses(),invite:savedInvite(),existing:fs.existsSync(path.join(roomDir(),"room.json"))}));
handle("newroom",()=>{
 if(child)throw Error("Stop the host before creating a new room.");
 const source=roomDir();if(!fs.existsSync(path.join(source,"room.json")))return false;
 const archive=path.join(app.getPath("userData"),"archives","room-"+new Date().toISOString().replace(/[:.]/g,"-")+"-"+crypto.randomBytes(4).toString("hex"));
 fs.mkdirSync(path.dirname(archive),{recursive:true});fs.renameSync(source,archive);return true;
 });
 handle("generate",()=>crypto.randomBytes(32).toString("base64"));
handle("derive",p=>{if(typeof p!=="string"||p.length<16||p.length>256)throw Error("Use a passphrase of 16-256 characters.");return crypto.pbkdf2Sync(p,crypto.randomBytes(32),600000,32,"sha512").toString("base64");});
handle("host",d=>startHost(d,!AUDIT));handle("join",async d=>{await join(d,!AUDIT);return true;});handle("copy",s=>{if(typeof s!=="string"||s.length>1024)throw Error("Invalid text");clipboard.writeText(s);return true;});handle("stop",()=>{if(hostWin&&!hostWin.isDestroyed())hostWin.close();else stopHost();return true;});}
function openLauncher(show=true){launcher=new BrowserWindow({width:900,height:780,minWidth:450,minHeight:600,show:false,title:"Phantom Vault",autoHideMenuBar:true,backgroundColor:"#050505",webPreferences:{preload:path.join(BASE,"preload.cjs"),nodeIntegration:false,contextIsolation:true,sandbox:true,devTools:false}});launcher.webContents.setWindowOpenHandler(()=>({action:"deny"}));launcher.webContents.on("will-navigate",e=>e.preventDefault());if(show)launcher.once("ready-to-show",()=>launcher.show());launcher.on("closed",()=>{launcher=null;if(!closing){closing=true;stopHost();app.quit();}});return launcher.loadFile(path.join(BASE,"launcher.html"));}
async function audit(){
 const assert=require("node:assert/strict");
 const key=crypto.randomBytes(32).toString("base64"),password="audit-"+crypto.randomBytes(16).toString("hex");
 const waitFor=async(w,code,label)=>{for(let i=0;i<120;i++){if(await w.webContents.executeJavaScript(code))return;await new Promise(r=>setTimeout(r,200));}throw Error("Timed out: "+label);};
 let guest;
 try{
   setupIPC();await openLauncher(false);
   await launcher.webContents.executeJavaScript("document.querySelector('#hname').value='HostAudit';document.querySelector('#hpw').value="+JSON.stringify(password)+";document.querySelector('#hkey').value="+JSON.stringify(key)+";document.querySelector('#start').click()");
   for(let i=0;i<120&&!activeInvite;i++){await new Promise(r=>setTimeout(r,200));}
   assert(activeInvite,await launcher.webContents.executeJavaScript("document.querySelector('#status').textContent"));
   const info=parseInvite(activeInvite);
   console.log("PASS launcher, certificate, signed host enrollment and root proof");
   guest=await join({invite:activeInvite,name:"GuestAudit",password,key},false);
   assert.equal(hostWin.pvChannel.epoch,0);assert.equal(guest.pvChannel.epoch,0);
   assert.notEqual(hostWin.pvChannel.pub,guest.pvChannel.pub);
   assert.equal(hostWin.pvChannel.key(0),guest.pvChannel.key(0));
   console.log("PASS distinct authenticated identities, identical derived epoch key");
   const msg=async(w,t)=>w.webContents.executeJavaScript("document.querySelector('[data-tabtarget=chat]').click();document.querySelector('#message').value="+JSON.stringify(t)+";document.querySelector('#compose').requestSubmit()");
   await msg(guest,"R14 original signed message");
   await waitFor(hostWin,"document.querySelector('#messages').textContent.includes('R14 original signed message')","signed message");
   const roles=await Promise.all([hostWin,guest].map(w=>w.webContents.executeJavaScript("fetch('/api/vault').then(r=>r.json()).then(d=>d.host)")));
   assert.deepEqual(roles,[true,false]);console.log("PASS signed encrypted messages, separate host authority");
   const reject=async(fn,label)=>{let failed=false;try{const w=await fn();if(w&&!w.isDestroyed())w.destroy();}catch(e){failed=true;console.log("PASS "+label+" ("+e.message+")");}assert(failed,label);};
   await reject(()=>openRoom({...info,fp:"0".repeat(64)},"WrongPin",password,key,"TEST",false),"incorrect certificate identity rejected");
   await reject(()=>openRoom(info,"WrongRoot",password,crypto.randomBytes(32).toString("base64"),"TEST",false),"incorrect root rejected");
   await reject(()=>openRoom(info,"GuestAudit",password,key,"TEST",false,crypto.generateKeyPairSync("ed25519").privateKey),"same-name identity substitution rejected");
   await reject(()=>openRoom(info,"HostAudit",password,key,"TEST",false),"guest cannot impersonate host");
   const c=guest.pvChannel,p="/api/security/state",opts=c.signedOptions("GET",p,{},Buffer.alloc(0));
   assert.equal((await c.raw(p,opts)).status,200);assert.equal((await c.raw(p,opts)).status,403);
   const tamper=c.signedOptions("POST","/api/security/rotate",{"Content-Type":"application/json"},Buffer.from("{}"));tamper.body=new Uint8Array(Buffer.from('{"tampered":true}'));
   assert.equal((await c.raw("/api/security/rotate",tamper)).status,403);
   const unsigned=await c.raw(p,{headers:{Authorization:"Basic "+Buffer.from("GuestAudit:"+password).toString("base64")}});assert.equal(unsigned.status,403);
   const badsig=c.signedOptions("GET",p,{},Buffer.alloc(0));
   const altered=Buffer.from(badsig.headers.get("X-PV-Signature"),"base64");altered[0]^=1;badsig.headers.set("X-PV-Signature",altered.toString("base64"));
   assert.equal((await c.raw(p,badsig)).status,403);
   console.log("PASS replay, altered body hash, invalid signature and password-only API rejected");
   await guest.webContents.executeJavaScript("document.querySelector('[data-tabtarget=keys]').click();document.querySelector('#generate').click()");
   await waitFor(guest,"document.querySelector('#roomkey').value.includes('EPOCH 1')","guest rotation");
   await waitFor(hostWin,"document.querySelector('#roomkey').value.includes('EPOCH 1')","automatic host synchronization");
   assert.equal(hostWin.pvChannel.key(1),guest.pvChannel.key(1));assert.notEqual(c.key(0),c.key(1));
   await msg(hostWin,"R14 synchronized rotated message");
   await waitFor(guest,"document.querySelector('#messages').textContent.includes('R14 synchronized rotated message')","rotated message");
   console.log("PASS receiver requested signed rotation; host auto-derived matching new key");
   await guest.webContents.executeJavaScript("document.querySelector('[data-tabtarget=files]').click()");
   await hostWin.webContents.executeJavaScript("document.querySelector('[data-tabtarget=files]').click()");
   await waitFor(guest,"!document.querySelector('#filepick').disabled","file picker");
   await guest.webContents.executeJavaScript("(()=>{const d=new DataTransfer();d.items.add(new File(['R14 verified file contents'], 'r14-audit.txt',{type:'text/plain'}));document.querySelector('#filepick').files=d.files;document.querySelector('#publish').click()})()");
   await waitFor(hostWin,"[...document.querySelectorAll('#requestlist button')].some(b=>b.textContent==='ACCEPT')","host approval");
   await hostWin.webContents.executeJavaScript("[...document.querySelectorAll('#requestlist button')].find(b=>b.textContent==='ACCEPT').click()");
   await waitFor(hostWin,"document.querySelector('#filelist').textContent.includes('r14-audit.txt')","encrypted upload");
   await hostWin.webContents.executeJavaScript("[...document.querySelectorAll('#filelist button')].find(b=>b.textContent==='PREVIEW').click()");
   await waitFor(hostWin,"document.querySelector('#previewtext').textContent==='R14 verified file contents'","file preview");
   await hostWin.webContents.executeJavaScript("document.querySelector('#closeplayer').click()");
   console.log("PASS signed encrypted file transfer and preview");
   // Multi-chunk binary test. The deterministic source and downloaded bytes are hashed independently.
   const binarySize=2*4194304+317;
   const binary=Buffer.alloc(binarySize);for(let i=0;i<binary.length;i++)binary[i]=(i*37+(i>>>12))&255;
   const expected=crypto.createHash("sha256").update(binary).digest("hex");
   await guest.webContents.executeJavaScript("(()=>{const size="+binarySize+";const b=new Uint8Array(size);for(let i=0;i<size;i++)b[i]=(i*37+(i>>>12))&255;const d=new DataTransfer();d.items.add(new File([b],'r14-multichunk.bin',{type:'application/octet-stream'}));document.querySelector('#filepick').files=d.files;document.querySelector('#publish').click()})()");
   await waitFor(hostWin,"[...document.querySelectorAll('#requestlist button')].some(b=>b.textContent==='ACCEPT')","binary approval");
   await hostWin.webContents.executeJavaScript("[...document.querySelectorAll('#requestlist button')].find(b=>b.textContent==='ACCEPT').click()");
   await waitFor(hostWin,"document.querySelector('#filelist').textContent.includes('r14-multichunk.bin')","multi-chunk upload");
   const save=path.join(roomDir(),"r14-audit-download.bin");
   const downloadDone=new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(Error("Download timed out")),30000);hostWin.webContents.session.once("will-download",(_e,item)=>{item.setSavePath(save);item.once("done",(_e,state)=>{clearTimeout(timeout);state==="completed"?resolve():reject(Error(state));});});});
   await hostWin.webContents.executeJavaScript("[...document.querySelectorAll('#filelist .filecard')].find(c=>c.textContent.includes('r14-multichunk.bin')).querySelectorAll('button')[0].click()");
   await downloadDone;
   const received=fs.readFileSync(save);assert.equal(received.length,binarySize);assert.equal(crypto.createHash("sha256").update(received).digest("hex"),expected);
   console.log("PASS 3-chunk exact download, bytes="+binarySize+", source/receiver SHA256="+expected);

   await hostWin.webContents.executeJavaScript("document.querySelector('[data-tabtarget=keys]').click();document.querySelector('#generate').click()");
   await waitFor(guest,"document.querySelector('#roomkey').value.includes('EPOCH 2')","receiver automatic rotation");
   assert.equal(hostWin.pvChannel.key(2),guest.pvChannel.key(2));
   guest.destroy();guest=await join({invite:activeInvite,name:"GuestAudit",password,key},false);
   assert.equal(guest.pvChannel.epoch,2);
   await waitFor(guest,"document.querySelector('#messages').textContent.includes('R14 original signed message')&&document.querySelector('#messages').textContent.includes('R14 synchronized rotated message')","historical keys");
   await guest.webContents.executeJavaScript("document.querySelector('[data-tabtarget=files]').click()");
   await waitFor(guest,"document.querySelector('#filelist').textContent.includes('r14-audit.txt')","historical file");
   await guest.webContents.executeJavaScript("[...document.querySelectorAll('#filelist .filecard')].find(c=>c.textContent.includes('r14-audit.txt')).querySelectorAll('button')[1].click()");
   await waitFor(guest,"document.querySelector('#previewtext').textContent==='R14 verified file contents'","historical file decrypt");
   console.log("PASS offline/rejoin catch-up and old message/file decryption");
   const cfg=fs.readFileSync(path.join(roomDir(),"room.json"),"utf8");assert(!cfg.includes(key)&&!cfg.includes(password));console.log("PASS root and password absent from config");
   const png=await hostWin.webContents.capturePage();fs.writeFileSync(path.join(BASE,"audit-r14-security.png"),png.toPNG());
   console.log("PASS R14 complete local audit");
 }finally{closing=true;stopHost();for(const w of windows)if(!w.isDestroyed())w.destroy();if(launcher&&!launcher.isDestroyed())launcher.destroy();}
}

app.whenReady().then(async()=>{selftest();if(AUDIT){try{await audit();app.exit(0);}catch(e){console.error(e);app.exit(1);}}else{setupIPC();openLauncher();}}).catch(e=>{console.error(e);app.exit(1);});
app.on("login",(event,_wc,_details,_auth,callback)=>{event.preventDefault();callback();});
app.on("before-quit",()=>{closing=true;stopHost();});
app.on("window-all-closed",()=>{if(!AUDIT)app.quit();});
