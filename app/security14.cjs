"use strict";
const crypto=require("node:crypto"),fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict");
const canon=(...a)=>Buffer.from(JSON.stringify(a),"utf8");
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
const hk=(root,salt,info,n=32)=>Buffer.from(crypto.hkdfSync("sha256",root,salt,Buffer.from(info),n));
const seedKey=seed=>crypto.createPrivateKey({key:Buffer.concat([Buffer.from("302e020100300506032b657004220420","hex"),seed]),format:"der",type:"pkcs8"});
const pubkey=k=>crypto.createPublicKey(k).export({format:"der",type:"spki"}).toString("base64");
function publicKey(p){const b=Buffer.from(p,"base64");if(b.length!==44||b.toString("base64")!==p)throw Error("Invalid public key");const k=crypto.createPublicKey({key:b,format:"der",type:"spki"});if(k.asymmetricKeyType!=="ed25519")throw Error("Invalid signature algorithm");return k;}
const sign=(k,b)=>crypto.sign(null,b,k).toString("base64");
function verify(p,s,b){if(typeof s!=="string"||Buffer.from(s,"base64").length!==64||!crypto.verify(null,b,publicKey(p),Buffer.from(s,"base64")))throw Error("Ed25519 signature verification failed");}
function selftest(){
 assert.equal(sha("abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 assert.equal(crypto.createHmac("sha256",Buffer.alloc(20,11)).update("Hi There").digest("hex"),"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
 assert.equal(hk(Buffer.alloc(22,11),Buffer.from([...Array(13).keys()]),Buffer.from([...Array(10).keys()].map(i=>240+i)),42).toString("hex"),"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
 const aes=crypto.createCipheriv("aes-256-gcm",Buffer.alloc(32),Buffer.alloc(12));aes.final();assert.equal(aes.getAuthTag().toString("hex"),"530f8afbc74536b9a963b4f1c4cb738b");
 const ed=seedKey(Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60","hex"));
 assert.equal(crypto.sign(null,Buffer.alloc(0),ed).toString("hex"),"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
 verify(pubkey(ed),sign(ed,Buffer.from("test")),Buffer.from("test"));
}
function atomic(file,value){fs.mkdirSync(path.dirname(file),{recursive:true});const tmp=file+"."+crypto.randomBytes(5).toString("hex")+".tmp";fs.writeFileSync(tmp,value,{flag:"wx"});fs.renameSync(tmp,file);}
function readJson(file,def){try{return JSON.parse(fs.readFileSync(file,"utf8"));}catch(e){if(e.code==="ENOENT")return def;throw e;}}
function identity(dir,rid,name,safeStorage){
 const file=path.join(dir,"identities",sha(rid+"\n"+name.toLowerCase())+".dpapi");
 if(!safeStorage.isEncryptionAvailable())throw Error("Windows protected credential storage unavailable");
 let k;
 if(fs.existsSync(file)){const der=safeStorage.decryptString(fs.readFileSync(file));k=crypto.createPrivateKey({key:Buffer.from(der,"base64"),format:"der",type:"pkcs8"});}
 else{k=crypto.generateKeyPairSync("ed25519").privateKey;atomic(file,safeStorage.encryptString(k.export({format:"der",type:"pkcs8"}).toString("base64")));}
 if(k.asymmetricKeyType!=="ed25519")throw Error("Invalid stored identity");
 return k;
}
const jsonResponse=(d,status=200)=>new Response(JSON.stringify(d),{status,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
class Channel{
 constructor({ses,info,name,credential,key,dir,safeStorage,identityOverride}){
   this.ses=ses;this.info=info;this.name=name;this.origin="https://["+info.ip+"]:"+info.port;this.room=info.fp;
   this.root=Buffer.from(key,"base64");this.identity=identityOverride||identity(dir,this.room,name,safeStorage);this.pub=pubkey(this.identity);
   this.basic="Basic "+Buffer.from(name+":"+credential).toString("base64");
   this.pinfile=path.join(dir,"trust",sha(this.room+"\n"+name.toLowerCase())+".json");this.pins=readJson(this.pinfile,{epoch:0,members:{},head:""});
   this.epoch=-1;this.closed=false;this.token=null;
 }
 async raw(p,options={}){
   if(this.closed)throw Error("Disconnected");
   const url=new URL(p,this.origin);
   if(url.origin!==this.origin)throw Error("Invalid API origin");
   return this.ses.fetch(url.href,{...options,redirect:"error",bypassCustomProtocolHandlers:true});
 }
 async read(r){if(!r.ok){let msg="HTTP "+r.status;try{msg=(await r.json()).error||msg;}catch{}throw Error(msg);}return r.json();}
 async enroll(){
   const challenge=await this.read(await this.raw("/api/security/challenge",{headers:{Authorization:this.basic}}));
   if(challenge.room!==this.room||challenge.protocol!==14||!/^[a-f0-9]{64}$/.test(challenge.challenge))throw Error("Host cryptographic identity mismatch");
   const seed=hk(this.root,Buffer.from(this.room,"hex"),"PV14 room possession Ed25519");const proofKey=seedKey(seed);seed.fill(0);
   const root=pubkey(proofKey),msg=canon("PV14-enroll",this.room,this.name,challenge.challenge,this.pub,root);
   const d={challenge:challenge.challenge,device:this.pub,root,sig:sign(this.identity,msg),proof:sign(proofKey,msg)};
   const out=await this.read(await this.raw("/api/security/enroll",{method:"POST",headers:{Authorization:this.basic,"Content-Type":"application/json"},body:JSON.stringify(d)}));
   if(out.room!==this.room||out.user!==this.name||out.protocol!==14||!/^[a-f0-9]{64}$/.test(out.token))throw Error("Invalid authenticated session");
   this.token=out.token;this.basic=null;await this.sync();
 }
 signedOptions(method,p,headers,body){
   if(!this.token)throw Error("Authentication required");
   const h=new Headers(headers),stamp=String(Math.floor(Date.now()/1000)),nonce=crypto.randomBytes(16).toString("hex"),digest=sha(body);
   const range=h.get("range")||"",ctype=h.get("content-type")||"";
   h.delete("content-length");h.delete("transfer-encoding");h.set("Authorization","PV14 "+this.token);h.set("X-PV-Time",stamp);h.set("X-PV-Nonce",nonce);h.set("X-PV-Hash",digest);
   h.set("X-PV-Signature",sign(this.identity,canon("PV14-request",this.room,this.token,method,p,stamp,nonce,digest,range,ctype)));
   if(method==="POST")h.set("Origin",this.origin);
   return {method,headers:h,...(method==="POST"?{body:new Uint8Array(body)}:{})};
 }
 async signed(method,p,headers={},body=Buffer.alloc(0)){return this.raw(p,this.signedOptions(method,p,headers,body));}
 pin(name,p){
   if(typeof name!=="string"||!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$/.test(name))throw Error("Invalid identity name");
   publicKey(p);const k=name.toLowerCase(),old=Object.prototype.hasOwnProperty.call(this.pins.members,k)?this.pins.members[k]:undefined;
   if(old&&(old.name!==name||old.pub!==p))throw Error("Peer identity changed: "+name);
   this.pins.members[k]={name,pub:p};
 }
 async sync(){
   if(this.syncing)return this.syncing;
   this.syncing=(async()=>{
     const d=await this.read(await this.signed("GET","/api/security/state"));
     if(d.room!==this.room||!Number.isInteger(d.epoch)||d.epoch<Math.max(this.pins.epoch,this.epoch)||d.epoch>4096||!Array.isArray(d.events)||d.events.length!==d.epoch||!Array.isArray(d.members))throw Error("Invalid or rolled-back key epoch");
     const committed=this.pins,previous=JSON.stringify(committed);this.pins=JSON.parse(previous);
     try{
     if(d.members.length>512)throw Error("Too many registered identities");
     for(const m of d.members)this.pin(m.name,m.pub);
     if(this.pins.members[this.name.toLowerCase()]?.pub!==this.pub)throw Error("Local device registration missing");
     let head="";
     for(let i=0;i<d.events.length;i++){const e=d.events[i];if(e.n!==i+1||!/^[a-f0-9]{32}$/.test(e.nonce)||this.pins.members[e.name.toLowerCase()]?.pub!==e.pub)throw Error("Invalid rotation event");
       if(e.n>this.pins.epoch||!this.pins.head)verify(e.pub,e.sig,canon("PV14-rotate",this.room,e.n,e.name,e.nonce));
       head=sha(canon(head,e.n,e.name,e.pub,e.nonce,e.sig));
       if(e.n===this.pins.epoch&&this.pins.head&&head!==this.pins.head)throw Error("Rotation history changed");
     }
     this.epoch=d.epoch;this.pins.epoch=d.epoch;this.pins.head=head;const next=JSON.stringify(this.pins);if(next!==previous||!fs.existsSync(this.pinfile))atomic(this.pinfile,next);return d.epoch;
     }catch(e){this.pins=committed;this.epoch=committed.epoch;throw e;}
   })();
   try{return await this.syncing;}finally{this.syncing=null;}
 }
 key(epoch){if(!Number.isInteger(epoch)||epoch<0||epoch>this.epoch)throw Error("Unverified key epoch");const k=hk(this.root,Buffer.from(this.room,"hex"),"PV14 AES-256 epoch "+epoch);const result=k.toString("base64");k.fill(0);return result;}
 async rotate(){
   for(let i=0;i<3;i++){await this.sync();const n=this.epoch+1;if(n>4096)throw Error("Room epoch limit reached; create a new room");
     const nonce=crypto.randomBytes(16).toString("hex"),sig=sign(this.identity,canon("PV14-rotate",this.room,n,this.name,nonce));
     const r=await this.signed("POST","/api/security/rotate",{"Content-Type":"application/json"},Buffer.from(JSON.stringify({n,nonce,sig})));
     if(r.status===409)continue;await this.read(r);return this.sync();
   }throw Error("Concurrent rotation; try again");
 }
 async route(req){
   const u=new URL(req.url);const p=u.pathname+u.search;
   if(u.origin!==this.origin)return jsonResponse({error:"Forbidden"},403);
   try{
     if(p==="/api/local/state"&&req.method==="GET"){await this.sync();return jsonResponse({epoch:this.epoch,key:this.key(this.epoch),fingerprint:this.pub,verified:true});}
     if(u.pathname==="/api/local/key"&&req.method==="GET"){const e=Number(u.searchParams.get("epoch"));if(e>this.epoch)await this.sync();return jsonResponse({epoch:e,key:this.key(e)});}
     if(p==="/api/local/rotate"&&req.method==="POST"){await this.rotate();return jsonResponse({epoch:this.epoch,key:this.key(this.epoch),verified:true});}
     if(!u.pathname.startsWith("/api/")&&!u.pathname.startsWith("/media/"))return jsonResponse({error:"Not found"},404);
     if(!["GET","POST","HEAD"].includes(req.method))return jsonResponse({error:"Method forbidden"},405);
     let body=req.method==="POST"?Buffer.from(await req.arrayBuffer()):Buffer.alloc(0);
     if(body.length>4194304+65536)throw Error("Request too large");
     if(req.method==="POST"&&p==="/api/messages"){
       const d=JSON.parse(body.toString("utf8"));if(typeof d.body!=="string")throw Error("Invalid message");
       d.sig=sign(this.identity,canon("PV14-message",this.room,this.name,d.body));body=Buffer.from(JSON.stringify(d));
     }
     const r=await this.signed(req.method,p,req.headers,body);
     if(r.ok&&u.pathname==="/api/messages"&&req.method==="GET"){
       const d=await r.json();if(d.user!==this.name||!Array.isArray(d.messages))throw Error("Invalid message response");
       // Check all sender signatures before releasing any ciphertext to the UI.
       await this.sync();
       for(const m of d.messages){if(this.pins.members[m.sender.toLowerCase()]?.pub!==m.pub)throw Error("Unknown message identity");verify(m.pub,m.sig,canon("PV14-message",this.room,m.sender,m.body));}
       return jsonResponse(d);
     }
     return r;
   }catch(e){return jsonResponse({error:e.message||"Verification failed"},503);}
 }
 close(){this.closed=true;this.root.fill(0);this.token=null;this.basic=null;this.identity=null;}
}
module.exports={Channel,selftest,sha,pubkey,sign,verify,canon,identity,seedKey};
