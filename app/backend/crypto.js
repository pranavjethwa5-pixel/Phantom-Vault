"use strict";
const SCrypto=(()=>{
 const enc=new TextEncoder(), dec=new TextDecoder("utf-8",{fatal:true});
 const b64=b=>{const a=new Uint8Array(b);let s="";for(let i=0;i<a.length;i+=32768)s+=String.fromCharCode(...a.subarray(i,i+32768));return btoa(s);};
 const unb=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
 const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
 const hex=a=>Array.from(new Uint8Array(a),x=>x.toString(16).padStart(2,"0")).join("");
 const aad=(sender,epoch)=>enc.encode("PV14/message/"+epoch+":"+sender);
 const ring=new Map(),epochs=new Map();
 async function key(raw,epoch){if(!Number.isInteger(epoch)||epoch<0||epoch>4096)throw Error("Invalid epoch");const b=unb(raw.trim());if(b.length!==32)throw Error("Key must contain 32 bytes");const id=hex(await crypto.subtle.digest("SHA-256",b)).slice(0,24);if(ring.has(id)){b.fill(0);const k=ring.get(id);if(k.epoch!==epoch)throw Error("Epoch mismatch");return k;}const aes=await crypto.subtle.importKey("raw",b,"AES-GCM",false,["encrypt","decrypt"]);const hk=await crypto.subtle.importKey("raw",b,"HKDF",false,["deriveKey"]);b.fill(0);const k={id,aes,hk,epoch};ring.set(id,k);epochs.set(epoch,k);return k;}
 function generate(){return b64(rnd(32));}
 async function custom(pass){if(pass.length<16)throw Error("Use at least 16 characters, preferably a long random passphrase.");const salt=rnd(32),material=await crypto.subtle.importKey("raw",enc.encode(pass),"PBKDF2",false,["deriveBits"]);return b64(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-512",salt,iterations:600000},material,256));}
 async function epochKey(epoch){if(!Number.isInteger(epoch)||epoch<0||epoch>4096)throw Error("Invalid epoch");if(epochs.has(epoch))return epochs.get(epoch);const r=await fetch("/api/local/key?epoch="+epoch,{cache:"no-store"});if(!r.ok)throw Error("Historical key unavailable");const d=await r.json();if(d.epoch!==epoch)throw Error("Epoch mismatch");return key(d.key,epoch);}
 async function seal(k,sender,text){const iv=rnd(12);const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad(sender,k.epoch),tagLength:128},k.aes,enc.encode(text));return JSON.stringify({v:3,e:k.epoch,iv:b64(iv),ct:b64(ct)});}
 async function open(k,sender,envelope){const e=JSON.parse(envelope);if(e.v!==3)throw Error("Unsupported format");const x=await epochKey(e.e);return dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unb(e.iv),additionalData:aad(sender,e.e),tagLength:128},x.aes,unb(e.ct)));}
 async function fileKey(k,id){if(!/^[a-f0-9]{32}$/.test(id))throw Error("Invalid file id");k=await epochKey(parseInt(id.slice(0,8),16));return crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-512",salt:enc.encode(id),info:enc.encode("SC vault v1 file AES-256-GCM")},k.hk,{name:"AES-GCM",length:256},true,["encrypt","decrypt"]);}
 function fa(id,size,i){return enc.encode("SC vault v1:"+id+":"+size+":"+i);}
 async function encrypt(k,id,size,i,plain){const iv=rnd(12),ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:fa(id,size,i),tagLength:128},k,plain));const result=new Uint8Array(12+ct.length);result.set(iv);result.set(ct,12);return result;}
 async function decrypt(k,id,size,i,data){const a=new Uint8Array(data);return crypto.subtle.decrypt({name:"AES-GCM",iv:a.subarray(0,12),additionalData:fa(id,size,i),tagLength:128},k,a.subarray(12));}
 async function metadata(r){const fk=await fileKey(null,r.id);const meta=JSON.parse(dec.decode(await decrypt(fk,r.id,r.size,"meta",unb(r.meta))));if(typeof meta.name!=="string"||typeof meta.mime!=="string")throw Error("Bad metadata");return {fk,meta};}
 return {key,generate,custom,seal,open,fileKey,encrypt,decrypt,metadata,b64,hex,rnd,enc,clear:()=>{ring.clear();epochs.clear();},count:()=>ring.size};
})();