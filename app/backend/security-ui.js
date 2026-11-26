"use strict";
// Only epoch-derived keys reach the local interface. The root remains in the desktop process.
(()=>{
 const label=document.querySelector("#keyhint"),field=document.querySelector("#roomkey"),rot=document.querySelector("#generate"),syncBtn=document.querySelector("#unlock");
 let syncing=null,connected=false,rotationTimer=null,rotating=false;
 async function apply(d){
   if(!d.verified||!Number.isInteger(d.epoch)||d.epoch<0||typeof d.key!=="string")throw Error("Key verification failed");
   if(!room||room.epoch!==d.epoch)room=await SCrypto.key(d.key,d.epoch);
   field.value="EPOCH "+d.epoch+" / AES-256-GCM";
   label.textContent="Mutual authentication verified · epoch "+d.epoch+" · synchronized";
   document.querySelector("#keycount").textContent="EPOCH "+d.epoch;
   return room;
 }
 async function sync(){
   if(!connected)throw Error("Disconnected");
   if(syncing)return syncing;
   syncing=(async()=>apply(await api("/api/local/state")))();
   try{return await syncing;}finally{syncing=null;}
 }
 window.pvSync=sync;
 window.pvConnect=async()=>{
   connected=true;
   try{await sync();reset();window.vaultKeyChanged?.();const d=await api("/api/messages?after=0");me=d.user;identity.textContent=me.toUpperCase();state(true);await poll();const v=await api("/api/vault");document.querySelector("#rotationpolicy").hidden=!v.host;}
   catch(e){connected=false;locked();throw e;}
 };
 async function rotate(){
   if(!connected||rotating)return;rotating=true;rot.disabled=true;
   try{await sync();await apply(await api("/api/local/rotate",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}));label.textContent="New key epoch "+room.epoch+" signed and synchronized automatically.";}
   catch(e){label.textContent=e.message;}finally{rot.disabled=false;rotating=false;}
 }
 rot.onclick=rotate;
 document.querySelector("#rotationinterval").onchange=e=>{clearInterval(rotationTimer);const seconds=Number(e.target.value);if(seconds>0)rotationTimer=setInterval(rotate,seconds*1000);};
 syncBtn.onclick=async()=>{try{await sync();}catch(e){label.textContent=e.message;}};
 document.querySelector("#lock").onclick=()=>{connected=false;clearInterval(rotationTimer);locked();window.close();};
 document.querySelector("#reveal").hidden=true;
 document.querySelector("#customkey").disabled=true;
 document.querySelector("#passphrase").disabled=true;
 field.type="text";field.readOnly=true;
 setInterval(()=>{if(connected)sync().catch(e=>{label.textContent="Synchronization failed: "+e.message;});},2000);
})();
