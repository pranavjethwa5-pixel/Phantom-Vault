"use strict";
const fs=require("node:fs"),crypto=require("node:crypto");
const [id,size,start]=process.argv.slice(2);
function read(n){const b=Buffer.alloc(n);let p=0;while(p<n){const m=fs.readSync(0,b,p,n-p,null);if(!m){if(!p)return null;throw Error("short input");}p+=m;}return b;}
function write(b){let p=0;while(p<b.length)p+=fs.writeSync(1,b,p,b.length-p);}
const key=read(32);if(!key)process.exit(1);let i=start==="meta"?"meta":Number(start);
try{while(true){const head=read(4);if(!head)break;const n=head.readUInt32BE();if(n<28||n>4194332)throw Error("size");const b=read(n);if(!b)throw Error("short input");const d=crypto.createDecipheriv("aes-256-gcm",key,b.subarray(0,12));d.setAAD(Buffer.from("SC vault v1:"+id+":"+size+":"+i));d.setAuthTag(b.subarray(-16));write(Buffer.concat([d.update(b.subarray(12,-16)),d.final()]));if(i==="meta")break;i++;}}catch{process.exitCode=1;}finally{key.fill(0);}
