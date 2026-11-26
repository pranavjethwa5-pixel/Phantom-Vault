import io, json, re, secrets, subprocess, threading, time, shutil, os, base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from vault import Vault, Fault, M, CHUNK

MAX_OUTPUT=256*1024*1024
MAX_DOCUMENT=64*1024*1024
SLOTS=threading.BoundedSemaphore(1)
FLAGS=getattr(subprocess,"CREATE_NO_WINDOW",0)

class PreviewVault(Vault):
    def get(self,h,user,path,local):
        m=re.fullmatch(r"/api/vault/preview/([a-f0-9]{48})(?:/([0-9]{1,5}))?",path)
        if m:
            if h.command!="GET":raise Fault(405,"GET required")
            self.preview(h,user,m[1],int(m[2] or 0));return True
        return super().get(h,user,path,local)
    def ticket(self,h,user,token):
        with M,self.conn() as c:
            self.clean();s=self.tickets.get(token)
            if not s or s["user"]!=user or s["peer"]!=h.client_address[0] or s["mode"]!="stream":raise Fault(404,"Preview unavailable")
            r=self.row(c,s["id"])
            if r["state"]!="ready":raise Fault(404,"File unavailable")
            return s,dict(r)
    def valid(self,token,s):
        with M:
            return self.tickets.get(token) is s and s["until"]>time.monotonic()
    def plain(self,token,s,r,limit):
        if r["size"]>limit:raise Fault(413,"Document too large for this preview. Download instead.")
        proc=subprocess.Popen(["node",str(Path(__file__).with_name("decrypt.cjs")),r["id"],str(r["size"]),"0"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=FLAGS)
        try:
            proc.stdin.write(s["key"]);proc.stdin.flush()
            out=bytearray()
            for i in range(r["n"]):
                if not self.valid(token,s):raise Fault(404,"Preview revoked")
                data=(self.root/r["id"]/str(i)).read_bytes()
                import struct
                proc.stdin.write(struct.pack(">I",len(data))+data);proc.stdin.flush()
                n=min(CHUNK,r["size"]-i*CHUNK);b=proc.stdout.read(n)
                if len(b)!=n:raise Fault(422,"File authentication failed")
                out.extend(b)
            return bytes(out)
        finally:
            try:proc.stdin.close();proc.wait(timeout=2)
            except Exception:proc.kill();proc.wait()
    def preview(self,h,user,token,page):
        s,r=self.ticket(h,user,token)
        ext=Path(s["meta"]["name"]).suffix.lower()
        if not SLOTS.acquire(False):raise Fault(429,"Another preview is being prepared. Try again.")
        try:
            if ext==".pdf":
                import fitz
                data=self.plain(token,s,r,MAX_DOCUMENT)
                try:
                    with fitz.open(stream=data,filetype="pdf") as doc:
                        if doc.needs_pass or page>=len(doc):raise Fault(400,"Page unavailable or PDF password required")
                        p=doc[page];scale=min(2.5,2400/max(p.rect.width,p.rect.height,1))
                        pix=p.get_pixmap(matrix=fitz.Matrix(scale,scale),alpha=False)
                        result={"pages":len(doc),"page":page,"png":base64.b64encode(pix.tobytes("png")).decode()}
                except Fault:raise
                except Exception:raise Fault(422,"Cannot read PDF")
                if not self.valid(token,s):raise Fault(404,"Preview revoked")
                h.js(200,result);return
            if ext not in {".mp4",".m4v",".mov",".mkv",".webm",".avi",".mts",".m2ts",".mpeg",".mpg",".ts",".wmv",".flv",".ogv",".3gp"}:raise Fault(415,"Compatibility video preview unavailable for this file")
            self.video(h,user,token,s,r)
        finally:SLOTS.release()
    def video(self,h,user,token,s,r):
        # Private loopback bridge exposes just this already-authorized file to FFmpeg.
        # The original stays encrypted on disk. No decrypted temporary files.
        nonce="/"+secrets.token_hex(32)
        vault=self
        class Bridge(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_HEAD(self):self.do_GET()
            def do_GET(self):
                if self.path!=nonce or not vault.valid(token,s):self.send_error(404);return
                self.client_address=(s["peer"],0)
                # transfer uses the existing ticket and authenticated chunks.
                try:vault.transfer(self,user,token)
                except (Fault,OSError):self.close_connection=True
        # Original transfer endpoint accepts limited MIME types. The bridge can
        # read arbitrary video containers using a request-local ticket copy.
        # Use its own range reader instead of altering the live ticket.
        class Source(Bridge):
            def do_GET(self):
                if self.path!=nonce or not vault.valid(token,s):self.send_error(404);return
                size=r["size"];start=0;end=size-1;partial=False
                rg=self.headers.get("Range")
                if rg:
                    m=re.fullmatch(r"bytes=(\d+)-(\d*)",rg)
                    if not m:self.send_error(416);return
                    start=int(m[1]);end=min(end,int(m[2])) if m[2] else end
                    if not 0<=start<=end<size:self.send_error(416);return
                    partial=True
                self.send_response(206 if partial else 200);self.send_header("Content-Type","application/octet-stream");self.send_header("Content-Length",str(max(0,end-start+1)));self.send_header("Accept-Ranges","bytes")
                if partial:self.send_header("Content-Range",f"bytes {start}-{end}/{size}")
                self.end_headers()
                if self.command=="HEAD" or not size:return
                import struct
                p=None
                try:
                    p=subprocess.Popen(["node",str(Path(__file__).with_name("decrypt.cjs")),r["id"],str(size),str(start//CHUNK)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=FLAGS)
                    p.stdin.write(s["key"]);p.stdin.flush();pos=start
                    while pos<=end:
                        if not vault.valid(token,s):break
                        i=pos//CHUNK;data=(vault.root/r["id"]/str(i)).read_bytes()
                        p.stdin.write(struct.pack(">I",len(data))+data);p.stdin.flush()
                        n=min(CHUNK,size-i*CHUNK);b=p.stdout.read(n)
                        if len(b)!=n:break
                        off=pos-i*CHUNK;length=min(n-off,end-pos+1)
                        self.wfile.write(b[off:off+length]);pos+=length
                except OSError:pass
                finally:
                    if p:
                        try:p.stdin.close();p.wait(timeout=2)
                        except Exception:p.kill();p.wait()
        server=ThreadingHTTPServer(("127.0.0.1",0),Source);server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        url=f"http://127.0.0.1:{server.server_port}{nonce}"
        p=None;timer=None
        try:
            cmd=["ffmpeg","-hide_banner","-nostdin","-loglevel","error","-protocol_whitelist","http,tcp","-hwaccel","cuda","-hwaccel_output_format","cuda","-i",url,"-map","0:v:0","-map","0:a:0?","-vf","scale_cuda=format=nv12","-c:v","h264_nvenc","-preset","p4","-rc","vbr","-cq","19","-b:v","16M","-maxrate","20M","-bufsize","20M","-c:a","aac","-b:a","192k","-movflags","+frag_keyframe+empty_moov+default_base_moof","-f","mp4","pipe:1"]
            p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=FLAGS)
            timer=threading.Timer(150,p.kill);timer.daemon=True;timer.start()
            buf=bytearray()
            while True:
                block=p.stdout.read(256*1024)
                if not block:break
                if not self.valid(token,s):raise Fault(404,"Preview revoked")
                if len(buf)+len(block)>MAX_OUTPUT:raise Fault(413,"Preview exceeds memory limit. Download original.")
                buf.extend(block)
            if p.wait()!=0 or len(buf)<1024:raise Fault(422,"GPU could not convert this video. Download original.")
            if not self.valid(token,s):raise Fault(404,"Preview revoked")
            h.respond(200,bytes(buf),"video/mp4")
        finally:
            if timer:timer.cancel()
            if p and p.poll() is None:p.kill();p.wait()
            server.shutdown();server.server_close()
