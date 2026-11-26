import sqlite3, base64, json, re, secrets, shutil, threading, os, time, subprocess, struct, ssl
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote
CHUNK=4*1024*1024
M=threading.RLock()
class Fault(Exception):
    def __init__(self,code,msg):self.code=code;self.msg=msg
class Vault:
    def __init__(self,root):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.db=self.root/"index.sqlite3";self.tickets={}
        with self.conn() as c:c.execute("CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,owner TEXT,size INTEGER,meta TEXT,state TEXT,n INTEGER DEFAULT 0,created TEXT DEFAULT CURRENT_TIMESTAMP)")
    @contextmanager
    def conn(self):
        c=sqlite3.connect(self.db,timeout=15);c.row_factory=sqlite3.Row
        try:
            with c:yield c
        finally:c.close()
    def row(self,c,id):
        r=c.execute("SELECT * FROM files WHERE id=?",(id,)).fetchone()
        if not r or r["state"]=="deleted":raise Fault(404,"File unavailable")
        return r
    def read(self,h,limit):
        try:n=int(h.headers.get("Content-Length","-1"))
        except ValueError:raise Fault(400,"Invalid length")
        if not 0<=n<=limit or h.headers.get("Transfer-Encoding"):raise Fault(400,"Invalid length")
        data=h.rfile.read(n)
        if len(data)!=n:raise Fault(400,"Incomplete request")
        return data
    def obj(self,h):
        if h.headers.get_content_type()!="application/json":raise Fault(415,"JSON required")
        try:
            d=json.loads(self.read(h,65536))
            if not isinstance(d,dict):raise ValueError()
            return d
        except (ValueError,UnicodeError):raise Fault(400,"Invalid JSON")
    def clean(self):
        now=time.monotonic()
        for token,s in list(self.tickets.items()):
            if s["until"]<now:self.tickets.pop(token,None)
    def get(self,h,user,path,local):
        if path=="/api/vault":
            with self.conn() as c:
                rows=[dict(r) for r in c.execute("SELECT id,owner,size,meta,state,n,created FROM files WHERE state!='deleted' ORDER BY created DESC")]
            h.js(200,{"files":[r for r in rows if r["state"]=="ready"],"requests":[r for r in rows if r["state"]!="ready" and (local or r["owner"]==user)],"host":local,"chunk":CHUNK});return True
        m=re.fullmatch(r"/api/vault/transfer/([a-f0-9]{48})",path)
        if m:self.transfer(h,user,m[1]);return True
        m=re.fullmatch(r"/api/vault/([a-f0-9]{32})/chunk/([0-9]{1,12})",path)
        if not m:return False
        id,i=m[1],int(m[2])
        with M,self.conn() as c:
            r=self.row(c,id)
            if r["state"]!="ready" or i>=r["n"]:raise Fault(404,"Chunk unavailable")
            data=(self.root/id/str(i)).read_bytes()
        h.respond(200,data,"application/octet-stream");return True
    def post(self,h,user,path,local):
        if path=="/api/vault/create":
            d=self.obj(h);id=d.get("id");size=d.get("size");meta=d.get("meta")
            if not isinstance(id,str) or not re.fullmatch("[a-f0-9]{32}",id) or type(size)!=int or not 0<=size<=9007199254740991 or not isinstance(meta,str) or not 0<len(meta)<=32768:raise Fault(400,"Invalid manifest")
            with M,self.conn() as c:
                if c.execute("SELECT 1 FROM files WHERE id=?",(id,)).fetchone():raise Fault(409,"ID already exists")
                if not local and c.execute("SELECT count(*) FROM files WHERE owner=? AND state IN ('pending','upload')",(user,)).fetchone()[0]>=8:raise Fault(429,"Too many pending transfers")
                state="upload" if local else "pending"
                if local:self.reserve(c,size)
                c.execute("INSERT INTO files(id,owner,size,meta,state) VALUES(?,?,?,?,?)",(id,user,size,meta,state))
                if local:(self.root/id).mkdir()
            h.js(201,{"id":id,"state":state});return True
        if path=="/api/vault/revoke":
            d=self.obj(h)
            with M:
                t=d.get("token")
                if isinstance(t,str) and t in self.tickets and self.tickets[t]["user"]==user:self.tickets.pop(t,None)
            h.js(200,{"revoked":True});return True
        m=re.fullmatch(r"/api/vault/([a-f0-9]{32})/(chunk/([0-9]{1,12})|finish|delete|approve|reject|ticket)",path)
        if not m:return False
        id,op=m[1],m[2]
        if op in ("approve","reject"):
            self.obj(h)
            if not local:raise Fault(403,"Host approval required")
            with M,self.conn() as c:
                r=self.row(c,id)
                if r["state"]!="pending":raise Fault(409,"Not pending")
                if op=="approve":
                    self.reserve(c,r["size"]);(self.root/id).mkdir();state="upload"
                else:state="rejected"
                c.execute("UPDATE files SET state=? WHERE id=?",(state,id))
            h.js(200,{"state":state});return True
        if op=="ticket":
            d=self.obj(h)
            try:
                raw=base64.b64decode(d["key"],validate=True)
                if len(raw)!=32 or d["mode"] not in ("download","stream"):raise ValueError()
            except (KeyError,TypeError,ValueError):raise Fault(400,"Invalid file key")
            with M,self.conn() as c:
                self.clean();r=self.row(c,id)
                if r["state"]!="ready":raise Fault(404,"File unavailable")
                if len(self.tickets)>=32:raise Fault(429,"Too many active transfers")
                meta=self.decode_meta(r,raw)
                token=secrets.token_hex(24)
                self.tickets[token]={"user":user,"peer":h.client_address[0],"id":id,"key":raw,"meta":meta,"mode":d["mode"],"until":time.monotonic()+3600}
            timer=threading.Timer(3600,self.expire,args=(token,));timer.daemon=True;timer.start()
            h.js(201,{"url":"/api/vault/transfer/"+token,"token":token});return True
        if op=="delete":
            self.obj(h)
            with M,self.conn() as c:
                r=self.row(c,id)
                if r["state"]!="ready" and r["owner"]!=user and not local:raise Fault(403,"Not owner")
                c.execute("UPDATE files SET state='deleted' WHERE id=?",(id,))
                for token,s in list(self.tickets.items()):
                    if s["id"]==id:self.tickets.pop(token,None)
            with M:
                folder=self.root/id
                if folder.exists():shutil.rmtree(folder)
            h.js(200,{"deleted":True});return True
        if op=="finish":
            self.obj(h)
            with M,self.conn() as c:
                r=self.row(c,id)
                if r["owner"]!=user or r["state"]!="upload":raise Fault(403,"Not approved for upload")
                if r["n"]!=(r["size"]+CHUNK-1)//CHUNK:raise Fault(409,"Upload incomplete")
                c.execute("UPDATE files SET state='ready' WHERE id=?",(id,))
            h.js(200,{"ready":True});return True
        i=int(m[3])
        if h.headers.get_content_type()!="application/octet-stream":raise Fault(415,"Binary required")
        with M,self.conn() as c:
            r=self.row(c,id)
            if r["owner"]!=user or r["state"]!="upload":raise Fault(403,"Host approval required")
            want=min(CHUNK,r["size"]-i*CHUNK)
            if want<=0 or i>r["n"]:raise Fault(400,"Invalid chunk")
        data=self.read(h,CHUNK+28)
        if len(data)!=want+28:raise Fault(400,"Incorrect encrypted chunk size")
        with M,self.conn() as c:
            r=self.row(c,id)
            if r["owner"]!=user or r["state"]!="upload":raise Fault(403,"Not approved")
            f=self.root/id/str(i)
            if i<r["n"]:
                if f.read_bytes()!=data:raise Fault(409,"Chunk already committed")
            elif i!=r["n"]:raise Fault(409,"Out of order")
            else:
                tmp=f.with_suffix(".tmp")
                with tmp.open("wb") as out:out.write(data);out.flush();os.fsync(out.fileno())
                os.replace(tmp,f);c.execute("UPDATE files SET n=n+1 WHERE id=?",(id,))
        h.js(200,{"next":i+1});return True
    def expire(self,token):
        with M:self.tickets.pop(token,None)
    def reserve(self,c,size):
        reserved=sum(max(0,r["size"]-r["n"]*CHUNK)+28*((r["size"]+CHUNK-1)//CHUNK-r["n"]) for r in c.execute("SELECT size,n FROM files WHERE state='upload'"))
        if size+28*((size+CHUNK-1)//CHUNK)+reserved>shutil.disk_usage(self.root).free:raise Fault(507,"Insufficient host storage")
    def decode_meta(self,r,key):
        try:
            raw=base64.b64decode(r["meta"],validate=True)
            payload=key+struct.pack(">I",len(raw))+raw
            out=subprocess.run(["node",str(Path(__file__).with_name("decrypt.cjs")),r["id"],str(r["size"]),"meta"],input=payload,capture_output=True,timeout=8,check=True,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)).stdout
            d=json.loads(out)
            if not isinstance(d["name"],str) or not isinstance(d["mime"],str):raise ValueError()
            return d
        except (ValueError,KeyError,TypeError,subprocess.SubprocessError):raise Fault(403,"File key authentication failed")
    def transfer(self,h,user,token):
        with M,self.conn() as c:
            self.clean();s=self.tickets.get(token)
            if not s or s["user"]!=user or s["peer"]!=h.client_address[0]:raise Fault(404,"Transfer expired")
            r=self.row(c,s["id"])
            if r["state"]!="ready":raise Fault(404,"File unavailable")
        size=r["size"];start=0;end=size-1;partial=False
        range_header=h.headers.get("Range")
        if range_header:
            m=re.fullmatch(r"bytes=(\d*)-(\d*)",range_header)
            try:
                if not m or not size or not any(m.groups()):raise ValueError()
                if not m[1]:
                    n=int(m[2])
                    if n<=0:raise ValueError()
                    start=max(0,size-n)
                else:
                    start=int(m[1]);end=min(end,int(m[2])) if m[2] else end
                if not 0<=start<=end<size:raise ValueError()
            except ValueError:
                h.send_response(416);h.send_header("Content-Range","bytes */"+str(size));h.send_header("Content-Length","0");h.end_headers();return
            partial=True
        mime=s["meta"]["mime"].lower()
        allowed={"video/mp4","video/webm","video/ogg","audio/mpeg","audio/mp4","audio/wav","audio/x-wav","audio/ogg","audio/webm","audio/flac"}
        mime=mime if s["mode"]=="stream" and mime in allowed else "application/octet-stream"
        if s["mode"]=="stream" and mime=="application/octet-stream":raise Fault(415,"Original format not supported for streaming")
        name=re.sub(r'[\x00-\x1f\x7f/\\]','_',s["meta"]["name"])[:240] or "file"
        h.send_response(206 if partial else 200);h.send_header("Content-Type",mime);h.send_header("Content-Length",str(max(0,end-start+1)));h.send_header("Accept-Ranges","bytes");h.send_header("Cache-Control","no-store");h.send_header("X-Content-Type-Options","nosniff");h.send_header("Referrer-Policy","no-referrer");h.send_header("Content-Security-Policy","default-src 'none'; sandbox")
        if s["mode"]=="download":h.send_header("Content-Disposition","attachment; filename*=UTF-8''"+quote(name,safe=""))
        if partial:h.send_header("Content-Range",f"bytes {start}-{end}/{size}")
        h.end_headers()
        if h.command=="HEAD" or not size:return
        proc=None
        try:
            proc=subprocess.Popen(["node",str(Path(__file__).with_name("decrypt.cjs")),r["id"],str(size),str(start//CHUNK)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            proc.stdin.write(s["key"]);proc.stdin.flush()
            pos=start
            while pos<=end:
                i=pos//CHUNK
                with M,self.conn() as c:
                    if self.tickets.get(token) is not s or s["until"]<time.monotonic():raise OSError("Transfer revoked")
                    if self.row(c,r["id"])["state"]!="ready":raise OSError("Removed")
                    data=(self.root/r["id"]/str(i)).read_bytes()
                proc.stdin.write(struct.pack(">I",len(data))+data);proc.stdin.flush()
                length=min(CHUNK,size-i*CHUNK)
                plain=proc.stdout.read(length)
                if len(plain)!=length:raise OSError("File authentication failed")
                off=pos-i*CHUNK;n=min(length-off,end-pos+1)
                h.wfile.write(plain[off:off+n]);pos+=n
        except (OSError,Fault,ssl.SSLError):h.close_connection=True
        finally:
            if proc:
                try:proc.stdin.close();proc.wait(timeout=2)
                except Exception:proc.kill();proc.wait()
