import base64, hashlib, hmac, json, sqlite3, sys, threading, time, ssl, socket, re, secrets, ipaddress
from datetime import datetime, timezone
from vault import Fault
from preview import PreviewVault as Vault
from security14 import Security
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
UI=Path(__file__).resolve().parent
import os
CONFIG=Path(os.environ["PV_ROOM_CONFIG"]).resolve()
ROOM=CONFIG.parent
CFG=json.loads(CONFIG.read_text(encoding="utf-8"))
ROOT=ROOM
MEDIA=Path(CFG["media"]) if CFG.get("media") else ROOM/"media"
VAULT=Vault(ROOM/"Shared Vault")
PORT=int(CFG["port"])
ALLOWED_HOSTS={f"[{ip}]:{PORT}" for ip in CFG["ips"]}|{f"[::1]:{PORT}"}
ALLOWED_ORIGINS={"https://"+h for h in ALLOWED_HOSTS}
DB=ROOM/"messages.sqlite3"
SEC=None
AUTH_CACHE={}
ASSETS={"/vault.js":("vault.js","application/javascript; charset=utf-8"),"/":("index.html","text/html; charset=utf-8"),"/style.css":("style.css","text/css; charset=utf-8"),"/app.js":("app.js","application/javascript; charset=utf-8"),"/crypto.js":("crypto.js","application/javascript; charset=utf-8")}
LOCK=threading.Lock()
FAIL={}
def ipkey(value):
    a=ipaddress.ip_address(value.split("%")[0])
    return str(a.ipv4_mapped or a) if isinstance(a,ipaddress.IPv6Address) else str(a)
def display_profile(peer,user):
    return "hi" if user==CFG["host_name"] else "lo"
def connect():
    c=sqlite3.connect(DB,timeout=10)
    c.row_factory=sqlite3.Row
    return c
def initialize():
    with connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,sender TEXT NOT NULL,body TEXT NOT NULL,created TEXT NOT NULL,pub TEXT NOT NULL,sig TEXT NOT NULL)")
class Handler(BaseHTTPRequestHandler):
    server_version="SC"
    sys_version=""
    def setup(self):
        super().setup()
        self.connection.settimeout(15)
    def log_message(self,fmt,*args):
        route="/api/vault/transfer/[redacted]" if self.path.startswith(("/api/vault/transfer/","/api/vault/preview/")) else urlsplit(self.path).path
        print(f"{self.log_date_time_string()} {self.client_address[0]} {self.command} {route}",file=sys.stderr,flush=True)
    def respond(self,code,data=b"",mime="application/json; charset=utf-8",auth=False):
        self.send_response(code)
        self.send_header("Content-Type",mime)
        self.send_header("Content-Length",str(len(data)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("X-Frame-Options","DENY")
        self.send_header("Referrer-Policy","no-referrer")
        self.send_header("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; media-src 'self' blob:; img-src 'self' blob: data:; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if auth:self.send_header("WWW-Authenticate",'Basic realm="Phantom Vault"')
        self.end_headers()
        if self.command!="HEAD":
            try:self.wfile.write(data)
            except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError):pass
    def js(self,code,obj): self.respond(code,json.dumps(obj,ensure_ascii=False).encode())
    def password_auth(self):
        ip=ipkey(self.client_address[0])
        now=time.monotonic()
        header=self.headers.get("Authorization","")
        if len(header)>1024:
            self.js(401,{"error":"Invalid name or server password"});return None
        marker=hashlib.sha256(header.encode()).digest()
        with LOCK:
            cached=AUTH_CACHE.get(marker)
            if cached and cached[0]>now:return cached[1]
            attempts=[t for t in FAIL.get(ip,[]) if now-t<60]
            FAIL[ip]=attempts
            if len(attempts)>=12:
                self.js(429,{"error":"Too many failed logins; try again in a minute"});return None
        try:
            scheme,encoded=header.split(" ",1)
            if scheme.lower()!="basic":raise ValueError()
            user,pw=base64.b64decode(encoded,validate=True).decode().split(":",1)
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}",user) or not 1<=len(pw)<=255:raise ValueError()
            if user.casefold()==CFG["host_name"].casefold():
                ok=user==CFG["host_name"] and hmac.compare_digest(hashlib.sha256(pw.encode()).hexdigest(),CFG["host_token_hash"])
            else:
                digest=hashlib.pbkdf2_hmac("sha256",pw.encode(),bytes.fromhex(CFG["salt"]),310000).hex()
                ok=hmac.compare_digest(digest,CFG["password_hash"])
            if ok:
                with LOCK:
                    if len(AUTH_CACHE)>=256:AUTH_CACHE.clear()
                    AUTH_CACHE[marker]=(now+300,user)
                return user
        except (ValueError,UnicodeError):pass
        with LOCK:FAIL[ip].append(now)
        self.js(401,{"error":"Invalid name or server password"});return None
    def valid_host(self):
        if self.headers.get("Host","") not in ALLOWED_HOSTS:
            self.js(403,{"error":"Invalid host"});return False
        return True
    def do_HEAD(self):
        self.do_GET()
    def do_GET(self):
        if not self.valid_host():return
        if self.path in ("/api/security/challenge","/api/security/enroll"):
            user=self.password_auth()
            if user:SEC.handshake(self,user)
            return
        user=SEC.authenticate(self)
        if not user:return
        path=urlsplit(self.path)
        if path.path=="/api/security/state":
            SEC.state(self);return
        if path.path in ASSETS:
            name,mime=ASSETS[path.path]
            self.respond(200,(UI/name).read_bytes(),mime);return
        profile=display_profile(self.client_address[0],user)
        if path.path.startswith("/api/vault"):
            try:
                if not VAULT.get(self,user,path.path,profile=="hi"):self.js(404,{"error":"Unknown vault route"})
            except Fault as e:self.js(e.code,{"error":e.msg})
            except OSError:self.js(503,{"error":"Storage unavailable"})
            return
        if path.path=="/api/display-profile":
            self.js(200,{"mode":profile,"fps":240 if profile=="hi" else 120,"width":1920,"height":1080,"codec":"hevc"});return
        if path.path=="/media/stats.json":
            try:
                data=(MEDIA/"stats.json").read_bytes()
                if time.time()-json.loads(data)["timestamp"]>8:raise ValueError()
            except (OSError,ValueError,KeyError):self.js(503,{"error":"Renderer unavailable"});return
            self.respond(200,data);return
        match=re.fullmatch(r"/media/(hi|lo)/(live\.m3u8|init_[0-9]+_(?:hi|lo)\.mp4|seg_[0-9]+_[0-9]{8}\.m4s)",path.path)
        if match:
            mode,name=match.groups()
            if mode!=profile:self.js(403,{"error":"Display profile not assigned"});return
            try:
                file=(MEDIA/name) if name.startswith("init_") and name.endswith("_"+mode+".mp4") else (MEDIA/mode/name)
                data=file.read_bytes()
                if len(data)>16*1024*1024:raise ValueError()
            except (OSError,ValueError):self.js(404,{"error":"Media unavailable"});return
            mime="application/vnd.apple.mpegurl" if name.endswith(".m3u8") else "video/mp4"
            self.respond(200,data,mime);return
        if path.path=="/api/messages":
            try: after=int(parse_qs(path.query).get("after",["0"])[0]);assert 0<=after<=9223372036854775807
            except (ValueError,AssertionError):self.js(400,{"error":"Invalid cursor"});return
            with connect() as c:
                rows=c.execute("SELECT id,sender,body,created,pub,sig FROM messages WHERE id>? ORDER BY id LIMIT 200",(after,)).fetchall()
            self.js(200,{"user":user,"messages":[dict(r) for r in rows]});return
        self.js(404,{"error":"Not found"})
    def do_POST(self):
        if not self.valid_host():return
        if self.path in ("/api/security/challenge","/api/security/enroll"):
            user=self.password_auth()
            if user:SEC.handshake(self,user)
            return
        user=SEC.authenticate(self)
        if not user:return
        if self.path=="/api/security/rotate":
            SEC.rotate(self,user);return
        if self.path.startswith("/api/vault"):
            if self.headers.get("Origin") not in ALLOWED_ORIGINS:self.js(403,{"error":"Invalid origin"});return
            try:
                if not VAULT.post(self,user,self.path,display_profile(self.client_address[0],user)=="hi"):self.js(404,{"error":"Unknown vault route"})
            except Fault as e:self.js(e.code,{"error":e.msg})
            except OSError:self.js(507,{"error":"Storage unavailable"})
            return
        if self.path!="/api/messages":self.js(404,{"error":"Not found"});return
        if self.headers.get("Origin") not in ALLOWED_ORIGINS or self.headers.get_content_type()!="application/json":
            self.js(403,{"error":"Invalid origin or content type"});return
        try:
            n=int(self.headers.get("Content-Length","0"))
            if not 0<n<=40000:raise ValueError()
            data=json.loads(self.rfile.read(n))
            body=data["body"]
            if not isinstance(body,str) or len(body)>24000:raise ValueError()
            envelope=json.loads(body)
            if not isinstance(envelope,dict) or set(envelope)!={"v","e","iv","ct"} or envelope["v"]!=3 or type(envelope["e"])!=int or not 0<=envelope["e"]<=4096:raise ValueError()
            iv=base64.b64decode(envelope["iv"],validate=True)
            ct=base64.b64decode(envelope["ct"],validate=True)
            if len(iv)!=12 or not 17<=len(ct)<=16016:raise ValueError()
            with connect() as c:
                if envelope["e"]>c.execute("SELECT coalesce(max(n),0) FROM pv_epoch").fetchone()[0]:raise ValueError("Unverified epoch")
            signature=data["sig"]
            SEC.check_message(self,user,body,signature)
        except Exception:
            self.js(400,{"error":"Invalid message or signature"});return
        with connect() as c:
            cur=c.execute("INSERT INTO messages(sender,body,created,pub,sig) VALUES(?,?,?,?,?)",(user,body,datetime.now(timezone.utc).isoformat(),self.pv_pub,signature))
            mid=cur.lastrowid
        self.js(201,{"id":mid})
class SecureServer(ThreadingHTTPServer):
    address_family=socket.AF_INET6
    daemon_threads=True
    request_queue_size=64
    slots=threading.BoundedSemaphore(32)
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
        super().server_bind()
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:super().process_request(request,client_address)
        except Exception:
            self.slots.release()
            raise
    def process_request_thread(self,request,client_address):
        try:
            request.settimeout(8)
            with TLS.wrap_socket(request,server_side=True) as secured:
                secured.settimeout(12)
                super().process_request_thread(secured,client_address)
        except (ssl.SSLError,OSError):
            self.shutdown_request(request)
        finally:self.slots.release()

if __name__=="__main__":
    initialize()
    SEC=Security(DB,CFG)
    TLS=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    TLS.minimum_version=ssl.TLSVersion.TLSv1_3
    TLS.load_cert_chain(ROOM/"cert.pem",ROOM/"key.pem")
    with SecureServer((CFG.get("bind","::"),PORT),Handler) as server:
        print(f"PHANTOM READY {PORT}",flush=True)
        server.serve_forever()
