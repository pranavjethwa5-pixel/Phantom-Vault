"""R14 authenticated desktop API: password enrollment, Ed25519 device proof, replay-safe requests."""
import base64,hashlib,hmac,json,re,secrets,threading,time,sqlite3,io
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
def canonical(*a):return json.dumps(a,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def b64(s,n=None):
    if not isinstance(s,str) or len(s)>512:raise ValueError("Invalid encoding")
    b=base64.b64decode(s,validate=True)
    if n is not None and len(b)!=n:raise ValueError("Invalid length")
    return b
def pub(s):
    p=load_der_public_key(b64(s,44))
    if not isinstance(p,Ed25519PublicKey):raise ValueError("Invalid key algorithm")
    return p
def verify(p,s,data):
    pub(p).verify(b64(s,64),data)
def selftest():
    assert hashlib.sha256(b"abc").hexdigest()=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hmac.new(b"\x0b"*20,b"Hi There",hashlib.sha256).hexdigest()=="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    assert HKDF(algorithm=hashes.SHA256(),length=42,salt=bytes(range(13)),info=bytes(range(240,250))).derive(b"\x0b"*22).hex()=="3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    assert AESGCM(bytes(32)).encrypt(bytes(12),b"",None).hex()=="530f8afbc74536b9a963b4f1c4cb738b"
    Ed25519PublicKey.from_public_bytes(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")).verify(bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),b"")
class Security:
    def __init__(self,db,cfg):
        selftest();self.db=db;self.cfg=cfg;self.rid=cfg["room_id"];self.lock=threading.RLock();self.challenges={};self.sessions={}
        with self.conn() as c:
            c.executescript("CREATE TABLE IF NOT EXISTS pv_identity(name TEXT PRIMARY KEY COLLATE NOCASE, pub TEXT NOT NULL); CREATE TABLE IF NOT EXISTS pv_state(id INTEGER PRIMARY KEY CHECK(id=1), root TEXT NOT NULL); CREATE TABLE IF NOT EXISTS pv_epoch(n INTEGER PRIMARY KEY, name TEXT NOT NULL, pub TEXT NOT NULL, nonce TEXT NOT NULL, sig TEXT NOT NULL);")
    def conn(self):return sqlite3.connect(self.db,timeout=10)
    def clean(self):
        now=time.monotonic()
        self.challenges={k:v for k,v in self.challenges.items() if v[1]>now}
        self.sessions={k:v for k,v in self.sessions.items() if v["expiry"]>now}
    def json_body(self,h,limit=8192):
        n=int(h.headers.get("Content-Length","0"))
        if not 0<n<=limit or h.headers.get("Transfer-Encoding"):raise ValueError("Invalid request length")
        return json.loads(h.rfile.read(n))
    def handshake(self,h,user):
        try:
            if h.path=="/api/security/challenge" and h.command=="GET":
                with self.lock:
                    self.clean()
                    if len(self.challenges)>=512:raise ValueError("Too many pending logins")
                    token=secrets.token_hex(32);self.challenges[token]=(user,time.monotonic()+60)
                h.js(200,{"challenge":token,"room":self.rid,"protocol":14});return
            if h.path!="/api/security/enroll" or h.command!="POST":h.js(404,{"error":"Unknown handshake"});return
            d=self.json_body(h);ch=d["challenge"];device=d["device"];root=d["root"]
            with self.lock:
                self.clean();q=self.challenges.pop(ch,None)
                if not q or q[0]!=user:raise ValueError("Expired or invalid challenge")
                msg=canonical("PV14-enroll",self.rid,user,ch,device,root)
                verify(device,d["sig"],msg);verify(root,d["proof"],msg)
                if len(self.sessions)>=512:raise ValueError("Too many sessions")
                with self.conn() as c:
                    c.execute("BEGIN IMMEDIATE")
                    old=c.execute("SELECT root FROM pv_state WHERE id=1").fetchone()
                    if old is None:
                        if user!=self.cfg["host_name"]:raise ValueError("Host must initialize the room")
                        c.execute("INSERT INTO pv_state VALUES(1,?)",(root,))
                    elif not hmac.compare_digest(old[0],root):raise ValueError("Incorrect room encryption key")
                    row=c.execute("SELECT name,pub FROM pv_identity WHERE name=?",(user,)).fetchone()
                    if row and (row[0]!=user or not hmac.compare_digest(row[1],device)):raise ValueError("Name is already bound to another device")
                    if row is None:
                        if c.execute("SELECT count(*) FROM pv_identity").fetchone()[0]>=512:raise ValueError("Room identity limit reached")
                        c.execute("INSERT INTO pv_identity VALUES(?,?)",(user,device))
                session=secrets.token_hex(32)
                self.sessions[session]={"user":user,"pub":device,"expiry":time.monotonic()+3600,"nonces":{}}
            h.js(200,{"token":session,"user":user,"room":self.rid,"protocol":14})
        except (ValueError,KeyError,TypeError,InvalidSignature,OverflowError) as e:
            h.js(403,{"error":str(e) or "Digital signature verification failed"})
    def authenticate(self,h):
        # No password-only access to application APIs.
        try:
            auth=h.headers.get("Authorization","")
            if not re.fullmatch(r"PV14 [a-f0-9]{64}",auth):raise ValueError("Signed session required")
            token=auth[5:];stamp=h.headers.get("X-PV-Time","");nonce=h.headers.get("X-PV-Nonce","")
            if not re.fullmatch(r"[0-9]{1,12}",stamp) or abs(int(stamp)-int(time.time()))>60 or not re.fullmatch(r"[a-f0-9]{32}",nonce):raise ValueError("Expired request or invalid nonce; check clock")
            digest=h.headers.get("X-PV-Hash","");sig=h.headers.get("X-PV-Signature","");rng=h.headers.get("Range","");ctype=h.headers.get("Content-Type","")
            if not re.fullmatch(r"[a-f0-9]{64}",digest) or len(rng)>128 or len(ctype)>128:raise ValueError("Invalid signed request")
            with self.lock:
                self.clean();q=self.sessions.get(token)
                if not q:raise ValueError("Session expired; reconnect")
                if nonce in q["nonces"]:raise ValueError("Replay rejected")
                verify(q["pub"],sig,canonical("PV14-request",self.rid,token,h.command,h.path,stamp,nonce,digest,rng,ctype))
                now=time.monotonic()
                q["nonces"]={k:v for k,v in q["nonces"].items() if v>now}
                if len(q["nonces"])>=16384:raise ValueError("Request rate exceeded")
                q["nonces"][nonce]=now+125;q["expiry"]=now+3600
                h.pv_pub=q["pub"];user=q["user"]
            if h.headers.get("Transfer-Encoding"):raise ValueError("Transfer encoding forbidden")
            n=int(h.headers.get("Content-Length","0"))
            if n<0 or n>4194304+65536 or (h.command!="POST" and n):raise ValueError("Invalid body size")
            body=h.rfile.read(n) if n else b""
            if len(body)!=n or not hmac.compare_digest(hashlib.sha256(body).hexdigest(),digest):raise ValueError("SHA-256 body verification failed")
            if h.command=="POST":h.rfile=io.BytesIO(body)
            return user
        except (ValueError,TypeError,InvalidSignature,OverflowError) as e:
            h.js(403,{"error":str(e) or "Invalid digital signature"});return None
    def state(self,h):
        with self.conn() as c:
            rows=c.execute("SELECT n,name,pub,nonce,sig FROM pv_epoch ORDER BY n").fetchall()
            identities=c.execute("SELECT name,pub FROM pv_identity ORDER BY name").fetchall()
        h.js(200,{"room":self.rid,"epoch":len(rows),"events":[dict(zip(("n","name","pub","nonce","sig"),r)) for r in rows],"members":[dict(zip(("name","pub"),r)) for r in identities]})
    def rotate(self,h,user):
        try:
            d=self.json_body(h);n=d["n"];nonce=d["nonce"];sig=d["sig"]
            if type(n)!=int or not 1<=n<=4096 or not isinstance(nonce,str) or not re.fullmatch(r"[a-f0-9]{32}",nonce):raise ValueError("Invalid rotation")
            verify(h.pv_pub,sig,canonical("PV14-rotate",self.rid,n,user,nonce))
            with self.conn() as c:
                c.execute("BEGIN IMMEDIATE");current=c.execute("SELECT coalesce(max(n),0) FROM pv_epoch").fetchone()[0]
                if n!=current+1:h.js(409,{"error":"Epoch changed; synchronize and retry"});return
                c.execute("INSERT INTO pv_epoch VALUES(?,?,?,?,?)",(n,user,h.pv_pub,nonce,sig))
            h.js(201,{"epoch":n})
        except (ValueError,KeyError,TypeError,InvalidSignature) as e:h.js(403,{"error":str(e) or "Invalid rotation signature"})
    def check_message(self,h,user,body,signature):
        verify(h.pv_pub,signature,canonical("PV14-message",self.rid,user,body))
