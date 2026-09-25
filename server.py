#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

DB_FILE = os.environ.get("DB_FILE", "/tmp/ghanizada.db")
USERS_FILE = os.environ.get("USERS_FILE", "/tmp/ghanizada-users.json")
XRAY_CONFIG = os.environ.get("XRAY_CONFIG", "/tmp/xray-managed.json")
ACCESS_LOG = "/tmp/xray-access.log"
ERROR_LOG = "/tmp/xray-error.log"
SNI = os.environ.get("SNI", "firebase-settings.crashlytics.com")
OWNER_KEY = os.environ.get("OWNER_KEY", "")
PORT = int(os.environ.get("DASHBOARD_PORT", "8081"))
PERSIST_BUCKET = os.environ.get("PERSIST_BUCKET", "").strip()
PERSIST_PREFIX = os.environ.get("PERSIST_PREFIX", "ghanizada")
SETTINGS_FILE = os.environ.get("SETTINGS_FILE", "/tmp/ghanizada-settings.json")
SESSION_TTL = 12 * 60 * 60
START_TIME = time.time()
STATE_LOCK = threading.RLock()
SESSIONS = {}
PROTOCOLS = {
    "trojan": {"name": "Trojan", "path": "/ws/Ghanizada"},
    "vless": {"name": "VLESS", "path": "/ws/VLESS-Ghanizada"},
    "vmess": {"name": "VMess", "path": "/ws/VMess-Ghanizada"},
}


def metadata_token():
    req = Request("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", headers={"Metadata-Flavor": "Google"})
    with urlopen(req, timeout=2) as r:
        return json.loads(r.read())['access_token']


def gcs_request(method, path, data=None, content_type="application/json"):
    if not PERSIST_BUCKET:
        return None
    token = metadata_token()
    url = "https://storage.googleapis.com" + path
    headers = {"Authorization": f"Bearer {token}", "Content-Type": content_type}
    req = Request(url, data=data, headers=headers, method=method)
    with urlopen(req, timeout=8) as r:
        return r.read()


def gcs_load(name):
    if not PERSIST_BUCKET:
        return None
    try:
        path = f"/storage/v1/b/{PERSIST_BUCKET}/o/{quote(PERSIST_PREFIX + '/' + name, safe='')}?alt=media"
        return gcs_request("GET", path)
    except Exception:
        return None


def gcs_save(name, raw):
    if not PERSIST_BUCKET:
        return False
    try:
        obj = quote(PERSIST_PREFIX + '/' + name, safe="")
        path = f"/upload/storage/v1/b/{PERSIST_BUCKET}/o?uploadType=media&name={obj}"
        gcs_request("POST", path, data=raw, content_type="application/json")
        return True
    except Exception:
        return False


def atomic_write(path, raw):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ghanizada-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try: os.unlink(tmp)
        except OSError: pass


def load_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json_file(path, data):
    raw = json.dumps(data, indent=2, ensure_ascii=False).encode()
    atomic_write(path, raw)
    return raw


def ensure_state():
    os.makedirs(os.path.dirname(USERS_FILE) or "/tmp", exist_ok=True)
    if not os.path.exists(USERS_FILE):
        raw = gcs_load("users.json")
        if raw:
            try: atomic_write(USERS_FILE, raw)
            except Exception: pass
    if not os.path.exists(USERS_FILE):
        save_users([])
    if not os.path.exists(os.path.join(os.path.dirname(USERS_FILE), "admin.json")):
        raw = gcs_load("admin.json")
        if raw:
            try: atomic_write(os.path.join(os.path.dirname(USERS_FILE), "admin.json"), raw)
            except Exception: pass
    if not os.path.exists(SETTINGS_FILE):
        raw = gcs_load("settings.json")
        if raw:
            try: atomic_write(SETTINGS_FILE, raw)
            except Exception: pass
    if not os.path.exists(SETTINGS_FILE):
        save_settings({"server_name":"Ghanizada VPN","default_expiry_days":0,"default_devices":0,"default_traffic_gb":0,"notifications":True,"ssh_backend":{"enabled":False,"host":"","port":443,"path":"/ws/ssh"}})


def load_users():
    with STATE_LOCK:
        data = load_json_file(USERS_FILE, [])
        return data if isinstance(data, list) else []


def save_users(users):
    with STATE_LOCK:
        raw = save_json_file(USERS_FILE, users)
        gcs_save("users.json", raw)


def admin_path():
    return os.path.join(os.path.dirname(USERS_FILE), "admin.json")


def load_admin():
    return load_json_file(admin_path(), {})


def save_admin(data):
    raw = save_json_file(admin_path(), data)
    gcs_save("admin.json", raw)


def load_settings():
    return load_json_file(SETTINGS_FILE, {"server_name":"Ghanizada VPN","default_expiry_days":0,"default_devices":0,"default_traffic_gb":0,"notifications":True,"ssh_backend":{"enabled":False,"host":"","port":443,"path":"/ws/ssh"}})

def save_settings(data):
    raw = save_json_file(SETTINGS_FILE, data)
    gcs_save("settings.json", raw)

def caddy_backend_config(settings=None):
    settings = settings or load_settings()
    b = settings.get("ssh_backend") or {}
    enabled = bool(b.get("enabled"))
    host = str(b.get("host", "")).strip()
    port = int(b.get("port", 443) or 443)
    path = str(b.get("path", "/ws/ssh")).strip() or "/ws/ssh"
    if not path.startswith("/"):
        path = "/" + path
    route = ""
    if enabled and host:
        upstream = "https://%s:%s" % (host, port) if port != 443 else "https://%s" % host
        route = "\n    @ssh_ws path /ws/ssh\n    handle @ssh_ws {\n        rewrite * %s\n        reverse_proxy %s\n    }\n" % (path, upstream)
    return ":{$PORT} {\n    encode gzip\n" + route + "\n    @trojan path /ws/Ghanizada\n    reverse_proxy @trojan 127.0.0.1:10000\n\n    @vless path /ws/VLESS-Ghanizada\n    reverse_proxy @vless 127.0.0.1:10001\n\n    @vmess path /ws/VMess-Ghanizada\n    reverse_proxy @vmess 127.0.0.1:10002\n\n    reverse_proxy 127.0.0.1:8081\n}\n"

def configure_caddy_backend(reload=True):
    path = "/etc/caddy/Caddyfile"
    try:
        atomic_write(path, caddy_backend_config().encode())
        if reload and os.path.exists("/tmp/caddy-ready"):
            subprocess.run(["caddy", "reload", "--config", path, "--adapter", "caddyfile"], capture_output=True, timeout=8, check=True)
        return True, "SSH backend configuration applied"
    except Exception as e:
        return False, str(e)

def save_backup_snapshot():
    payload = {"version":3,"created_at":time.strftime("%Y-%m-%d %H:%M:%S"),"users":load_users(),"usage":load_json_file(os.path.join(os.path.dirname(USERS_FILE) or "/tmp","usage.json"),{}),"settings":load_settings()}
    raw = json.dumps(payload, indent=2, ensure_ascii=False).encode()
    stamp=time.strftime("%Y%m%d-%H%M%S")
    gcs_save("backups/"+stamp+".json", raw)
    return stamp

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
    return {"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(digest).decode()}


def verify_password(password, record):
    try:
        salt = base64.b64decode(record["salt"])
        expected = base64.b64decode(record["hash"])
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 180_000)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def bootstrap_admin(password):
    if not password:
        return
    a = load_admin()
    if not a.get("hash"):
        rec = hash_password(password)
        rec["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        save_admin(rec)


def create_session():
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token


def session_ok(handler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth[7:].strip()
    exp = SESSIONS.get(token, 0)
    if exp <= time.time():
        SESSIONS.pop(token, None)
        return False
    return True


def cleanup_sessions():
    now = time.time()
    for k, v in list(SESSIONS.items()):
        if v <= now: SESSIONS.pop(k, None)


def defaults_for_user(u):
    u.setdefault("enabled", True)
    u.setdefault("expires_at", "")
    u.setdefault("max_devices", 0)
    u.setdefault("traffic_limit_gb", 0)
    u.setdefault("note", "")
    u.setdefault("sub_token", secrets.token_urlsafe(24))
    u.setdefault("ip_reset_at", 0)
    u.setdefault("created_at", time.strftime("%Y-%m-%d %H:%M:%S"))
    return u


def expired(u):
    if not u.get("expires_at"):
        return False
    try:
        return time.strptime(u["expires_at"], "%Y-%m-%d") < time.localtime()
    except Exception:
        return False


def user_enabled(u):
    return bool(u.get("enabled", True)) and not expired(u)


def parse_log_events():
    events = []
    try:
        with open(ACCESS_LOG, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-3000:]
    except Exception:
        return events
    now = time.time()
    for line in lines:
        m = re.search(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
        if not m: continue
        try: ts = time.mktime(time.strptime(m.group(1), "%Y/%m/%d %H:%M:%S"))
        except Exception: continue
        if now - ts > 900: continue
        ipm = re.search(r"(?:from|client|remote|source)[ =:]([0-9a-fA-F:.]+)", line)
        ip = ipm.group(1) if ipm else ""
        events.append((ts, ip, line))
    return events


def online_info():
    users = load_users(); events = parse_log_events(); now = time.time(); xstats = xray_stats() if "xray_stats" in globals() else {}
    out = {}
    for u in users:
        name = u["username"]
        matched = [e for e in events if re.search(rf"(?:email=|email |\b){re.escape(name)}(?:\b|\s|\")", e[2], re.I)]
        recent = [e for e in matched if now-e[0] <= 90]
        ips = sorted({e[1] for e in recent if e[1]})
        stat_online = bool(xstats.get(name, {}).get("online", 0))
        out[u["id"]] = {"online": (stat_online or bool(recent)) and user_enabled(u), "ips": ips, "last_seen": max([e[0] for e in matched], default=0)}
    return out


def make_uri(u, host):
    p = PROTOCOLS[u["protocol"]]; path = quote(p["path"], safe=""); h = quote(host, safe="")
    if u["protocol"] == "trojan":
        return f"trojan://{quote(u['credential'], safe='')}@{host}:443?security=tls&type=ws&path={path}&host={h}&sni={quote(SNI, safe='')}#{quote(u['username'], safe='')}"
    if u["protocol"] == "vless":
        return f"vless://{u['credential']}@{host}:443?encryption=none&security=tls&type=ws&path={path}&host={h}&sni={quote(SNI, safe='')}#{quote(u['username'], safe='')}"
    obj = {"v":"2","ps":u["username"],"add":host,"port":"443","id":u["credential"],"aid":"0","scy":"auto","net":"ws","type":"none","host":host,"path":p["path"],"tls":"tls","sni":SNI}
    return "vmess://" + base64.b64encode(json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()).decode()


def write_xray_config(users):
    clients = {"trojan": [], "vless": [], "vmess": []}
    for u in users:
        defaults_for_user(u)
        if not user_enabled(u): continue
        if u["protocol"] == "trojan": clients["trojan"].append({"password":u["credential"],"email":u["username"]})
        elif u["protocol"] == "vless": clients["vless"].append({"id":u["credential"],"email":u["username"],"level":0})
        else: clients["vmess"].append({"id":u["credential"],"email":u["username"],"alterId":0})
    cfg = {
      "log":{"loglevel":"warning","access":ACCESS_LOG,"error":ERROR_LOG},
      "api":{"tag":"api","listen":"127.0.0.1:10085","services":["StatsService"]},
      "stats":{},
      "policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True,"statsUserOnline":True,"connIdle":300}},"system":{"statsInboundUplink":True,"statsInboundDownlink":True}},
      "inbounds":[
        {"tag":"trojan-ws","listen":"127.0.0.1","port":10000,"protocol":"trojan","settings":{"clients":clients["trojan"]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":PROTOCOLS["trojan"]["path"]}}},
        {"tag":"vless-ws","listen":"127.0.0.1","port":10001,"protocol":"vless","settings":{"clients":clients["vless"],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":PROTOCOLS["vless"]["path"]}}},
        {"tag":"vmess-ws","listen":"127.0.0.1","port":10002,"protocol":"vmess","settings":{"clients":clients["vmess"]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":PROTOCOLS["vmess"]["path"]}}}
      ],
      "outbounds":[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}]
    }
    raw=json.dumps(cfg,indent=2).encode(); atomic_write(XRAY_CONFIG,raw); open("/tmp/xray-reload","w").close()


def audit(action, username):
    try:
        c=sqlite3.connect(DB_FILE); c.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, username TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        c.execute("INSERT INTO audit(action,username) VALUES (?,?)",(action,username)); c.commit(); c.close()
    except Exception: pass


def public_user(u, host, info=None, usage=None):
    info = info or {}; usage = usage or {}
    return {"id":u["id"],"username":u["username"],"protocol":u["protocol"],"credential":u["credential"],"created_at":u.get("created_at",""),"enabled":u.get("enabled",True),"expires_at":u.get("expires_at",""),"expired":expired(u),"max_devices":int(u.get("max_devices",0) or 0),"traffic_limit_gb":float(u.get("traffic_limit_gb",0) or 0),"traffic_used_gb":round(float(usage.get(u["username"],0))/1073741824,3),"note":u.get("note",""),"online":info.get("online",False),"ips":info.get("ips",[]),"last_seen":info.get("last_seen",0),"uri":make_uri(u,host),"subscription_url":f"https://{host}/sub/{quote(u.get('sub_token',''),safe='')}","client_config_url":f"https://{host}/api/config?id={quote(u['id'],safe='')}","sub_token":u.get("sub_token",""),"server_name":load_settings().get("server_name","Ghanizada VPN") }


def cpu_percent():
    try:
        a=float(os.getloadavg()[0]); cpus=os.cpu_count() or 1
        return min(100, round(a/cpus*100,1))
    except Exception:return 0


def memory_percent():
    try:
        vals={}
        with open("/proc/meminfo") as f:
            for line in f:
                k,v=line.split(":",1); vals[k]=int(v.strip().split()[0])
        return round((1-vals.get("MemAvailable",0)/max(vals.get("MemTotal",1),1))*100,1)
    except Exception:return 0


def uptime():
    s=int(time.time()-START_TIME); h,r=divmod(s,3600); m,s=divmod(r,60); d,h=divmod(h,24); return f"{d}d {h:02d}:{m:02d}:{s:02d}"




def xray_stats():
    try:
        p = subprocess.run(["/usr/bin/xray", "api", "statsquery", "--server=127.0.0.1:10085"], capture_output=True, text=True, timeout=5, check=True)
        data = json.loads(p.stdout)
        out = {}
        for item in data.get("stat", []):
            name = item.get("name", "")
            value = int(float(item.get("value", 0)))
            parts = name.split(">>>")
            if len(parts) >= 4 and parts[0] == "user":
                out.setdefault(parts[1], {})[parts[3]] = value
        return out
    except Exception:
        return {}


def traffic_usage():
    current = xray_stats()
    path = os.path.join(os.path.dirname(USERS_FILE) or "/tmp", "usage.json")
    state = load_json_file(path, {})
    changed = False
    for email, vals in current.items():
        up = int(vals.get("uplink", 0)); down = int(vals.get("downlink", 0))
        old = state.get(email, {})
        last_up = int(old.get("last_up", 0)); last_down = int(old.get("last_down", 0))
        total = int(old.get("total", 0))
        if up >= last_up: total += up-last_up
        else: total += up
        if down >= last_down: total += down-last_down
        else: total += down
        state[email] = {"last_up": up, "last_down": down, "total": total, "updated_at": time.time()}
        changed = True
    if changed:
        raw=save_json_file(path,state); gcs_save("usage.json",raw)
    return {k:int(v.get("total",0)) for k,v in state.items()}


def traffic_breakdown():
    current=xray_stats(); up=down=0
    for vals in current.values():
        up += int(vals.get("uplink",0)); down += int(vals.get("downlink",0))
    return {"uplink_bytes":up,"downlink_bytes":down}

def storage_status():
    if not PERSIST_BUCKET: return {"configured":False,"ok":False,"bucket":""}
    try:
        ok = gcs_load("users.json") is not None or gcs_load("admin.json") is not None
    except Exception: ok=False
    return {"configured":True,"ok":ok,"bucket":PERSIST_BUCKET}

def service_health():
    def alive(name):
        try:
            if name=="xray": return subprocess.run(["/usr/bin/xray","version"],capture_output=True,timeout=3).returncode==0 and os.path.exists("/tmp/xray.pid")
            if name=="caddy": return True
            return True
        except Exception: return False
    return {"xray":alive("xray"),"dashboard":True,"caddy":alive("caddy"),"storage":storage_status(),"uptime":uptime()}

def enforce_limits():
    while True:
        try:
            users = load_users(); usage = traffic_usage(); changed=False
            info = online_info()
            for u in users:
                defaults_for_user(u)
                if u.get("max_devices",0)>0 and len(info.get(u["id"],{}).get("ips",[])) > int(u["max_devices"]):
                    if u.get("enabled",True):
                        u["enabled"] = False; changed=True; audit("device_limit",u["username"])
                limit = float(u.get("traffic_limit_gb",0) or 0)
                if limit > 0 and usage.get(u["username"],0) >= limit*1024*1024*1024:
                    if u.get("enabled",True):
                        u["enabled"] = False; changed=True; audit("traffic_limit",u["username"])
                if expired(u) and u.get("enabled",True):
                    u["enabled"] = False; changed=True; audit("expired",u["username"])
            if changed:
                save_users(users); write_xray_config(users)
        except Exception:
            pass
        time.sleep(20)

class Handler(BaseHTTPRequestHandler):
    def send_bytes(self,body,ctype,code=200,extra=None):
        self.send_response(code); self.send_header("Content-Type",ctype); self.send_header("Cache-Control","no-store");
        for k,v in (extra or {}).items(): self.send_header(k,v)
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def json(self,data,code=200): self.send_bytes(json.dumps(data,ensure_ascii=False).encode(),"application/json; charset=utf-8",code)
    def read_json(self):
        n=int(self.headers.get("Content-Length","0")); return json.loads(self.rfile.read(n) or b"{}")
    def host(self): return self.headers.get("Host","localhost").split(":")[0]
    def need_auth(self):
        if not session_ok(self): self.json({"error":"Authentication required"},401); return False
        return True
    def do_GET(self):
        cleanup_sessions(); p=urlparse(self.path)
        if p.path=="/": return self.page()
        if p.path=="/healthz": return self.json({"ok":True,"users":len(load_users())})
        if p.path=="/api/stats":
            info=online_info(); users=load_users(); tb=traffic_breakdown(); return self.json({"active_count":sum(1 for x in info.values() if x["online"]),"total_users":len(users),"enabled_users":sum(1 for x in users if user_enabled(x)),"expired_users":sum(1 for x in users if expired(x)),"cpu_percent":cpu_percent(),"memory_percent":memory_percent(),"uptime":uptime(),"traffic_total_bytes":sum(traffic_usage().values()),"uplink_bytes":tb["uplink_bytes"],"downlink_bytes":tb["downlink_bytes"],"health":service_health()})
        if p.path=="/api/me":
            if not self.need_auth(): return
            return self.json({"ok":True,"session_expires_in":max(0,int(SESSIONS.get(self.headers.get("Authorization","")[7:],0)-time.time()))})
        if p.path=="/api/users":
            if not self.need_auth(): return
            info=online_info(); usage=traffic_usage(); return self.json([public_user(u,self.host(),info.get(u["id"],{}),usage) for u in load_users()])
        if p.path=="/api/qr":
            if not self.need_auth(): return
            uid=parse_qs(p.query).get("id",[""])[0]; u=next((x for x in load_users() if x["id"]==uid),None)
            if not u:return self.json({"error":"User not found"},404)
            return self.qr(make_uri(u,self.host()))
        if p.path=="/api/logs":
            if not self.need_auth(): return
            kind=parse_qs(p.query).get("kind",["access"])[0]; path=ERROR_LOG if kind=="error" else ACCESS_LOG
            try:
                with open(path,"r",encoding="utf-8",errors="replace") as f: lines=f.readlines()[-200:]
            except Exception: lines=[]
            return self.json({"lines":lines})
        if p.path=="/api/health":
            if not self.need_auth(): return
            return self.json(service_health())
        if p.path=="/api/audit":
            if not self.need_auth(): return
            try:
                c=sqlite3.connect(DB_FILE); rows=c.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, username TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)") or None
                rows=c.execute("SELECT id,action,username,created_at FROM audit ORDER BY id DESC LIMIT 100").fetchall(); c.close()
            except Exception: rows=[]
            return self.json([{"id":r[0],"action":r[1],"username":r[2],"created_at":r[3]} for r in rows])
        if p.path=="/api/config":
            if not self.need_auth(): return
            uid=parse_qs(p.query).get("id",[""])[0]; u=next((x for x in load_users() if x["id"]==uid),None)
            if not u:return self.json({"error":"User not found"},404)
            return self.send_bytes(make_uri(u,self.host()).encode(),"text/plain; charset=utf-8",200,{"Content-Disposition":f'attachment; filename="{u["username"]}-{u["protocol"]}.txt"'})
        if p.path.startswith("/sub/"):
            token=p.path.split("/",2)[2]
            u=next((x for x in load_users() if hmac.compare_digest(str(x.get("sub_token","")),token)),None)
            if not u or not user_enabled(u): return self.send_bytes(b"", "text/plain; charset=utf-8", 404)
            uri=make_uri(u,self.host())
            payload=base64.b64encode(uri.encode()).decode()+"\n"
            return self.send_bytes(payload.encode(),"text/plain; charset=utf-8",200,{"Content-Disposition":'inline; filename="subscription.txt"'})
        if p.path=="/api/sessions":
            if not self.need_auth(): return
            return self.json({"count":len(SESSIONS),"sessions":[{"expires_in":max(0,int(v-time.time()))} for v in SESSIONS.values()]})
        if p.path=="/api/settings":
            if not self.need_auth(): return
            return self.json(load_settings())
        if p.path=="/api/notifications":
            if not self.need_auth(): return
            users=load_users(); notices=[]; now=time.time(); usage=traffic_usage()
            for u in users:
                if not user_enabled(u): continue
                if u.get("expires_at"):
                    try:
                        exp=time.mktime(time.strptime(u["expires_at"],"%Y-%m-%d")); days=int((exp-now)/86400)
                        if 0 <= days <= 7: notices.append({"type":"expiry","username":u["username"],"message":f'{u["username"]} expires in {days} day(s)'})
                    except Exception: pass
                lim=float(u.get("traffic_limit_gb",0) or 0); used=float(usage.get(u["username"],0))/1073741824
                if lim and used >= lim*0.8: notices.append({"type":"traffic","username":u["username"],"message":f'{u["username"]} has used {used:.2f} / {lim:.2f} GB'})
            return self.json(notices)
        if p.path=="/api/backup/create":
            if not self.need_auth(): return
            try: return self.json({"ok":True,"backup":save_backup_snapshot()})
            except Exception as e: return self.json({"error":str(e)},500)
        if p.path=="/api/export":
            if not self.need_auth(): return
            raw=json.dumps({"version":2,"exported_at":time.strftime("%Y-%m-%d %H:%M:%S"),"users":load_users(),"usage":load_json_file(os.path.join(os.path.dirname(USERS_FILE) or "/tmp","usage.json"),{})},indent=2,ensure_ascii=False).encode(); return self.send_bytes(raw,"application/json; charset=utf-8",200,{"Content-Disposition":"attachment; filename=ghanizada-backup.json"})
        self.send_error(404)
    def do_POST(self):
        cleanup_sessions(); p=urlparse(self.path)
        if p.path=="/api/login":
            d=self.read_json(); password=str(d.get("password", "")); a=load_admin()
            if not verify_password(password,a): return self.json({"error":"Invalid admin password"},401)
            return self.json({"token":create_session(),"expires_in":SESSION_TTL})
        if p.path=="/api/logout":
            tok=self.headers.get("Authorization","")[7:] if self.headers.get("Authorization","").startswith("Bearer ") else ""; SESSIONS.pop(tok,None); return self.json({"ok":True})
        if p.path=="/api/users":
            if not self.need_auth(): return
            d=self.read_json(); protocol=d.get("protocol"); username=(d.get("username") or "").strip(); credential=(d.get("credential") or "").strip()
            if protocol not in PROTOCOLS or not username:return self.json({"error":"Protocol and username are required"},400)
            users=load_users()
            if any(x["username"].lower()==username.lower() for x in users):return self.json({"error":"Username already exists"},409)
            if not credential: credential=str(uuid.uuid4()) if protocol!="trojan" else secrets.token_urlsafe(16)
            settings=load_settings()
            if not d.get("expires_at") and int(settings.get("default_expiry_days",0) or 0)>0:
                d["expires_at"]=time.strftime("%Y-%m-%d",time.localtime(time.time()+int(settings["default_expiry_days"])*86400))
            d.setdefault("max_devices",settings.get("default_devices",0)); d.setdefault("traffic_limit_gb",settings.get("default_traffic_gb",0))
            if any(x["credential"]==credential for x in users):return self.json({"error":"Credential already exists"},409)
            u={"id":secrets.token_hex(8),"username":username,"protocol":protocol,"credential":credential,"created_at":time.strftime("%Y-%m-%d %H:%M:%S"),"enabled":bool(d.get("enabled",True)),"expires_at":str(d.get("expires_at","") or ""),"max_devices":max(0,int(d.get("max_devices",0) or 0)),"traffic_limit_gb":max(0,float(d.get("traffic_limit_gb",0) or 0)),"note":str(d.get("note","") or ""),"sub_token":secrets.token_urlsafe(24),"ip_reset_at":0}
            users.append(u); save_users(users); write_xray_config(users); audit("create",username); return self.json(public_user(u,self.host(),{},traffic_usage()),201)
        if p.path=="/api/import":
            if not self.need_auth(): return
            d=self.read_json(); users=d.get("users") if isinstance(d,dict) else d
            if not isinstance(users,list): return self.json({"error":"Expected JSON array or {users:[...]}"},400)
            imported_usage=d.get("usage",{}) if isinstance(d,dict) else {}
            clean=[]; names=set(); creds=set()
            for u in users:
                if not isinstance(u,dict) or u.get("protocol") not in PROTOCOLS or not u.get("username") or not u.get("credential"): continue
                u=dict(u); u["id"]=u.get("id") or secrets.token_hex(8); defaults_for_user(u)
                if u["username"].lower() in names or u["credential"] in creds: continue
                names.add(u["username"].lower()); creds.add(u["credential"]); clean.append(u)
            save_users(clean); write_xray_config(clean)
            if isinstance(imported_usage,dict):
                raw=save_json_file(os.path.join(os.path.dirname(USERS_FILE) or "/tmp","usage.json"),imported_usage); gcs_save("usage.json",raw)
            audit("import",str(len(clean))); return self.json({"ok":True,"imported":len(clean)})
        if p.path=="/api/backup/create":
            if not self.need_auth(): return
            try: return self.json({"ok":True,"backup":save_backup_snapshot()})
            except Exception as e: return self.json({"error":str(e)},500)
        if p.path=="/api/users/regenerate-sub":
            if not self.need_auth(): return
            d=self.read_json(); uid=str(d.get("id","")); users=load_users(); u=next((x for x in users if x["id"]==uid),None)
            if not u:return self.json({"error":"User not found"},404)
            u["sub_token"]=secrets.token_urlsafe(24); save_users(users); audit("regenerate_subscription",u["username"])
            return self.json({"ok":True,"subscription_url":f"https://{self.host()}/sub/{quote(u["sub_token"],safe="")}"})
        if p.path=="/api/sessions/logout-all":
            if not self.need_auth(): return
            SESSIONS.clear(); return self.json({"ok":True})
        if p.path=="/api/settings":
            if not self.need_auth(): return
            d=self.read_json(); cur=load_settings()
            b=d.get("ssh_backend",cur.get("ssh_backend",{})) or {}
            host=str(b.get("host","")).strip()
            try: port=int(b.get("port",443) or 443)
            except Exception: return self.json({"error":"SSH backend port must be a number"},400)
            path=str(b.get("path","/ws/ssh")).strip() or "/ws/ssh"
            if not path.startswith("/"): path="/"+path
            if len(host)>253 or any(c.isspace() for c in host) or "/" in host or (":" in host and not (host.startswith("[") and host.endswith("]"))):
                return self.json({"error":"SSH backend host must be a hostname or IPv4 address, without scheme/path"},400)
            if port<1 or port>65535:return self.json({"error":"SSH backend port must be 1-65535"},400)
            if not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]*$",path):return self.json({"error":"SSH backend path is invalid"},400)
            cur.update({"server_name":str(d.get("server_name",cur.get("server_name","Ghanizada VPN")))[:80],"default_expiry_days":max(0,int(d.get("default_expiry_days",cur.get("default_expiry_days",0)) or 0)),"default_devices":max(0,int(d.get("default_devices",cur.get("default_devices",0)) or 0)),"default_traffic_gb":max(0,float(d.get("default_traffic_gb",cur.get("default_traffic_gb",0)) or 0)),"notifications":bool(d.get("notifications",cur.get("notifications",True))),"ssh_backend":{"enabled":bool(b.get("enabled",False)),"host":host,"port":port,"path":path}})
            save_settings(cur); ok,msg=configure_caddy_backend(reload=True); audit("settings","admin")
            cur["ssh_backend_status"]={"ok":ok,"message":msg}
            return self.json(cur)
        if p.path=="/api/admin/password":
            if not self.need_auth(): return
            d=self.read_json(); current=str(d.get("current", "")); new=str(d.get("new", ""))
            if len(new)<8:return self.json({"error":"New password must be at least 8 characters"},400)
            if not verify_password(current,load_admin()):return self.json({"error":"Current password is incorrect"},401)
            rec=hash_password(new); rec["updated_at"]=time.strftime("%Y-%m-%d %H:%M:%S"); save_admin(rec); SESSIONS.clear(); return self.json({"ok":True})
        if p.path=="/api/users/reset-traffic":
            if not self.need_auth(): return
            d=self.read_json(); uid=str(d.get("id","")); users=load_users(); u=next((x for x in users if x["id"]==uid),None)
            if not u:return self.json({"error":"User not found"},404)
            path=os.path.join(os.path.dirname(USERS_FILE) or "/tmp","usage.json"); state=load_json_file(path,{})
            stats=xray_stats().get(u["username"],{}); state[u["username"]]={"last_up":int(stats.get("uplink",0)),"last_down":int(stats.get("downlink",0)),"total":0,"updated_at":time.time()}
            raw=save_json_file(path,state); gcs_save("usage.json",raw); audit("reset_traffic",u["username"]); return self.json({"ok":True})
        if p.path=="/api/users/reset-ips":
            if not self.need_auth(): return
            d=self.read_json(); uid=str(d.get("id","")); users=load_users(); u=next((x for x in users if x["id"]==uid),None)
            if not u:return self.json({"error":"User not found"},404)
            u["ip_reset_at"]=time.time(); save_users(users); audit("reset_ips",u["username"]); return self.json({"ok":True})
        if p.path=="/api/xray/restart":
            if not self.need_auth(): return
            open("/tmp/xray-reload","w").close(); return self.json({"ok":True,"message":"Xray restart requested"})
        self.send_error(404)
    def do_PUT(self):
        if not self.need_auth(): return
        parts=urlparse(self.path).path.split("/")
        if len(parts)!=4 or parts[2]!="users": return self.json({"error":"Not found"},404)
        uid=parts[3]; d=self.read_json(); users=load_users(); u=next((x for x in users if x["id"]==uid),None)
        if not u:return self.json({"error":"User not found"},404)
        newname=(d.get("username") or u["username"]).strip(); cred=(d.get("credential") or u["credential"]).strip()
        if not newname:return self.json({"error":"Username required"},400)
        if any(x["id"]!=uid and x["username"].lower()==newname.lower() for x in users):return self.json({"error":"Duplicate username"},409)
        if any(x["id"]!=uid and x["credential"]==cred for x in users):return self.json({"error":"Credential already exists"},409)
        u.setdefault("sub_token",secrets.token_urlsafe(24)); u.update({"username":newname,"protocol":d.get("protocol",u.get("protocol","trojan")) if d.get("protocol",u.get("protocol")) in PROTOCOLS else u.get("protocol","trojan"),"credential":cred,"enabled":bool(d.get("enabled",u.get("enabled",True))),"expires_at":str(d.get("expires_at",u.get("expires_at","")) or ""),"max_devices":max(0,int(d.get("max_devices",u.get("max_devices",0)) or 0)),"traffic_limit_gb":max(0,float(d.get("traffic_limit_gb",u.get("traffic_limit_gb",0)) or 0)),"note":str(d.get("note",u.get("note", "")) or "")})
        save_users(users); write_xray_config(users); audit("edit",newname); return self.json(public_user(u,self.host(),online_info().get(uid,{}),traffic_usage()))
    def do_DELETE(self):
        if not self.need_auth(): return
        parts=urlparse(self.path).path.split("/")
        if len(parts)!=4 or parts[2]!="users": return self.json({"error":"Not found"},404)
        uid=parts[3]; users=load_users(); u=next((x for x in users if x["id"]==uid),None)
        if not u:return self.json({"error":"User not found"},404)
        save_users([x for x in users if x["id"]!=uid]); write_xray_config(load_users()); audit("delete",u["username"]); return self.json({"ok":True})
    def qr(self,uri):
        try:
            # PNG avoids mobile-browser SVG aspect-ratio/stretching issues.
            # Keep the QR bitmap square and use high error correction for easier scanning.
            proc=subprocess.run(["qrencode","-t","PNG","-l","H","-m","4","-s","8","-o","-",uri],capture_output=True,timeout=3,check=True)
            return self.send_bytes(proc.stdout,"image/png")
        except Exception as e:return self.json({"error":"QR generator unavailable","detail":str(e)},503)
    def page(self): self.send_bytes(HTML.encode(),"text/html; charset=utf-8")
    def log_message(self,fmt,*args): pass


HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#070b14"><title>Ghanizada • Admin</title>
<style>
:root{color-scheme:dark;--bg:#070b14;--panel:#0d1422;--line:#22304a;--text:#f7f9fc;--muted:#8d9ab0;--blue:#4f7cff;--green:#39d98a;--red:#ef5b6b;--shadow:0 20px 60px #0008}*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:var(--bg);color:var(--text)}button,input,select,textarea{font:inherit}button{cursor:pointer}.hidden{display:none!important}
.login-screen{min-height:100vh;display:grid;place-items:center;padding:22px;background:radial-gradient(circle at 50% 0,#18264b 0,#0b1020 32%,#070b14 68%)}.login-card{width:min(430px,100%);background:#0c1321ee;border:1px solid #2a3b5d;border-radius:28px;padding:32px;box-shadow:var(--shadow);backdrop-filter:blur(16px)}.logo{width:58px;height:58px;border-radius:17px;display:grid;place-items:center;background:linear-gradient(135deg,#527dff,#27d9c3);font-weight:1000;font-size:22px;color:white;margin-bottom:20px}.login-card h1{margin:0;font-size:29px}.login-card p{color:var(--muted);margin:8px 0 25px}.login-input{width:100%;padding:15px 16px;background:#070c16;border:1px solid #2b3a56;border-radius:14px;color:white;outline:none}.login-input:focus{border-color:var(--blue);box-shadow:0 0 0 3px #4f7cff22}.login-btn{width:100%;margin-top:12px;padding:14px;border:0;border-radius:14px;background:linear-gradient(135deg,#4f7cff,#355fe8);color:#fff;font-weight:900}.login-error{min-height:20px;color:#ff8d99;font-size:13px;margin-top:10px}
.app{min-height:100vh;display:grid;grid-template-columns:250px 1fr}.sidebar{background:#090e18;border-right:1px solid #1d2940;padding:22px 16px;position:sticky;top:0;height:100vh}.side-brand{display:flex;align-items:center;gap:10px;padding:4px 8px 24px}.side-logo{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,#527cff,#28d7c2);display:grid;place-items:center;font-weight:1000}.side-name{font-weight:900}.side-name small{display:block;color:var(--muted);font-size:10px;letter-spacing:2px;margin-top:2px}.nav{display:grid;gap:7px}.nav button{border:1px solid transparent;background:transparent;color:#aeb9ca;text-align:left;padding:12px 13px;border-radius:12px;font-weight:800}.nav button.active,.nav button:hover{background:#141e31;border-color:#263754;color:white}.side-bottom{position:absolute;bottom:20px;left:16px;right:16px}.logout{width:100%;background:#131b2a;border:1px solid #273650;color:#c8d1df;padding:11px;border-radius:12px;font-weight:800}.main{min-width:0;padding:24px}.topbar{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:22px}.top-title h2{margin:0;font-size:25px}.top-title p{margin:4px 0 0;color:var(--muted);font-size:13px}.server-pill{padding:9px 12px;border-radius:999px;background:#0c211a;border:1px solid #1f674c;color:#67e8b0;font-size:12px;font-weight:900}.section{display:none}.section.active{display:block}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:18px}.card{background:var(--panel);border:1px solid var(--line);border-radius:17px;padding:17px;box-shadow:0 10px 30px #0003}.card-label{font-size:11px;color:var(--muted);font-weight:900;letter-spacing:1px}.card-value{font-size:25px;font-weight:950;margin-top:8px}.card-sub{font-size:11px;color:#68758b;margin-top:5px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:19px;padding:18px;margin-bottom:15px}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:15px}.panel-head h3{margin:0;font-size:17px}.toolbar{display:flex;gap:9px;flex-wrap:wrap}.input,.select{background:#080e18;border:1px solid #2b3a55;color:#fff;border-radius:11px;padding:11px 12px;outline:none}.search{min-width:220px;flex:1}.input:focus,.select:focus{border-color:var(--blue)}.btn{border:0;border-radius:11px;padding:10px 13px;background:var(--blue);color:white;font-weight:900}.btn.green{background:#12805b}.btn.gray{background:#1a2537}.btn.red{background:#a72f40}.btn:hover{filter:brightness(1.08)}
.user-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(285px,1fr));gap:12px}.user{background:#0a111d;border:1px solid #20304a;border-radius:17px;padding:15px}.user-top{display:flex;justify-content:space-between;gap:10px}.user-name{font-weight:950;font-size:17px}.proto{display:inline-block;margin-top:5px;font-size:10px;font-weight:900;color:#91b1ff;background:#172441;border:1px solid #29416d;padding:4px 7px;border-radius:999px;text-transform:uppercase}.status{font-size:11px;font-weight:900}.online{color:var(--green)}.offline{color:#64748b}.expired{color:#ff7e8b}.user-meta{color:#93a1b5;font-size:11px;line-height:1.7;margin-top:12px}.user-actions{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-top:12px}.user-actions button{padding:9px 7px;font-size:11px}.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.health{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.health-item{background:#0a111d;border:1px solid #20304a;border-radius:13px;padding:12px}.health-item b{display:block;margin-top:6px}.ok{color:var(--green)}.bad{color:var(--red)}.logs{background:#070c15;border:1px solid #263650;border-radius:13px;padding:13px;white-space:pre-wrap;max-height:360px;overflow:auto;font-size:11px;color:#b7c4d8}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field label{display:block;color:#8e9bb0;font-size:11px;margin-bottom:6px}.field .input,.field .select{width:100%}.setting-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.notice{padding:10px 0;border-bottom:1px solid #1c293e;color:#b8c4d7;font-size:12px}
.modal{position:fixed;inset:0;background:#02050bd9;display:none;align-items:center;justify-content:center;padding:18px;z-index:50;backdrop-filter:blur(8px)}.modal.show{display:flex}.modalbox{width:min(760px,100%);max-height:92vh;overflow:auto;background:#0d1422;border:1px solid #2b3c5c;border-radius:24px;box-shadow:var(--shadow);padding:20px}.modal-head{display:flex;justify-content:space-between;align-items:center;gap:12px}.closex{width:38px;height:38px;border-radius:11px;border:1px solid #2b3a55;background:#121b2b;color:#d7dfeb}.qr-layout{display:grid;grid-template-columns:250px 1fr;gap:20px;margin-top:16px}.qr-frame{width:240px;height:240px;background:#fff;border-radius:18px;padding:15px;display:grid;place-items:center;margin:auto;box-shadow:0 12px 35px #0005}.qr-frame img{width:210px!important;height:210px!important;max-width:210px!important;max-height:210px!important;display:block;object-fit:contain;aspect-ratio:1/1;image-rendering:pixelated}.qr-error{color:#4a5568;text-align:center;font-size:12px;padding:10px}.uri,.sub{width:100%;background:#070c15;border:1px solid #263650;border-radius:12px;color:#dbe6f7;padding:12px;word-break:break-all}.uri{min-height:130px;resize:vertical}.sub{font-size:12px;min-height:54px}.modal-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}@media(max-width:900px){.app{grid-template-columns:1fr}.sidebar{height:auto;position:relative;border-right:0;border-bottom:1px solid #1d2940;padding:10px}.side-brand{padding:5px 8px 10px}.nav{display:flex;overflow:auto}.nav button{white-space:nowrap}.side-bottom{position:static;margin-top:8px}.main{padding:14px}.cards{grid-template-columns:repeat(2,1fr)}}@media(max-width:620px){.cards{grid-template-columns:1fr 1fr}.qr-layout{grid-template-columns:1fr}.qr-frame{width:230px;height:230px}.form-grid,.setting-grid{grid-template-columns:1fr}.topbar{align-items:flex-start}.server-pill{font-size:10px}.search{min-width:100%}.user-grid{grid-template-columns:1fr}}
</style></head><body>
<div id="login" class="login-screen"><div class="login-card"><div class="logo">G</div><h1>Ghanizada Admin</h1><p>Secure control panel for your Cloud Run service.</p><input id="password" class="login-input" type="password" placeholder="Admin password" autocomplete="current-password" onkeydown="if(event.key==='Enter')login()"><button class="login-btn" onclick="login()">LOGIN TO DASHBOARD</button><div id="loginError" class="login-error"></div></div></div>
<div id="app" class="app hidden"><aside class="sidebar"><div class="side-brand"><div class="side-logo">G</div><div class="side-name">GHANIZADA<small>ADMIN PANEL</small></div></div><div class="nav"><button class="active" data-tab="dashboard" onclick="showTab('dashboard',this)">◈ Dashboard</button><button data-tab="users" onclick="showTab('users',this)">♙ Users</button><button data-tab="server" onclick="showTab('server',this)">▣ Server</button><button data-tab="security" onclick="showTab('security',this)">⌾ Security</button><button data-tab="backup" onclick="showTab('backup',this)">▤ Backup</button><button data-tab="settings" onclick="showTab('settings',this)">⚙ Settings</button></div><div class="side-bottom"><button class="logout" onclick="logout()">LOG OUT</button></div></aside>
<main class="main"><div class="topbar"><div class="top-title"><h2 id="pageTitle">Dashboard</h2><p id="pageSub">Server overview and account activity</p></div><div class="server-pill">● SYSTEM ONLINE</div></div>
<section id="dashboardTab" class="section active"><div class="cards"><div class="card"><div class="card-label">TOTAL USERS</div><div class="card-value" id="total">0</div><div class="card-sub">All accounts</div></div><div class="card"><div class="card-label">ONLINE NOW</div><div class="card-value" id="online">0</div><div class="card-sub">Active connections</div></div><div class="card"><div class="card-label">EXPIRED</div><div class="card-value" id="expired">0</div><div class="card-sub">Needs attention</div></div><div class="card"><div class="card-label">UPTIME</div><div class="card-value" id="uptime">—</div><div class="card-sub">Current instance</div></div></div><div class="panel"><div class="panel-head"><div><h3>System resources</h3><div class="card-sub">Live Cloud Run instance metrics</div></div></div><div class="metric-grid"><div class="card"><div class="card-label">CPU</div><div class="card-value" id="cpu">—</div></div><div class="card"><div class="card-label">RAM</div><div class="card-value" id="ram">—</div></div><div class="card"><div class="card-label">UPLOAD</div><div class="card-value" id="upload">—</div></div><div class="card"><div class="card-label">DOWNLOAD</div><div class="card-value" id="download">—</div></div></div></div><div class="panel"><div class="panel-head"><h3>Quick actions</h3></div><div class="toolbar"><button class="btn green" onclick="openCreate()">+ CREATE USER</button><button class="btn gray" onclick="showTab('users',document.querySelector('[data-tab=users]'))">MANAGE USERS</button><button class="btn gray" onclick="showTab('server',document.querySelector('[data-tab=server]'))">SERVER HEALTH</button></div></div></section>
<section id="usersTab" class="section"><div class="panel"><div class="panel-head"><div><h3>User accounts</h3><div class="card-sub">Create and manage Trojan, VLESS and VMess users</div></div><button class="btn green" onclick="openCreate()">+ CREATE USER</button></div><div class="toolbar"><input class="input search" id="search" placeholder="Search username or protocol..." oninput="render()"><select class="select" id="filter" onchange="render()"><option value="all">All users</option><option value="trojan">Trojan</option><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="online">Online</option><option value="expired">Expired</option></select></div></div><div id="userList" class="user-grid"></div></section>
<section id="serverTab" class="section"><div class="cards"><div class="card"><div class="card-label">SERVER</div><div class="card-value ok">● ONLINE</div></div><div class="card"><div class="card-label">ENABLED USERS</div><div class="card-value" id="enabled">0</div></div><div class="card"><div class="card-label">REGION</div><div class="card-value" style="font-size:19px">Cloud Run</div></div><div class="card"><div class="card-label">STORAGE</div><div class="card-value" id="storage" style="font-size:19px">—</div></div></div><div class="panel"><div class="panel-head"><h3>Service health</h3></div><div id="health" class="health"></div></div><div class="panel"><div class="panel-head"><h3>Diagnostics</h3></div><div class="toolbar"><button class="btn gray" onclick="restartXray()">RESTART XRAY</button><button class="btn gray" onclick="logs('access')">ACCESS LOG</button><button class="btn gray" onclick="logs('error')">ERROR LOG</button><button class="btn gray" onclick="auditLog()">AUDIT LOG</button></div><pre id="logbox" class="logs" style="margin-top:12px">Select a log.</pre></div></section>
<section id="securityTab" class="section"><div class="panel"><div class="panel-head"><h3>Administrator security</h3></div><div class="form-grid"><div class="field"><label>CURRENT PASSWORD</label><input class="input" id="oldpw" type="password"></div><div class="field"><label>NEW PASSWORD (8+ CHARACTERS)</label><input class="input" id="newpw" type="password"></div></div><div class="toolbar" style="margin-top:14px"><button class="btn" onclick="changePassword()">CHANGE PASSWORD</button><button class="btn gray" onclick="logoutAll()">LOG OUT ALL SESSIONS</button></div></div></section>
<section id="backupTab" class="section"><div class="panel"><div class="panel-head"><h3>Backup & restore</h3></div><div class="toolbar"><button class="btn" onclick="downloadBackup()">DOWNLOAD BACKUP</button><button class="btn gray" onclick="createBackup()">CREATE CLOUD BACKUP</button><label class="btn gray">IMPORT JSON<input id="importFile" type="file" accept="application/json" hidden onchange="importBackup()"></label></div><p class="card-sub">Cloud Storage persistence is used when configured. Local /tmp storage is ephemeral on Cloud Run.</p></div></section>
<section id="settingsTab" class="section"><div class="panel"><div class="panel-head"><h3>Panel settings</h3></div><div class="setting-grid"><div class="field"><label>SERVER NAME</label><input class="input" id="serverName"></div><div class="field"><label>DEFAULT EXPIRY DAYS</label><input class="input" id="defaultExpiry" type="number" min="0"></div><div class="field"><label>DEFAULT DEVICES</label><input class="input" id="defaultDevices" type="number" min="0"></div><div class="field"><label>DEFAULT TRAFFIC GB</label><input class="input" id="defaultTraffic" type="number" min="0" step="0.1"></div></div><div class="toolbar" style="margin-top:14px"><button class="btn" onclick="saveSettings()">SAVE SETTINGS</button><button class="btn gray" onclick="loadSettings()">RELOAD</button></div></div><div class="panel"><div class="panel-head"><div><h3>SSH / Stunnel VPS Backend</h3><div class="card-sub">Cloud Run exposes <b>/ws/ssh</b> and proxies it to your VPS WebSocket bridge.</div></div><span id="sshStatus" class="server-pill">● DISABLED</span></div><div class="notice" style="margin-bottom:14px">Use a WebSocket-capable HTTP(S) bridge on the VPS that forwards to SSH. A raw stunnel TLS listener by itself is not a WebSocket server.</div><div class="setting-grid"><div class="field"><label>ENABLE SSH BACKEND</label><select class="select" id="sshEnabled"><option value="false">Disabled</option><option value="true">Enabled</option></select></div><div class="field"><label>VPS HOSTNAME / IP</label><input class="input" id="sshHost" placeholder="ssh.example.com"></div><div class="field"><label>VPS HTTPS PORT</label><input class="input" id="sshPort" type="number" min="1" max="65535" value="443"></div><div class="field"><label>VPS WEBSOCKET PATH</label><input class="input" id="sshPath" value="/ws/ssh"></div></div><div class="toolbar" style="margin-top:14px"><button class="btn" onclick="saveSettings()">SAVE & APPLY BACKEND</button><button class="btn gray" onclick="loadSettings()">RELOAD</button></div><div class="card-sub" style="margin-top:12px">Client-facing endpoint: <code id="sshPublicPath">/ws/ssh</code></div></div><div class="panel"><div class="panel-head"><h3>Notifications</h3></div><div id="notices" class="card-sub">Loading...</div></div></section>
</main></div>
<div class="modal" id="modal"><div class="modalbox"><div class="modal-head"><div><h3 id="mtitle" style="margin:0">User</h3><div class="card-sub">Connection details</div></div><button class="closex" onclick="closeModal()">✕</button></div><div class="qr-layout"><div><div class="qr-frame" id="mqr"><div class="qr-error">Generating QR…</div></div></div><div><div class="card-label">CONNECTION URI</div><textarea id="muri" class="uri" readonly></textarea><div class="card-label" style="margin-top:12px">SUBSCRIPTION URL</div><div id="msub" class="sub">—</div><div class="modal-actions"><button class="btn" onclick="copyUri()">COPY URI</button><button class="btn gray" onclick="copySub()">COPY SUB</button><button class="btn gray" onclick="regenerateSub(window.CURRENT_USER.id)">REGENERATE SUB</button><button class="btn gray" onclick="downloadConfig()">DOWNLOAD CONFIG</button></div></div></div></div></div>
<div class="modal" id="formModal"><div class="modalbox"><div class="modal-head"><h3 id="formTitle" style="margin:0">Create User</h3><button class="closex" onclick="closeForm()">✕</button></div><div class="form-grid" style="margin-top:16px"><div class="field"><label>PROTOCOL</label><select id="fprotocol" class="select"><option value="trojan">Trojan</option><option value="vless">VLESS</option><option value="vmess">VMess</option></select></div><div class="field"><label>USERNAME</label><input class="input" id="fusername" placeholder="e.g. Ahmad"></div><div class="field"><label>PASSWORD / UUID</label><input class="input" id="fcredential" placeholder="Blank = generate automatically"></div><div class="field"><label>EXPIRY DATE</label><input class="input" id="fexpires" type="date"></div><div class="field"><label>MAX DEVICES (0 = UNLIMITED)</label><input class="input" id="fdevices" type="number" min="0" value="0"></div><div class="field"><label>TRAFFIC LIMIT GB (0 = UNLIMITED)</label><input class="input" id="ftraffic" type="number" min="0" step="0.1" value="0"></div></div><div class="field" style="margin-top:12px"><label>NOTE</label><input class="input" id="fnote" placeholder="Optional note"></div><div class="modal-actions"><button class="btn" onclick="saveUser()">SAVE USER</button><button class="btn gray" onclick="closeForm()">CANCEL</button></div></div></div>
<script>
let TOKEN=sessionStorage.getItem('ghanizada_session')||'',USERS=[],EDIT_ID='',QR_URL='';const $=id=>document.getElementById(id);const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
async function api(url,opt={}){let h={'Content-Type':'application/json'};if(TOKEN)h.Authorization='Bearer '+TOKEN;let r=await fetch(url,{...opt,headers:{...h,...(opt.headers||{})}});let d=await r.json();if(!r.ok)throw Error(d.error||'Request failed');return d}
async function login(){let pw=$('password').value.trim();$('loginError').textContent='';if(!pw){$('loginError').textContent='Enter your admin password.';return}try{let d=await api('/api/login',{method:'POST',body:JSON.stringify({password:pw})});TOKEN=d.token;sessionStorage.setItem('ghanizada_session',TOKEN);$('login').classList.add('hidden');$('app').classList.remove('hidden');$('password').value='';await refresh()}catch(e){$('loginError').textContent=e.message}}
function showTab(n,b){['dashboard','users','server','security','backup','settings'].forEach(x=>$(x+'Tab').classList.toggle('active',x===n));document.querySelectorAll('.nav button').forEach(x=>x.classList.remove('active'));if(b)b.classList.add('active');let names={dashboard:['Dashboard','Server overview and account activity'],users:['Users','Manage connection accounts'],server:['Server','Health, logs and diagnostics'],security:['Security','Administrator access'],backup:['Backup','Protect and restore data'],settings:['Settings','Panel defaults and notifications']};$('pageTitle').textContent=names[n][0];$('pageSub').textContent=names[n][1]}
function bytes(n){n=Number(n||0);if(n<1024)return n+' B';let u=['KB','MB','GB','TB'],i=-1;do{n/=1024;i++}while(n>=1024&&i<u.length-1);return n.toFixed(n<10?2:1)+' '+u[i]}
function render(){let q=$('search').value.toLowerCase(),f=$('filter').value;let arr=USERS.filter(u=>(!q||u.username.toLowerCase().includes(q)||u.protocol.includes(q))&&(f==='all'||u.protocol===f||(f==='online'&&u.online)||(f==='expired'&&u.expired)));$('userList').innerHTML=arr.map(u=>`<article class="user"><div class="user-top"><div><div class="user-name">${esc(u.username)}</div><span class="proto">${esc(u.protocol)}</span></div><div class="status ${u.online?'online':'offline'}">${u.online?'● ONLINE':'● OFFLINE'}</div></div><div class="user-meta">Credential: ${esc(u.credential)}<br>Expires: ${esc(u.expires_at||'Never')}<br>Devices: ${u.max_devices||'Unlimited'} • Traffic: ${u.traffic_used_gb} / ${u.traffic_limit_gb?u.traffic_limit_gb+' GB':'Unlimited'}<br>IPs: ${esc((u.ips||[]).join(', ')||'—')}${u.expired?'<br><span class="expired">● EXPIRED</span>':''}${u.note?'<br>Note: '+esc(u.note):''}</div><div class="user-actions"><button class="btn" onclick='showUser(${JSON.stringify(u)})'>QR / URI</button><button class="btn gray" onclick='openEdit(${JSON.stringify(u)})'>EDIT</button><button class="btn gray" onclick='toggleUser("${u.id}",${!u.enabled})'>${u.enabled?'DISABLE':'ENABLE'}</button><button class="btn gray" onclick='resetTraffic("${u.id}")'>RESET TRAFFIC</button><button class="btn gray" onclick='resetIPs("${u.id}")'>RESET IPs</button><button class="btn red" onclick='deleteUser("${u.id}")'>DELETE</button></div></article>`).join('')||'<div class="panel"><div class="card-sub">No users found.</div></div>'}
async function refresh(){try{USERS=await api('/api/users');render();let s=await api('/api/stats');$('total').textContent=s.total_users;$('online').textContent=s.active_count;$('expired').textContent=s.expired_users;$('enabled').textContent=s.enabled_users;$('cpu').textContent=s.cpu_percent+'%';$('ram').textContent=s.memory_percent+'%';$('uptime').textContent=s.uptime;$('upload').textContent=bytes(s.uplink_bytes);$('download').textContent=bytes(s.downlink_bytes);$('storage').textContent=s.health.storage.ok?'CONNECTED':(s.health.storage.configured?'ERROR':'LOCAL');$('health').innerHTML=Object.entries(s.health).filter(([k])=>k!=='storage'&&k!=='uptime').map(([k,v])=>`<div class="health-item"><span>${esc(k.toUpperCase())}</span><b class="${v?'ok':'bad'}">${v?'● OK':'● ERROR'}</b></div>`).join('')+`<div class="health-item"><span>STORAGE</span><b class="${s.health.storage.ok?'ok':'bad'}">${s.health.storage.ok?'● CONNECTED':(s.health.storage.configured?'● ERROR':'● LOCAL')}</b></div>`;loadSettings().catch(()=>{})}catch(e){if(e.message.includes('Authentication'))logout()}}
function openCreate(){EDIT_ID='';$('formTitle').textContent='Create User';['fusername','fcredential','fexpires','fnote'].forEach(id=>$(id).value='');$('fdevices').value=0;$('ftraffic').value=0;$('fprotocol').value='trojan';$('formModal').classList.add('show')}
function openEdit(u){EDIT_ID=u.id;$('formTitle').textContent='Edit User';$('fprotocol').value=u.protocol;$('fusername').value=u.username;$('fcredential').value=u.credential;$('fexpires').value=u.expires_at||'';$('fdevices').value=u.max_devices||0;$('ftraffic').value=u.traffic_limit_gb||0;$('fnote').value=u.note||'';$('formModal').classList.add('show')}
function closeForm(){$('formModal').classList.remove('show')}
async function saveUser(){let d={protocol:$('fprotocol').value,username:$('fusername').value,credential:$('fcredential').value,expires_at:$('fexpires').value,max_devices:Number($('fdevices').value||0),traffic_limit_gb:Number($('ftraffic').value||0),note:$('fnote').value};try{if(EDIT_ID)await api('/api/users/'+EDIT_ID,{method:'PUT',body:JSON.stringify(d)});else await api('/api/users',{method:'POST',body:JSON.stringify(d)});closeForm();await refresh();alert(EDIT_ID?'User updated':'User created')}catch(e){alert(e.message)}}
async function toggleUser(id,enabled){let u=USERS.find(x=>x.id===id);try{await api('/api/users/'+id,{method:'PUT',body:JSON.stringify({...u,enabled})});await refresh()}catch(e){alert(e.message)}}async function deleteUser(id){if(!confirm('Delete this user? This removes access immediately.'))return;try{await api('/api/users/'+id,{method:'DELETE'});await refresh()}catch(e){alert(e.message)}}
async function showUser(u){window.CURRENT_USER=u;$('mtitle').textContent=u.username+' • '+u.protocol;$('muri').value=u.uri;$('msub').textContent=u.subscription_url||'—';$('mqr').innerHTML='<div class="qr-error">Generating QR…</div>';$('modal').classList.add('show');try{let r=await fetch('/api/qr?id='+encodeURIComponent(u.id)+'&t='+Date.now(),{headers:{Authorization:'Bearer '+TOKEN},cache:'no-store'});if(!r.ok)throw Error('QR generator is unavailable on the server');let blob=await r.blob();if(!blob.type.includes('image'))throw Error('Invalid QR image');if(QR_URL)URL.revokeObjectURL(QR_URL);QR_URL=URL.createObjectURL(blob);$('mqr').innerHTML='<img src="'+QR_URL+'" alt="QR code">'}catch(e){$('mqr').innerHTML='<div class="qr-error">QR could not be generated.<br><br>'+esc(e.message)+'</div>'}}
function closeModal(){$('modal').classList.remove('show');if(QR_URL){URL.revokeObjectURL(QR_URL);QR_URL=''}}function copyUri(){navigator.clipboard.writeText($('muri').value).then(()=>alert('URI copied'))}function copySub(){navigator.clipboard.writeText($('msub').textContent).then(()=>alert('Subscription URL copied'))}function downloadConfig(){if(!window.CURRENT_USER)return;let a=document.createElement('a');a.href='/api/config?id='+encodeURIComponent(window.CURRENT_USER.id);a.download=window.CURRENT_USER.username+'-'+window.CURRENT_USER.protocol+'.txt';a.click()}
async function resetTraffic(id){if(!confirm('Reset traffic usage for this user?'))return;try{await api('/api/users/reset-traffic',{method:'POST',body:JSON.stringify({id})});await refresh();alert('Traffic reset')}catch(e){alert(e.message)}}async function resetIPs(id){if(!confirm('Reset recent IP/device history for this user?'))return;try{await api('/api/users/reset-ips',{method:'POST',body:JSON.stringify({id})});await refresh();alert('IP history reset')}catch(e){alert(e.message)}}async function restartXray(){try{await api('/api/xray/restart',{method:'POST'});alert('Xray restart requested')}catch(e){alert(e.message)}}async function logs(k){try{$('logbox').textContent=(await api('/api/logs?kind='+k)).lines.join('')||'No log entries.'}catch(e){$('logbox').textContent=e.message}}async function auditLog(){try{let rows=await api('/api/audit');$('logbox').textContent=rows.map(x=>`${x.created_at} | ${x.action} | ${x.username}`).join('\n')||'No audit entries.'}catch(e){$('logbox').textContent=e.message}}
async function changePassword(){try{await api('/api/admin/password',{method:'POST',body:JSON.stringify({current:$('oldpw').value,new:$('newpw').value})});alert('Password changed. Please log in again.');logout()}catch(e){alert(e.message)}}function downloadBackup(){let blob=new Blob([JSON.stringify(USERS,null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='ghanizada-users.json';a.click()}async function importBackup(){let f=$('importFile').files[0];if(!f)return;try{let d=JSON.parse(await f.text());let r=await api('/api/import',{method:'POST',body:JSON.stringify(d)});alert('Imported '+r.imported+' users');await refresh()}catch(e){alert(e.message)}}
async function loadSettings(){try{let s=await api('/api/settings');$('serverName').value=s.server_name||'';$('defaultExpiry').value=s.default_expiry_days||0;$('defaultDevices').value=s.default_devices||0;$('defaultTraffic').value=s.default_traffic_gb||0;let b=s.ssh_backend||{};$('sshEnabled').value=String(!!b.enabled);$('sshHost').value=b.host||'';$('sshPort').value=b.port||443;$('sshPath').value=b.path||'/ws/ssh';$('sshStatus').textContent=b.enabled?'● ENABLED':'● DISABLED';$('sshStatus').style.color=b.enabled?'#67e8b0':'';let n=await api('/api/notifications');$('notices').innerHTML=n.length?n.map(x=>`<div class="notice">⚠ ${esc(x.message)}</div>`).join(''):'<span class="ok">No active notifications.</span>'}catch(e){}}async function saveSettings(){try{let r=await api('/api/settings',{method:'POST',body:JSON.stringify({server_name:$('serverName').value,default_expiry_days:Number($('defaultExpiry').value||0),default_devices:Number($('defaultDevices').value||0),default_traffic_gb:Number($('defaultTraffic').value||0),notifications:true,ssh_backend:{enabled:$('sshEnabled').value==='true',host:$('sshHost').value.trim(),port:Number($('sshPort').value||443),path:$('sshPath').value.trim()||'/ws/ssh'}})});$('sshStatus').textContent=r.ssh_backend?.enabled?'● ENABLED':'● DISABLED';alert(r.ssh_backend_status?.message||'Settings saved')}catch(e){alert(e.message)}}async function regenerateSub(id){if(!confirm('Regenerate this subscription URL? Existing URL will stop working.'))return;try{let r=await api('/api/users/regenerate-sub',{method:'POST',body:JSON.stringify({id})});if(window.CURRENT_USER){window.CURRENT_USER.subscription_url=r.subscription_url;$('msub').textContent=r.subscription_url}await refresh();alert('Subscription regenerated')}catch(e){alert(e.message)}}async function logoutAll(){if(!confirm('Log out all admin sessions?'))return;try{await api('/api/sessions/logout-all',{method:'POST'});logout()}catch(e){alert(e.message)}}async function createBackup(){try{let r=await api('/api/backup/create',{method:'POST'});alert('Backup created: '+r.backup)}catch(e){alert(e.message)}}
async function logout(){TOKEN='';sessionStorage.removeItem('ghanizada_session');$('app').classList.add('hidden');$('login').classList.remove('hidden');$('password').focus()}if(TOKEN){$('login').classList.add('hidden');$('app').classList.remove('hidden');refresh().catch(()=>logout())}setInterval(()=>{if(TOKEN)refresh()},7000);
</script></body></html>
'''


if __name__ == "__main__":
    ensure_state(); db_init = lambda: None
    sqlite3.connect(DB_FILE).close()
    bootstrap_admin(OWNER_KEY)
    users=load_users()
    for u in users: defaults_for_user(u)
    save_users(users)
    if not os.path.exists(XRAY_CONFIG): write_xray_config(users)
    configure_caddy_backend(reload=False)
    threading.Thread(target=enforce_limits, daemon=True).start()
    def backup_loop():
        while True:
            time.sleep(86400)
            try: save_backup_snapshot()
            except Exception: pass
    threading.Thread(target=backup_loop, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
