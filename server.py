"""HK SDAN: authenticated multi-tenant monitoring, SQLite, outbound-only agents."""
import os, sqlite3, secrets, hashlib, time, json, re, math, sys, ipaddress
from pathlib import Path
from functools import wraps
from network import record_network, traffic_summary
from flask import Flask, request, jsonify, g, send_from_directory, make_response
from werkzeug.security import generate_password_hash, check_password_hash

ROOT = Path(__file__).parent
DATA = Path(os.environ.get('DATA_DIR', ROOT / 'data'))
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / 'panel.db'
SECURE = os.environ.get('COOKIE_SECURE', '1') == '1'
app = Flask(__name__, static_folder=None)
app.config['MAX_CONTENT_LENGTH'] = 32768

def connect():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def init():
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','client')));
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          csrf TEXT NOT NULL, expires INTEGER NOT NULL, entry TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS servers(id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER REFERENCES users(id),
          agent_hash TEXT UNIQUE NOT NULL, metrics TEXT, seen INTEGER, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS traffic_daily(server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          day TEXT NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL, PRIMARY KEY(server_id,day));
        CREATE TABLE IF NOT EXISTS network_points(server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          stamp INTEGER NOT NULL, rx_bps REAL, tx_bps REAL, PRIMARY KEY(server_id,stamp));
        CREATE TABLE IF NOT EXISTS ip_events(id INTEGER PRIMARY KEY,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          addresses TEXT NOT NULL,observed INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS ip_events_server_time ON ip_events(server_id,observed);
        CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY,server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id),action TEXT NOT NULL,status TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS commands_pending ON commands(server_id,status,created);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT OR IGNORE INTO settings(key,value) VALUES('admin_path','/admin');
        PRAGMA user_version=5;
        ''')

        if 'entry' not in [r[1] for r in db.execute('PRAGMA table_info(sessions)')]:
            db.execute("ALTER TABLE sessions ADD COLUMN entry TEXT NOT NULL DEFAULT ''")

def admin_path():
    with connect() as db:return db.execute("SELECT value FROM settings WHERE key='admin_path'").fetchone()[0]

def entry_context():
    path=request.headers.get('X-Panel-Entry','')
    if not path:return '', 'client', 'hksdan'
    if path==admin_path():return path, 'admin', 'hksdan_admin'
    return None,None,None

def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def error(msg, status=400): return jsonify(error=msg), status

def audit(db, action):
    db.execute('INSERT INTO audit(user_id,action,created) VALUES(?,?,?)', (g.user['id'], action, int(time.time())))

def auth(admin=False):
    def decorator(fn):
        @wraps(fn)
        def inner(*a, **kw):
            entry,required_role,cookie=entry_context()
            if entry is None:return error('入口不存在',404)
            with connect() as db:
                row = db.execute('SELECT users.*,sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>? AND entry=?',
                                 (digest(request.cookies.get(cookie, '')), int(time.time()),entry)).fetchone()
            if not row or row['role']!=required_role: return error('请先登录', 401)
            g.user = dict(row)
            g.cookie=cookie
            g.entry=entry
            if admin and row['role'] != 'admin': return error('没有管理员权限', 403)
            if request.method not in ('GET','HEAD') and not secrets.compare_digest(request.headers.get('X-CSRF-Token',''), row['csrf']):
                return error('请求校验失败，请刷新页面', 403)
            return fn(*a, **kw)
        return inner
    return decorator

def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict): return {}
    return data

def throttled(key, limit=10, window=900):
    now = int(time.time())
    with connect() as db:
        db.execute('DELETE FROM attempts WHERE expires<?', (now,))
        db.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1', (key,now+window))
        return db.execute('SELECT count FROM attempts WHERE key=?', (key,)).fetchone()[0] > limit

@app.after_request
def headers(r):
    r.headers['X-Content-Type-Options']='nosniff'
    r.headers['X-Frame-Options']='DENY'
    r.headers['Referrer-Policy']='no-referrer'
    r.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.path.startswith('/api/'): r.headers['Cache-Control']='no-store'
    return r

@app.get('/health')
def health():
    with connect() as db: db.execute('SELECT 1').fetchone()
    return jsonify(ok=True, version='0.2.0')

@app.post('/api/login')
def login():
    entry,required_role,cookie=entry_context()
    if entry is None:return error('入口不存在',404)
    data=body(); name=str(data.get('username',''))[:64]; password=str(data.get('password',''))[:1024]
    # Do not trust X-Forwarded-For; proxy traffic also has a global safety ceiling.
    if throttled('login:'+digest(name)) or throttled('login-global', 200): return error('尝试次数过多，请 15 分钟后再试',429)
    with connect() as db:
        u=db.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone()
        candidate=u['password'] if u else generate_password_hash('dummy-value')
        if not check_password_hash(candidate,password) or not u or u['role']!=required_role: return error('账号或密码不正确',401)
        token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); now=int(time.time())
        db.execute('DELETE FROM sessions WHERE expires<?',(now,))
        db.execute('DELETE FROM attempts WHERE key=?',('login:'+digest(name),))
        db.execute('INSERT INTO sessions(token,user_id,csrf,expires,entry) VALUES(?,?,?,?,?)',(digest(token),u['id'],csrf,now+43200,entry))
    r=jsonify(ok=True); r.set_cookie(cookie,token,max_age=43200,secure=SECURE,httponly=True,samesite='Strict')
    return r

@app.get('/api/entry')
def get_entry():
    entry,role,cookie=entry_context()
    if entry is None:return error('入口不存在',404)
    return jsonify(kind=role)

@app.get('/api/settings')
@auth(True)
def get_settings():return jsonify(admin_path=admin_path())

@app.patch('/api/settings')
@auth(True)
def update_settings():
    value=body().get('admin_path','')
    reserved={'api','health','agent.py','agent-install.sh','agent-update.sh','app.js','style.css','password.js'}
    if not isinstance(value,str) or not re.fullmatch(r'/[A-Za-z0-9][A-Za-z0-9/_-]{2,79}',value) or value.endswith('/') or '//' in value or value.split('/')[1] in reserved:
        return error('路径需以 / 开头，3～80 位英文、数字、下划线或短横线，可分层；不能使用系统保留路径')
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute("SELECT value FROM settings WHERE key='admin_path'").fetchone()[0]!=g.entry:return error('入口已被其他管理员修改，请重新登录',409)
        if value==g.entry:return jsonify(ok=True,changed=False,admin_path=value)
        db.execute("UPDATE settings SET value=? WHERE key='admin_path'",(value,))
        db.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role='admin')")
        audit(db,'修改管理员登录入口')
    r=jsonify(ok=True,changed=True,admin_path=value);r.delete_cookie(g.cookie,secure=SECURE,httponly=True,samesite='Strict');return r

@app.get('/api/me')
@auth()
def me(): return jsonify(id=g.user['id'], username=g.user['username'],role=g.user['role'],csrf=g.user['csrf'])

@app.post('/api/logout')
@auth()
def logout():
    with connect() as db: db.execute('DELETE FROM sessions WHERE token=?',(digest(request.cookies.get(g.cookie,'')),))
    r=jsonify(ok=True);r.delete_cookie(g.cookie,secure=SECURE,httponly=True,samesite='Strict');return r

@app.post('/api/password')
@auth()
def password():
    d=body(); new=d.get('new',''); old=d.get('old','')
    if not isinstance(new,str) or not 12<=len(new)<=128: return error('新密码需为 12～128 位')
    if not isinstance(old,str) or not check_password_hash(g.user['password'],old): return error('原密码不正确',403)
    with connect() as db:
        db.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new),g.user['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?',(g.user['id'],));audit(db,'修改登录密码')
    r=jsonify(ok=True);r.delete_cookie(g.cookie,secure=SECURE);return r

@app.get('/api/users')
@auth(True)
def users():
    with connect() as db: return jsonify([dict(x) for x in db.execute('SELECT id,username,role FROM users ORDER BY id')])

@app.post('/api/users')
@auth(True)
def add_user():
    d=body(); name=d.get('username',''); pw=d.get('password','')
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}',name): return error('账号需为 3～64 位英文、数字或 _.@-')
    if not isinstance(pw,str) or not 12<=len(pw)<=128: return error('密码需为 12～128 位')
    try:
        with connect() as db:
            db.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(name,generate_password_hash(pw),'client'));audit(db,'创建客户 '+name)
    except sqlite3.IntegrityError: return error('账号已存在',409)
    return jsonify(ok=True),201

@app.get('/api/servers')
@auth()
def servers():
    with connect() as db:
        sql='SELECT servers.*,users.username AS owner FROM servers LEFT JOIN users ON users.id=servers.owner_id'
        rows=db.execute(sql+('' if g.user['role']=='admin' else ' WHERE owner_id=?')+' ORDER BY servers.id',() if g.user['role']=='admin' else (g.user['id'],)).fetchall()
    result=[];now=int(time.time())
    for row in rows:
        x=dict(row);x.pop('agent_hash');x['metrics']=json.loads(x['metrics']) if x['metrics'] else None
        x['online']=bool(x['seen'] and now-x['seen']<=60)
        with connect() as summary_db:
            x['traffic']=traffic_summary(summary_db,x['id'],now)
            command=summary_db.execute('SELECT id,status,created,updated FROM commands WHERE server_id=? ORDER BY id DESC LIMIT 1',(x['id'],)).fetchone()
            x['last_command']=dict(command) if command else None
        result.append(x)
    return jsonify(result)

@app.post('/api/servers')
@auth(True)
def add_server():
    d=body();name=d.get('name','')
    if not isinstance(name,str) or not 1<=len(name.strip())<=64: return error('服务器名称需为 1～64 字符')
    token=secrets.token_urlsafe(40)
    with connect() as db:
        c=db.execute('INSERT INTO servers(name,agent_hash,created) VALUES(?,?,?)',(name.strip(),digest(token),int(time.time())))
        audit(db,'添加服务器 '+name)
    return jsonify(id=c.lastrowid,token=token),201

@app.patch('/api/servers/<int:sid>')
@auth(True)
def assign(sid):
    owner=body().get('owner_id')
    if owner is not None and type(owner) is not int:return error('客户编号无效')
    with connect() as db:
        if not db.execute('SELECT id FROM servers WHERE id=?',(sid,)).fetchone():return error('服务器不存在',404)
        if owner is not None and not db.execute("SELECT id FROM users WHERE id=? AND role='client'",(owner,)).fetchone():return error('客户不存在')
        db.execute('UPDATE servers SET owner_id=? WHERE id=?',(owner,sid));audit(db,f'服务器 #{sid} 分配给客户 #{owner}')
    return jsonify(ok=True)

@app.post('/api/servers/<int:sid>/rotate')
@auth(True)
def rotate(sid):
    token=secrets.token_urlsafe(40)
    with connect() as db:
        if not db.execute('UPDATE servers SET agent_hash=? WHERE id=?',(digest(token),sid)).rowcount:return error('服务器不存在',404)
        audit(db,f'重置服务器 #{sid} 采集密钥')
    return jsonify(token=token)

@app.delete('/api/servers/<int:sid>')
@auth(True)
def delete(sid):
    with connect() as db:
        db.execute('DELETE FROM servers WHERE id=?',(sid,));audit(db,f'移除服务器 #{sid}')
    return jsonify(ok=True)

@app.get('/api/audit')
@auth(True)
def logs():
    with connect() as db:return jsonify([dict(r) for r in db.execute('SELECT audit.*,users.username FROM audit LEFT JOIN users ON users.id=audit.user_id ORDER BY audit.id DESC LIMIT 200')])

@app.post('/api/agent/report')
def report():
    bearer=request.headers.get('Authorization','')
    if not bearer.startswith('Bearer ') or len(bearer)>256:return error('采集认证失败',401)
    token_hash=digest(bearer[7:])
    with connect() as db:
        row=db.execute('SELECT id FROM servers WHERE agent_hash=?',(token_hash,)).fetchone()
        if not row:return error('采集认证失败',401)
        # Per-server write throttle; accept up to 30 reports a minute.
        if throttled('agent:'+str(row['id']),30,60):return error('上报过于频繁',429)
        d=body(); clean={}
        numeric={'cpu_percent':100,'memory_percent':100,'disk_percent':100,'memory_total':2**60,'disk_total':2**60,
                 'uptime':2**53,'rx_bytes':2**63,'tx_bytes':2**63,'tcp':2**53,'udp':2**53}
        for k,maximum in numeric.items():
            v=d.get(k)
            if v is None:clean[k]=None;continue
            if type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=maximum:return error('指标格式无效：'+k)
            if k in ('tcp','udp') and type(v) is not int:return error('连接数必须是整数')
            clean[k]=v
        for k in ('hostname','os','kernel','network_error','ip_error'):
            v=d.get(k,'')
            if not isinstance(v,str) or len(v)>256:return error('指标格式无效：'+k)
            clean[k]=v
        if d.get('public_ips') is not None:
            ips=d['public_ips']
            if not isinstance(ips,list) or len(ips)>64:return error('公网 IP 列表格式无效')
            try:
                normalized=[ipaddress.ip_address(ip) for ip in ips if isinstance(ip,str)]
                if len(normalized)!=len(ips) or any(not ip.is_global for ip in normalized):return error('只能上报公网 IP 地址')
                clean['public_ips']=sorted(set(str(ip) for ip in normalized))
            except ValueError:return error('IP 地址格式无效')
        clean['capabilities']=['reboot'] if isinstance(d.get('capabilities'),list) and 'reboot' in d['capabilities'] else []
        clean['network_method']='TCP ESTABLISHED sockets; UDP conntrack original tuples (unreplied included)'
        db.execute('BEGIN IMMEDIATE')
        current=db.execute('SELECT * FROM servers WHERE id=? AND agent_hash=?',(row['id'],token_hash)).fetchone()
        if not current:return error('采集密钥已失效',401)
        clean=record_network(db,current,clean,int(time.time()))
        previous=json.loads(current['metrics']) if current['metrics'] else {}
        if clean.get('uptime') is not None and previous.get('uptime') is not None and clean['uptime']<previous['uptime']:
            db.execute("UPDATE commands SET status='completed',updated=? WHERE server_id=? AND status='accepted' AND created>=?",(int(time.time()),row['id'],int(time.time())-600))
        db.execute("UPDATE commands SET status='unconfirmed',updated=? WHERE server_id=? AND status='accepted' AND created<?",(int(time.time()),row['id'],int(time.time())-600))
        if 'public_ips' in clean:
            last=db.execute('SELECT addresses FROM ip_events WHERE server_id=? ORDER BY id DESC LIMIT 1',(row['id'],)).fetchone()
            addresses=json.dumps(clean['public_ips'])
            if not last or last['addresses']!=addresses:
                db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(?,?,?)',(row['id'],addresses,int(time.time())))
            db.execute('DELETE FROM ip_events WHERE server_id=? AND id NOT IN (SELECT id FROM ip_events WHERE server_id=? ORDER BY id DESC LIMIT 1000)',(row['id'],row['id']))
        db.execute('UPDATE servers SET metrics=?,seen=? WHERE id=?',(json.dumps(clean),int(time.time()),row['id']))
        # Fetch at most one command, and mark it issued before replying (no redelivery).
        command=None;now=int(time.time())
        db.execute("UPDATE commands SET status='expired',updated=? WHERE server_id=? AND status IN ('queued','issued') AND created<?",(now,row['id'],now-120))
        if 'reboot' in clean['capabilities']:
            job=db.execute("SELECT commands.*,users.role FROM commands JOIN users ON users.id=commands.user_id WHERE server_id=? AND status='queued' ORDER BY commands.id LIMIT 1",(row['id'],)).fetchone()
            if job:
                if job['role']=='admin' or current['owner_id']==job['user_id']:
                    db.execute("UPDATE commands SET status='issued',updated=? WHERE id=?",(now,job['id']))
                    command={'id':job['id'],'action':'reboot'}
                else:db.execute("UPDATE commands SET status='cancelled',updated=? WHERE id=?",(now,job['id']))
    return jsonify(ok=True,command=command)

@app.post('/api/servers/<int:sid>/reboot')
@auth()
def request_reboot(sid):
    if body().get('confirm') is not True:return error('请确认重启操作')
    now=int(time.time())
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM servers WHERE id=?',(sid,)).fetchone()
        if not row or (g.user['role']!='admin' and row['owner_id']!=g.user['id']):return error('服务器不存在',404)
        if not row['seen'] or now-row['seen']>60:return error('服务器离线，无法下发重启',409)
        metrics=json.loads(row['metrics']) if row['metrics'] else {}
        if 'reboot' not in metrics.get('capabilities',[]):return error('请先升级此服务器的采集客户端以启用重启',409)
        db.execute("UPDATE commands SET status='expired',updated=? WHERE server_id=? AND status IN ('queued','issued') AND created<?",(now,sid,now-120))
        # Accepted commands are also held for two minutes to prevent double-clicks.
        if db.execute("SELECT id FROM commands WHERE server_id=? AND status IN ('queued','issued','accepted') AND created>=?",(sid,now-120)).fetchone():return error('已有重启任务，请等待状态更新',409)
        result=db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'reboot','queued',?,?)",(sid,g.user['id'],now,now))
        audit(db,f'请求重启服务器 #{sid}')
    return jsonify(ok=True,id=result.lastrowid),202

@app.post('/api/agent/commands/<int:cid>/ack')
def ack_command(cid):
    bearer=request.headers.get('Authorization','')
    if not bearer.startswith('Bearer ') or len(bearer)>256:return error('采集认证失败',401)
    now=int(time.time())
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        node=db.execute('SELECT id,owner_id FROM servers WHERE agent_hash=?',(digest(bearer[7:]),)).fetchone()
        if not node:return error('采集认证失败',401)
        job=db.execute('SELECT commands.*,users.role FROM commands JOIN users ON users.id=commands.user_id WHERE commands.id=? AND server_id=?',(cid,node['id'])).fetchone()
        if not job:return error('任务不存在',404)
        if job['role']!='admin' and job['user_id']!=node['owner_id']:return error('任务权限已失效',403)
        if body().get('status')=='failed':
            if job['status']!='accepted':return error('任务状态不匹配',409)
            db.execute("UPDATE commands SET status='failed',updated=? WHERE id=?",(now,cid));return jsonify(ok=True)
        if job['status']!='issued' or now-job['created']>120:return error('任务已过期或已确认',409)
        db.execute("UPDATE commands SET status='accepted',updated=? WHERE id=?",(now,cid))
    return jsonify(ok=True)

@app.get('/api/servers/<int:sid>/network')
@auth()
def network_history(sid):
    now=int(time.time());period=request.args.get('range','1h')
    if period not in ('1h','24h'):return error('时间范围无效')
    seconds,bucket=(3600,15) if period=='1h' else (86400,360)
    with connect() as db:
        row=db.execute('SELECT * FROM servers WHERE id=?',(sid,)).fetchone()
        if not row or (g.user['role']!='admin' and row['owner_id']!=g.user['id']):return error('服务器不存在',404)
        points=db.execute('SELECT CAST(stamp/? AS INTEGER)*? AS stamp,AVG(rx_bps) AS rx_bps,AVG(tx_bps) AS tx_bps FROM network_points WHERE server_id=? AND stamp>=? GROUP BY CAST(stamp/? AS INTEGER) ORDER BY stamp',(bucket,bucket,sid,now-seconds,bucket)).fetchall()
        metrics=json.loads(row['metrics']) if row['metrics'] else {};online=bool(row['seen'] and now-row['seen']<=60)
        return jsonify(points=[dict(p) for p in points],traffic=traffic_summary(db,sid,now),
                       rx_bps=metrics.get('rx_bps') if online else None,tx_bps=metrics.get('tx_bps') if online else None,
                       online=online,seen=row['seen'],uptime=metrics.get('uptime') if online else None,now=now,bucket=bucket,seconds=seconds)

@app.get('/api/servers/<int:sid>/ip-history')
@auth()
def ip_history(sid):
    with connect() as db:
        row=db.execute('SELECT owner_id,metrics,seen FROM servers WHERE id=?',(sid,)).fetchone()
        if not row or (g.user['role']!='admin' and row['owner_id']!=g.user['id']):return error('服务器不存在',404)
        events=db.execute('SELECT addresses,observed FROM ip_events WHERE server_id=? ORDER BY id DESC LIMIT 1000',(sid,)).fetchall()
        metrics=json.loads(row['metrics']) if row['metrics'] else {}
        return jsonify(events=[{'addresses':json.loads(e['addresses']),'observed':e['observed']} for e in events],
                       available='public_ips' in metrics,error=metrics.get('ip_error',''),seen=row['seen'])

@app.get('/agent-update.sh')
def agent_updater_download(): return send_from_directory(ROOT/'agent','update.sh',mimetype='text/plain')

@app.get('/agent.py')
def agent_download(): return send_from_directory(ROOT/'agent','agent.py',mimetype='text/x-python')
@app.get('/agent-install.sh')
def installer_download(): return send_from_directory(ROOT/'agent','install.sh',mimetype='text/plain')
@app.get('/')
def index():
    r=send_from_directory(ROOT/'web','index.html');r.headers['Cache-Control']='no-store';return r
@app.get('/<path:path>')
def static(path):
    if '/'+path==admin_path():return index()
    return send_from_directory(ROOT/'web',path)

@app.errorhandler(413)
def too_large(e): return error('请求内容过大',413)

init()
if __name__=='__main__':
    import argparse, getpass
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['admin','backup','entry']);parser.add_argument('target',nargs='?');args=parser.parse_args()
    if args.command=='entry':
        print('管理员入口：'+admin_path())
    elif args.command=='backup':
        if not args.target:parser.error('需要备份路径')
        with connect() as src, sqlite3.connect(args.target) as dst:src.backup(dst)
        os.chmod(args.target,0o600);print('数据库备份完成')
    else:
        username=input('管理员账号 [admin]: ').strip() or 'admin';pw=getpass.getpass('管理员密码（至少 12 位）: ')
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{3,64}',username) or not 12<=len(pw)<=128:sys.exit('账号或密码格式不正确')
        if pw!=getpass.getpass('再输入一次密码: '):sys.exit('两次密码不一致')
        with connect() as db:
            db.execute("INSERT INTO users(username,password,role) VALUES(?,?,'admin') ON CONFLICT(username) DO UPDATE SET password=excluded.password,role='admin'",(username,generate_password_hash(pw)))
            uid=db.execute('SELECT id FROM users WHERE username=?',(username,)).fetchone()[0]
            db.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
        print('管理员已配置')

