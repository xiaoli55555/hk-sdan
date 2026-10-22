"""HK SDAN: authenticated multi-tenant monitoring, SQLite, outbound-only agents."""
import os, sqlite3, secrets, hashlib, time, json, re, math, sys
from pathlib import Path
from functools import wraps
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
          csrf TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS servers(id INTEGER PRIMARY KEY, name TEXT NOT NULL, owner_id INTEGER REFERENCES users(id),
          agent_hash TEXT UNIQUE NOT NULL, metrics TEXT, seen INTEGER, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
        PRAGMA user_version=1;
        ''')

def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def error(msg, status=400): return jsonify(error=msg), status

def audit(db, action):
    db.execute('INSERT INTO audit(user_id,action,created) VALUES(?,?,?)', (g.user['id'], action, int(time.time())))

def auth(admin=False):
    def decorator(fn):
        @wraps(fn)
        def inner(*a, **kw):
            with connect() as db:
                row = db.execute('SELECT users.*,sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?',
                                 (digest(request.cookies.get('hksdan', '')), int(time.time()))).fetchone()
            if not row: return error('请先登录', 401)
            g.user = dict(row)
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
    return jsonify(ok=True, version='0.1.0')

@app.post('/api/login')
def login():
    data=body(); name=str(data.get('username',''))[:64]; password=str(data.get('password',''))[:1024]
    # Do not trust X-Forwarded-For; proxy traffic also has a global safety ceiling.
    if throttled('login:'+digest(name)) or throttled('login-global', 200): return error('尝试次数过多，请 15 分钟后再试',429)
    with connect() as db:
        u=db.execute('SELECT * FROM users WHERE username=?',(name,)).fetchone()
        candidate=u['password'] if u else generate_password_hash('dummy-value')
        if not check_password_hash(candidate,password) or not u: return error('账号或密码不正确',401)
        token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(24); now=int(time.time())
        db.execute('DELETE FROM sessions WHERE expires<?',(now,))
        db.execute('DELETE FROM attempts WHERE key=?',('login:'+digest(name),))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(digest(token),u['id'],csrf,now+43200))
    r=jsonify(ok=True); r.set_cookie('hksdan',token,max_age=43200,secure=SECURE,httponly=True,samesite='Strict')
    return r

@app.get('/api/me')
@auth()
def me(): return jsonify(id=g.user['id'], username=g.user['username'],role=g.user['role'],csrf=g.user['csrf'])

@app.post('/api/logout')
@auth()
def logout():
    with connect() as db: db.execute('DELETE FROM sessions WHERE token=?',(digest(request.cookies.get('hksdan','')),))
    r=jsonify(ok=True);r.delete_cookie('hksdan',secure=SECURE,httponly=True,samesite='Strict');return r

@app.post('/api/password')
@auth()
def password():
    d=body(); new=d.get('new',''); old=d.get('old','')
    if not isinstance(new,str) or not 12<=len(new)<=128: return error('新密码需为 12～128 位')
    if not isinstance(old,str) or not check_password_hash(g.user['password'],old): return error('原密码不正确',403)
    with connect() as db:
        db.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new),g.user['id']))
        db.execute('DELETE FROM sessions WHERE user_id=?',(g.user['id'],));audit(db,'修改登录密码')
    r=jsonify(ok=True);r.delete_cookie('hksdan',secure=SECURE);return r

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
        for k in ('hostname','os','kernel','network_error'):
            v=d.get(k,'')
            if not isinstance(v,str) or len(v)>256:return error('指标格式无效：'+k)
            clean[k]=v
        clean['network_method']='TCP ESTABLISHED sockets; UDP conntrack original tuples (unreplied included)'
        db.execute('UPDATE servers SET metrics=?,seen=? WHERE id=?',(json.dumps(clean),int(time.time()),row['id']))
    return jsonify(ok=True)

@app.get('/agent.py')
def agent_download(): return send_from_directory(ROOT/'agent','agent.py',mimetype='text/x-python')
@app.get('/agent-install.sh')
def installer_download(): return send_from_directory(ROOT/'agent','install.sh',mimetype='text/plain')
@app.get('/')
def index(): return send_from_directory(ROOT/'web','index.html')
@app.get('/<path:path>')
def static(path): return send_from_directory(ROOT/'web',path)

@app.errorhandler(413)
def too_large(e): return error('请求内容过大',413)

init()
if __name__=='__main__':
    import argparse, getpass
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=['admin','backup']);parser.add_argument('target',nargs='?');args=parser.parse_args()
    if args.command=='backup':
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
