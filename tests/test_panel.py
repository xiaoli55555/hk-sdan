import unittest, tempfile, os, json, time, importlib.util
os.environ['DATA_DIR']=tempfile.mkdtemp(prefix='hksdan-test-')
os.environ['COOKIE_SECURE']='0'
import server
from werkzeug.security import generate_password_hash

class PanelTest(unittest.TestCase):
    def setUp(self):
        with server.connect() as db:
            for table in ['sessions','commands','servers','audit','attempts','users']:db.execute('DELETE FROM '+table)
            db.execute("UPDATE settings SET value='/admin' WHERE key='admin_path'")
            for name,role in [('admin','admin'),('alice','client'),('bob','client')]:
                db.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(name,generate_password_hash('correct-password-123'),role))
        self.admin,self.alice,self.bob=[server.app.test_client() for _ in range(3)]
        self.admin.environ_base['HTTP_X_PANEL_ENTRY']='/admin'
        self.tokens={}
        for client,name in [(self.admin,'admin'),(self.alice,'alice'),(self.bob,'bob')]:
            self.assertEqual(client.post('/api/login',json={'username':name,'password':'correct-password-123'}).status_code,200)
            self.tokens[name]=client.get('/api/me').json['csrf']
    def post(self,path,data=None):return self.admin.post(path,json=data or {},headers={'X-CSRF-Token':self.tokens['admin']})
    def test_tenant_boundary(self):
        r=self.post('/api/servers',{'name':'HK-01'});self.assertEqual(r.status_code,201);sid=r.json['id'];token=r.json['token']
        alice_id=self.alice.get('/api/me').json['id']
        self.assertEqual(self.admin.patch('/api/servers/'+str(sid),json={'owner_id':alice_id},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,200)
        self.assertEqual(len(self.alice.get('/api/servers').json),1)
        self.assertEqual(self.bob.get('/api/servers').json,[])
        self.assertEqual(self.bob.post('/api/servers',json={'name':'bad'},headers={'X-CSRF-Token':self.tokens['bob']}).status_code,403)
        self.assertEqual(self.bob.delete('/api/servers/'+str(sid),headers={'X-CSRF-Token':self.tokens['bob']}).status_code,403)
        self.assertEqual(self.bob.get('/api/users').status_code,403)
        result=self.admin.post('/api/agent/report',json={'tcp':2427,'udp':12},headers={'Authorization':'Bearer '+token})
        self.assertEqual(result.status_code,200)
        row=self.alice.get('/api/servers').json[0]
        self.assertEqual(row['metrics']['tcp'],2427);self.assertTrue(row['online']);self.assertNotIn('agent_hash',row)
        self.assertNotIn(token,json.dumps(row))
        with server.connect() as db:db.execute('UPDATE servers SET seen=?',(int(time.time())-100,))
        self.assertFalse(self.alice.get('/api/servers').json[0]['online'])
    def test_csrf_and_auth(self):
        self.assertEqual(server.app.test_client().get('/api/servers').status_code,401)
        self.assertEqual(self.admin.post('/api/servers',json={'name':'a'}).status_code,403)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1}).status_code,401)
        self.assertEqual(self.post('/api/users',{'username':'eve','password':'short'}).status_code,400)
    def test_token_rotation_and_metrics(self):
        r=self.post('/api/servers',{'name':'node'}).json;headers={'Authorization':'Bearer '+r['token']}
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':-1},headers=headers).status_code,400)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1.5},headers=headers).status_code,400)
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':None,'udp':None},headers=headers).status_code,200)
        self.post('/api/servers/'+str(r['id'])+'/rotate')
        self.assertEqual(self.admin.post('/api/agent/report',json={'tcp':1},headers=headers).status_code,401)
    def test_password_revokes_sessions(self):
        r=self.alice.post('/api/password',json={'old':'correct-password-123','new':'new-password-123'},headers={'X-CSRF-Token':self.tokens['alice']})
        self.assertEqual(r.status_code,200);self.assertEqual(self.alice.get('/api/me').status_code,401)
    def test_backup(self):
        destination=tempfile.mktemp()
        import sqlite3
        with server.connect() as src,sqlite3.connect(destination) as dst:src.backup(dst)
        with sqlite3.connect(destination) as db:self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone()[0],3)
        os.unlink(destination)
    def test_tcp_parser(self):
        spec=importlib.util.spec_from_file_location('agent',server.ROOT/'agent/agent.py');agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
        from pathlib import Path
        root=Path(tempfile.mkdtemp());(root/'net').mkdir()
        (root/'net/tcp').write_text('header\n0: local remote 01\n1: local remote 0A\n')
        (root/'net/tcp6').write_text('header\n0: local remote 01\n')
        self.assertEqual(agent.tcp_count(root),2)
    def test_login_throttle(self):
        c=server.app.test_client()
        for _ in range(10):self.assertEqual(c.post('/api/login',json={'username':'nobody','password':'bad'}).status_code,401)
        self.assertEqual(c.post('/api/login',json={'username':'nobody','password':'bad'}).status_code,429)
    def test_network_and_ip_access(self):
        from unittest.mock import patch
        r=self.post('/api/servers',{'name':'network-node'}).json;sid=r['id']
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch('/api/servers/'+str(sid),json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        h={'Authorization':'Bearer '+r['token']};base=int(time.time())
        with patch('server.time.time',return_value=base):
            self.assertEqual(self.admin.post('/api/agent/report',json={'rx_bytes':1000,'tx_bytes':2000,'uptime':100,'public_ips':['8.8.8.8']},headers=h).status_code,200)
        with patch('server.time.time',return_value=base+15):
            self.assertEqual(self.admin.post('/api/agent/report',json={'rx_bytes':2500,'tx_bytes':5000,'uptime':115,'public_ips':['1.1.1.1']},headers=h).status_code,200)
            d=self.alice.get(f'/api/servers/{sid}/network').json
            self.assertEqual(d['rx_bps'],800);self.assertEqual(d['tx_bps'],1600)
            self.assertEqual(d['traffic']['today_rx'],1500)
            ips=self.alice.get(f'/api/servers/{sid}/ip-history').json
            self.assertEqual(len(ips['events']),2)
            self.assertEqual(ips['events'][0]['addresses'],['1.1.1.1'])
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/network').status_code,404)
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/ip-history').status_code,404)
        # Omitted IP data from old agents does not erase the history.
        self.admin.post('/api/agent/report',json={'tcp':1},headers=h)
        self.assertEqual(len(self.alice.get(f'/api/servers/{sid}/ip-history').json['events']),2)
        self.assertEqual(self.admin.post('/api/agent/report',json={'public_ips':['127.0.0.1']},headers=h).status_code,400)

    def test_reboot_permissions_one_time_delivery_and_completion(self):
        r=self.post('/api/servers',{'name':'reboot-test'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch('/api/servers/'+str(sid),json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        ah={'X-CSRF-Token':self.tokens['alice']};bh={'X-CSRF-Token':self.tokens['bob']}
        # Offline and legacy clients cannot receive commands.
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah).status_code,409)
        self.admin.post('/api/agent/report',json={'uptime':100},headers=h)
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah).status_code,409)
        self.admin.post('/api/agent/report',json={'uptime':100,'capabilities':['reboot']},headers=h)
        self.assertEqual(self.bob.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=bh).status_code,404)
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True}).status_code,403)
        job=self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah)
        self.assertEqual(job.status_code,202);cid=job.json['id']
        self.assertEqual(self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers=ah).status_code,409)
        result=self.admin.post('/api/agent/report',json={'uptime':115,'capabilities':['reboot']},headers=h).json
        self.assertEqual(result['command'],{'id':cid,'action':'reboot'})
        self.assertIsNone(self.admin.post('/api/agent/report',json={'uptime':116,'capabilities':['reboot']},headers=h).json['command'])
        self.assertEqual(self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers={'Authorization':'Bearer bad'}).status_code,401)
        self.assertEqual(self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers=h).status_code,200)
        self.assertEqual(self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers=h).status_code,409)
        self.admin.post('/api/agent/report',json={'uptime':5,'capabilities':['reboot']},headers=h)
        self.assertEqual(self.alice.get('/api/servers').json[0]['last_command']['status'],'completed')
    def test_reboot_revoked_after_reassignment(self):
        r=self.post('/api/servers',{'name':'reassign-test'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.admin.post('/api/agent/report',json={'uptime':100,'capabilities':['reboot']},headers=h)
        self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers={'X-CSRF-Token':self.tokens['alice']})
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':None},headers={'X-CSRF-Token':self.tokens['admin']})
        report=self.admin.post('/api/agent/report',json={'uptime':115,'capabilities':['reboot']},headers=h)
        self.assertIsNone(report.json['command'])
        self.assertEqual(self.admin.get('/api/servers').json[0]['last_command']['status'],'cancelled')

    def test_admin_entry_role_separation_and_change(self):
        c=server.app.test_client()
        self.assertEqual(c.post('/api/login',json={'username':'admin','password':'correct-password-123'}).status_code,401)
        self.assertEqual(c.post('/api/login',json={'username':'alice','password':'correct-password-123'},headers={'X-Panel-Entry':'/admin'}).status_code,401)
        self.assertEqual(self.alice.get('/api/settings').status_code,403)
        with self.admin.get('/admin') as response:self.assertEqual(response.status_code,200)
        self.assertEqual(self.admin.patch('/api/settings',json={'admin_path':'/api/hidden'},headers={'X-CSRF-Token':self.tokens['admin']}).status_code,400)
        r=self.admin.patch('/api/settings',json={'admin_path':'/secure/panel-123'},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(r.status_code,200)
        self.assertEqual(c.get('/admin').status_code,404)
        with c.get('/secure/panel-123') as response:self.assertEqual(response.status_code,200)
        self.assertEqual(self.admin.get('/api/me').status_code,404)
        self.admin.environ_base['HTTP_X_PANEL_ENTRY']='/secure/panel-123'
        self.assertEqual(self.admin.get('/api/me').status_code,401)
        self.assertEqual(self.admin.post('/api/login',json={'username':'admin','password':'correct-password-123'}).status_code,200)
        self.assertEqual(self.admin.get('/api/me').status_code,200)
        self.assertEqual(self.alice.get('/api/me').status_code,200)
        self.assertEqual(c.get('/api/entry').json,{'kind':'client'})

    def test_reboot_expired_and_late_ack_revocation(self):
        from unittest.mock import patch
        r=self.post('/api/servers',{'name':'expire-test'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']};base=int(time.time())
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.admin.post('/api/agent/report',json={'uptime':100,'capabilities':['reboot']},headers=h)
        job=self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers={'X-CSRF-Token':self.tokens['alice']}).json
        with patch('server.time.time',return_value=base+125):
            result=self.admin.post('/api/agent/report',json={'uptime':225,'capabilities':['reboot']},headers=h)
            self.assertIsNone(result.json['command'])
        # Fresh task issued, but revoked before the agent acknowledges.
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(base,sid))
        job=self.alice.post(f'/api/servers/{sid}/reboot',json={'confirm':True},headers={'X-CSRF-Token':self.tokens['alice']}).json
        self.admin.post('/api/agent/report',json={'uptime':230,'capabilities':['reboot']},headers=h)
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':None},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(self.admin.post('/api/agent/commands/'+str(job['id'])+'/ack',json={},headers=h).status_code,403)

    def test_complete_ip_history_pagination_and_ownership(self):
        r=self.post('/api/servers',{'name':'cmhk-node'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        # More than the previous 1000-entry cap must survive a new report.
        with server.connect() as db:
            for i in range(1005):db.execute('INSERT INTO ip_events(server_id,addresses,observed) VALUES(?,?,?)',(sid,json.dumps(['8.8.8.8' if i%2 else '1.1.1.1']),1000+i))
        self.admin.post('/api/agent/report',json={'uptime':10,'public_ips':['9.9.9.9']},headers=h)
        first=self.alice.get(f'/api/servers/{sid}/ip-history').json
        self.assertEqual(first['total'],1006);self.assertEqual(len(first['events']),50);self.assertTrue(first['has_more'])
        self.assertEqual(first['events'][0]['addresses'],['9.9.9.9'])
        self.assertEqual(first['events'][0]['previous_addresses'],['1.1.1.1'])
        seen=[];cursor=None
        while True:
            page=self.alice.get(f'/api/servers/{sid}/ip-history'+(f'?before={cursor}' if cursor else '')).json
            seen.extend(e['id'] for e in page['events'])
            if not page['has_more']:break
            cursor=page['next_cursor']
        self.assertEqual(len(seen),1006);self.assertEqual(len(set(seen)),1006)
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/ip-history?before='+str(first['next_cursor'])).status_code,404)
        self.assertEqual(self.alice.get(f'/api/servers/{sid}/ip-history?before=invalid').status_code,400)

    def test_metric_history_scope_values_and_validation(self):
        r=self.post('/api/servers',{'name':'metric-node'}).json;sid=r['id'];h={'Authorization':'Bearer '+r['token']}
        uid=self.alice.get('/api/me').json['id']
        self.admin.patch(f'/api/servers/{sid}',json={'owner_id':uid},headers={'X-CSRF-Token':self.tokens['admin']})
        self.assertEqual(self.admin.post('/api/agent/report',json={'cpu_percent':25,'memory_percent':60,'tcp':1234,'udp':20},headers=h).status_code,200)
        data=self.alice.get(f'/api/servers/{sid}/metrics').json
        self.assertEqual(data['current']['tcp'],1234)
        self.assertEqual(data['points'][-1]['cpu'],25)
        self.assertEqual(data['points'][-1]['memory'],60)
        self.assertEqual(data['points'][-1]['udp'],20)
        self.assertEqual(self.bob.get(f'/api/servers/{sid}/metrics').status_code,404)
        self.assertEqual(self.alice.get(f'/api/servers/{sid}/metrics?range=invalid').status_code,400)
        self.assertEqual(self.alice.get(f'/api/servers/{sid}/metrics?range=24h').status_code,200)
        with server.connect() as db:db.execute('UPDATE servers SET seen=? WHERE id=?',(int(time.time())-100,sid))
        offline=self.alice.get(f'/api/servers/{sid}/metrics').json
        self.assertFalse(offline['online']);self.assertEqual(offline['current'],{})
        self.assertTrue(offline['points'])

class NetworkDeltaTest(unittest.TestCase):
    def test_midnight_reset_and_missing(self):
        import sqlite3,datetime
        from network import record_network,TZ
        db=sqlite3.connect(':memory:')
        db.executescript('CREATE TABLE metric_points(server_id INTEGER,stamp INTEGER,cpu REAL,memory REAL,tcp REAL,udp REAL,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));CREATE TABLE traffic_daily(server_id INTEGER,day TEXT,rx INTEGER,tx INTEGER,PRIMARY KEY(server_id,day));CREATE TABLE network_points(server_id INTEGER,stamp INTEGER,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));')
        start=int(datetime.datetime(2026,10,22,23,59,50,tzinfo=TZ).timestamp())
        old={'rx_bytes':1000,'tx_bytes':2000,'uptime':100}
        row={'id':1,'seen':start,'metrics':json.dumps(old)}
        m={'rx_bytes':3000,'tx_bytes':6000,'uptime':120}
        record_network(db,row,m,start+20)
        self.assertEqual(m['rx_bps'],800)
        rows=db.execute('SELECT day,rx,tx FROM traffic_daily ORDER BY day').fetchall()
        self.assertEqual(rows,[('2026-10-22',1000,2000),('2026-10-23',1000,2000)])
        reset={'rx_bytes':100,'tx_bytes':200,'uptime':1}
        record_network(db,{'id':1,'seen':start+20,'metrics':json.dumps(m)},reset,start+35)
        self.assertIsNone(reset['rx_bps'])
        self.assertEqual(db.execute('SELECT SUM(rx) FROM traffic_daily').fetchone()[0],2000)
        # Long reporting gaps count observed monotonic traffic but not real-time rate.
        later={'rx_bytes':1100,'tx_bytes':2200,'uptime':121}
        record_network(db,{'id':1,'seen':start+35,'metrics':json.dumps(reset)},later,start+155)
        self.assertIsNone(later['rx_bps'])
        self.assertEqual(db.execute('SELECT SUM(rx) FROM traffic_daily').fetchone()[0],3000)
        first={'rx_bytes':999999,'tx_bytes':999999,'uptime':12}
        record_network(db,{'id':2,'seen':None,'metrics':None},first,start)
        self.assertIsNone(first['rx_bps'])
        db.close()

if __name__=='__main__':unittest.main()


