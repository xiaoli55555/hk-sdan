import unittest, tempfile, os, json, time, importlib.util
os.environ['DATA_DIR']=tempfile.mkdtemp(prefix='hksdan-test-')
os.environ['COOKIE_SECURE']='0'
import server
from werkzeug.security import generate_password_hash

class PanelTest(unittest.TestCase):
    def setUp(self):
        with server.connect() as db:
            for table in ['sessions','servers','audit','attempts','users']:db.execute('DELETE FROM '+table)
            for name,role in [('admin','admin'),('alice','client'),('bob','client')]:
                db.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)',(name,generate_password_hash('correct-password-123'),role))
        self.admin,self.alice,self.bob=[server.app.test_client() for _ in range(3)]
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
if __name__=='__main__':unittest.main()
