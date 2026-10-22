import unittest, importlib.util, sqlite3, json
from pathlib import Path
from unittest.mock import patch, MagicMock
from network import record_network
spec=importlib.util.spec_from_file_location('collector',Path(__file__).parents[1]/'agent/agent.py')
collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)

class CadenceTest(unittest.TestCase):
    def test_connections_are_cached_for_fifteen_seconds(self):
        sampler=collector.ConnectionSampler()
        with patch.object(collector,'tcp_count',return_value=12) as tcp,patch.object(collector,'udp_count',return_value=(3,'')) as udp:
            for stamp in (0,5,10,14):self.assertEqual(sampler.sample(lambda:stamp),(12,3,''))
            self.assertEqual(tcp.call_count,1);self.assertEqual(udp.call_count,1)
            sampler.sample(lambda:15);self.assertEqual(tcp.call_count,2)
    def test_history_is_limited_but_all_traffic_is_counted(self):
        db=sqlite3.connect(':memory:')
        db.executescript('CREATE TABLE metric_points(server_id INTEGER,stamp INTEGER,cpu REAL,memory REAL,tcp REAL,udp REAL,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));CREATE TABLE traffic_daily(server_id INTEGER,day TEXT,rx INTEGER,tx INTEGER,PRIMARY KEY(server_id,day));CREATE TABLE network_points(server_id INTEGER,stamp INTEGER,rx_bps REAL,tx_bps REAL,PRIMARY KEY(server_id,stamp));')
        row={'id':1,'seen':None,'metrics':None}
        for stamp in (100,105,110,115,120):
            m={'rx_bytes':stamp*100,'tx_bytes':stamp*200,'uptime':stamp,'cpu_percent':20}
            record_network(db,row,m,stamp);row={'id':1,'seen':stamp,'metrics':json.dumps(m)}
        self.assertEqual(db.execute('SELECT COUNT(*) FROM metric_points').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM network_points').fetchone()[0],2)
        self.assertEqual(db.execute('SELECT SUM(rx),SUM(tx) FROM traffic_daily').fetchone(),(2000,4000))
        self.assertEqual(m['rx_bps'],800)
    def test_egress_probe_is_bounded_and_rejects_private_results(self):
        sampler=collector.EgressSampler();response=MagicMock();response.__enter__.return_value.read.return_value=b'127.0.0.1'
        opener=MagicMock();opener.open.return_value=response
        with patch.object(collector.urllib.request,'build_opener',return_value=opener),patch.object(collector.time,'sleep',side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):sampler.run()
        self.assertIsNone(sampler.snapshot()['egress_ips']);self.assertTrue(sampler.snapshot()['egress_error'])
        self.assertEqual(opener.open.call_count,2)
        self.assertEqual(opener.open.call_args.kwargs['timeout'],3)
