"""Counter deltas, traffic buckets and sampled bandwidth (host perspective)."""
import datetime, json, time
TZ=datetime.timezone(datetime.timedelta(hours=8))

def day_key(stamp):return datetime.datetime.fromtimestamp(stamp,TZ).date().isoformat()

def traffic_summary(db,sid,now=None):
    day=day_key(time.time() if now is None else now);month=day[:7]
    today=db.execute('SELECT rx,tx FROM traffic_daily WHERE server_id=? AND day=?',(sid,day)).fetchone()
    rows=db.execute('SELECT SUM(rx),SUM(tx),COUNT(*) FROM traffic_daily WHERE server_id=? AND day LIKE ?',(sid,month+'-%')).fetchone()
    return {'today_rx':today[0] if today else None,'today_tx':today[1] if today else None,
            'month_rx':rows[0] if rows[2] else None,'month_tx':rows[1] if rows[2] else None,'timezone':'Asia/Shanghai'}

def record_network(db,row,metrics,now):
    old=json.loads(row['metrics']) if row['metrics'] else {};dt=now-(row['seen'] or now)
    metrics['rx_bps']=metrics['tx_bps']=None
    valid=dt>0 and row['seen'] and all(type(v) in (int,float) for v in [old.get('rx_bytes'),old.get('tx_bytes'),old.get('uptime'),metrics.get('rx_bytes'),metrics.get('tx_bytes'),metrics.get('uptime')])
    if valid:
        # Reboot/counter reset/interface disappearance: establish a new baseline.
        valid=metrics['uptime']>=old['uptime'] and metrics['rx_bytes']>=old['rx_bytes'] and metrics['tx_bytes']>=old['tx_bytes']
        # Detect reboot even if the new uptime happens to exceed the old uptime.
        valid=valid and abs((metrics['uptime']-old['uptime'])-dt)<=max(10,dt*.05)
    if valid:
        rx=int(metrics['rx_bytes']-old['rx_bytes']);tx=int(metrics['tx_bytes']-old['tx_bytes'])
        if dt<=60:
            metrics['rx_bps']=rx*8/dt;metrics['tx_bps']=tx*8/dt
        # Split a delta across local midnight proportionally. These are monitoring
        # estimates, not provider billing; exact intra-gap timing isn't available.
        start=row['seen'];end=now;allocated_rx=allocated_tx=0
        while start<end:
            local=datetime.datetime.fromtimestamp(start,TZ)
            boundary=int(datetime.datetime.combine(local.date()+datetime.timedelta(days=1),datetime.time(),TZ).timestamp())
            stop=min(end,boundary)
            part_rx=rx-allocated_rx if stop==end else int(rx*(stop-start)/dt)
            part_tx=tx-allocated_tx if stop==end else int(tx*(stop-start)/dt)
            db.execute('INSERT INTO traffic_daily(server_id,day,rx,tx) VALUES(?,?,?,?) ON CONFLICT(server_id,day) DO UPDATE SET rx=rx+excluded.rx,tx=tx+excluded.tx',
                       (row['id'],day_key(start),part_rx,part_tx))
            allocated_rx+=part_rx;allocated_tx+=part_tx;start=stop
    # Keep current counters and traffic fresh on every report, but sample history
    # at most once per 15 seconds. Indexed lookup; old agents remain compatible.
    last=db.execute('SELECT stamp FROM metric_points WHERE server_id=? ORDER BY stamp DESC LIMIT 1',(row['id'],)).fetchone()
    if last is None or now-last[0]>=15:
        db.execute('INSERT OR REPLACE INTO network_points(server_id,stamp,rx_bps,tx_bps) VALUES(?,?,?,?)',(row['id'],now,metrics['rx_bps'],metrics['tx_bps']))
        db.execute('INSERT OR REPLACE INTO metric_points(server_id,stamp,cpu,memory,tcp,udp,rx_bps,tx_bps) VALUES(?,?,?,?,?,?,?,?)',
                   (row['id'],now,metrics.get('cpu_percent'),metrics.get('memory_percent'),metrics.get('tcp'),metrics.get('udp'),metrics['rx_bps'],metrics['tx_bps']))
        db.execute('DELETE FROM metric_points WHERE server_id=? AND stamp<?',(row['id'],now-7*86400))
        # Only prune the reporting node; bounded indexed deletes instead of full scans.
        db.execute('DELETE FROM network_points WHERE server_id=? AND stamp<?',(row['id'],now-7*86400))
        db.execute('DELETE FROM traffic_daily WHERE server_id=? AND day<?',(row['id'],day_key(now-400*86400)))
    return metrics
