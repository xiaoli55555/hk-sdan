#!/usr/bin/env python3
"""Read-only Debian host collector. No shell commands or remote execution."""
import json, os, time, socket, platform, shutil, subprocess, urllib.request, urllib.error, argparse, ipaddress
from pathlib import Path

def tcp_count(root=Path('/proc')):
    count=0; found=False
    for name in ('tcp','tcp6'):
        p=root/'net'/name
        if not p.exists():continue
        found=True
        for line in p.read_text().splitlines()[1:]:
            cols=line.split()
            if len(cols)>3 and cols[3]=='01':count+=1
    return count if found else None

def udp_count():
    # conntrack counts UDP flows rather than listening UDP sockets.
    # Each original/reply pair is one entry, not two sessions.
    if not shutil.which('conntrack'):return None,'未安装 conntrack，UDP 会话数不可用'
    try:
        r=subprocess.run(['conntrack','-L','-p','udp','-o','extended'],capture_output=True,text=True,timeout=5,check=False)
        if r.returncode:return None,'conntrack 不可用（权限或内核不支持）'
        return sum(1 for line in r.stdout.splitlines() if ' udp ' in ' '+line+' '),' '
    except (OSError,subprocess.TimeoutExpired):return None,'conntrack 采集超时或失败'

def public_addresses():
    try:
        result=subprocess.run(['ip','-j','address','show','scope','global'],capture_output=True,text=True,timeout=5,check=True)
        addresses=set()
        for interface in json.loads(result.stdout):
            for info in interface.get('addr_info',[]):
                address=ipaddress.ip_address(info.get('local',''))
                if address.is_global:addresses.add(str(address))
        return sorted(addresses),''
    except (OSError,ValueError,subprocess.SubprocessError):return None,'网卡公网 IP 采集失败'

def cpu_snapshot():
    v=[int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    return sum(v),v[3]+v[4]

def collect(previous=None):
    now=cpu_snapshot();cpu=None
    if previous and now[0]>previous[0]:cpu=round(100*(1-(now[1]-previous[1])/(now[0]-previous[0])),1)
    mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if len(line.split())>=2}
    disk=shutil.disk_usage('/');rx=tx=0
    for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
        iface,fields=line.split(':',1)
        if iface.strip()=='lo':continue
        values=fields.split();rx+=int(values[0]);tx+=int(values[8])
    udp,err=udp_count()
    addresses,ip_error=public_addresses()
    try:tcp=tcp_count()
    except OSError:tcp=None;err+=' TCP 采集失败'
    os_name=platform.system()
    try:
        for line in Path('/etc/os-release').read_text().splitlines():
            if line.startswith('PRETTY_NAME='):os_name=line.split('=',1)[1].strip('"')
    except OSError:pass
    return {'cpu_percent':cpu,'memory_percent':round(100*(1-mem.get('MemAvailable',mem.get('MemFree',0))/mem['MemTotal']),1),
            'memory_total':mem['MemTotal'],'disk_percent':round(100*disk.used/disk.total,1),'disk_total':disk.total,
            'uptime':int(float(Path('/proc/uptime').read_text().split()[0])), 'rx_bytes':rx,'tx_bytes':tx,
            'capabilities':['reboot'],'tcp':tcp,'udp':udp,'public_ips':addresses,'ip_error':ip_error,'network_error':err.strip(),'hostname':socket.gethostname(),'os':os_name,'kernel':platform.release()},now

def main():
    p=argparse.ArgumentParser();p.add_argument('--once',action='store_true');p.add_argument('--config',default='/etc/hk-sdan-agent/config.json');a=p.parse_args()
    config=json.loads(Path(a.config).read_text());url=config['url'].rstrip('/')
    if not url.startswith('https://'):raise SystemExit('只支持 HTTPS 面板地址')
    previous=None
    while True:
        try:
            metrics,previous=collect(previous)
            req=urllib.request.Request(url+'/api/agent/report',data=json.dumps(metrics).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+config['token']},method='POST')
            # Never follow redirects with the agent credential.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args,**kwargs):return None
            opener=urllib.request.build_opener(NoRedirect)
            with opener.open(req,timeout=15) as response:result=json.loads(response.read(32768))
            command=result.get('command')
            if isinstance(command,dict) and command.get('action')=='reboot' and type(command.get('id')) is int:
                command_url=url+'/api/agent/commands/'+str(command['id'])+'/ack'
                headers={'Content-Type':'application/json','Authorization':'Bearer '+config['token']}
                ack=urllib.request.Request(command_url,data=b'{}',headers=headers,method='POST')
                # Only act after the server accepts this one-time acknowledgement.
                with opener.open(ack,timeout=15) as response:response.read(1024)
                try:
                    subprocess.run(['/usr/bin/systemctl','reboot','--no-block'],check=True,timeout=15,capture_output=True)
                    print('重启请求已交给系统管理器',flush=True)
                except (OSError,subprocess.SubprocessError):
                    print('系统重启请求失败',flush=True)
                    failure=urllib.request.Request(command_url,data=b'{"status":"failed"}',headers=headers,method='POST')
                    with opener.open(failure,timeout=15) as response:response.read(1024)
            print('上报成功',flush=True)
        except Exception as e:
            # Avoid including URL, request headers or token in logs.
            print('采集或上报失败：'+type(e).__name__,flush=True)
        if a.once:break
        time.sleep(15)
if __name__=='__main__':main()
