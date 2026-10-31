from __future__ import annotations
import json, random
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

CATALOG={
 'ssh-bruteforce':('SSH brute-force attack','Credential-guessing activity followed by a successful login and privileged command.'),
 'web-application':('Web application attack','Traversal and SQL-injection-like probes followed by authentication and export activity.'),
 'network-activity':('Suspicious network activity','Denied connection attempts and related host/network observations.')}

def generate_scenario(scenario_id: str, seed: int=13013) -> dict:
    if scenario_id not in CATALOG: raise KeyError(scenario_id)
    rng=random.Random(seed); name,description=CATALOG[scenario_id]
    base=datetime(2026,10,22,12,0,tzinfo=timezone.utc); ip=rng.choice(['203.0.113.42','198.51.100.77','192.0.2.55']); user=rng.choice(['analyst','deploy','ops'])
    files=[]
    def add(filename,fmt,tz,skew,text): files.append({'filename':filename,'format':fmt,'source_timezone':tz,'clock_offset_minutes':skew,'text':text,'origin':'SYNTHETIC'})
    if scenario_id=='ssh-bruteforce':
        events=[]
        for i in range(5):
            t=base+timedelta(minutes=i*2);wall=t.astimezone(ZoneInfo('America/New_York')).strftime('%b %d %H:%M:%S')
            events.append(f'{wall} srv-01 sshd[{2200+i}]: Failed password for {user} from {ip} port {51000+i} ssh2 [SYNTHETIC]')
        t=base+timedelta(minutes=14);events.append(f'{t.astimezone(ZoneInfo("America/New_York")).strftime("%b %d %H:%M:%S")} srv-01 sshd[2300]: Accepted password for {user} from {ip} port 51010 ssh2 [SYNTHETIC]')
        events.append('NOT_A_VALID_AUTH_RECORD -- SYNTHETIC PARSING GAP')
        events.append('Oct 22 12:44:00 srv-01 sshd[2399]: Failed password with no source timestamp -- SYNTHETIC')
        add('host-auth.log','auth','America/New_York',2,'\n'.join(events)+'\n')
        add('gateway.csv','csv','UTC',0,'timestamp,event,user,source_ip,level,host\n'+f'{base.isoformat()},SYNTHETIC firewall allow, {user},{ip},INFO,edge-01\n'+f'{(base+timedelta(minutes=15)).isoformat()},SYNTHETIC SSH session correlated,{user},{ip},WARN,edge-01\n'+'not-a-time,missing-time example,ops,203.0.113.8,INFO,edge-01\n')
        add('application.jsonl','jsonl','UTC',0,'\n'.join(json.dumps({'timestamp':(base+timedelta(minutes=m)).isoformat(),'host':'app-01','level':'WARN','event':'SYNTHETIC privileged command observed','user':user,'source_ip':ip,'synthetic':True}) for m in (17,18))+'\n')
    elif scenario_id=='web-application':
        web=[]
        for i,path in enumerate(['/','/../../etc/passwd',"/search?q=%27%20UNION%20SELECT%20password",'/login','/admin/export']):
            stamp=(base+timedelta(minutes=i*3)).strftime('%d/%b/%Y:%H:%M:%S +0000');status=[200,400,403,401,200][i]
            web.append(f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} {900+i} "-" "SYNTHETIC TracepointDemo/1.0"')
        web.append('NOT_A_WEB_ACCESS_LINE -- SYNTHETIC GAP')
        add('web-access.log','apache','UTC',0,'\n'.join(web)+'\n')
        add('application.jsonl','jsonl','Asia/Kolkata',-4,'\n'.join(json.dumps({'timestamp':(base+timedelta(minutes=m)).astimezone(ZoneInfo('Asia/Kolkata')).isoformat(),'host':'webapp-01','level':'WARN' if m<12 else 'ERROR','event':ev,'username':user,'client_ip':ip,'synthetic':True}) for m,ev in [(6,'SYNTHETIC authentication failed'),(9,'SYNTHETIC authentication failed'),(12,'SYNTHETIC login accepted'),(15,'SYNTHETIC export requested')])+'\n'+'{"timestamp":"not-a-time","event":"SYNTHETIC missing timestamp"}\n')
        add('auth.csv','csv','UTC',1,'timestamp,event,user,source_ip,host\n'+f'{(base+timedelta(minutes=13)).isoformat()},SYNTHETIC accepted publickey,{user},{ip},web-01\n')
    else:
        rows=[]
        for i,action in enumerate(['DENY','DENY','DROP','ALLOW']):
            t=base+timedelta(minutes=i*5);rows.append(f'{t.isoformat()} edge-fw-01 action={action} src={ip} dst=10.0.0.{20+i} proto=TCP dport={22 if i<3 else 443} reason=SYNTHETIC-policy')
        rows.append('broken firewall timestamp edge-fw action=DENY src=203.0.113.9 -- SYNTHETIC GAP')
        add('firewall.log','firewall','UTC',3,'\n'.join(rows)+'\n')
        add('host-auth.jsonl','jsonl','UTC',0,'\n'.join(json.dumps({'timestamp':(base+timedelta(minutes=m)).isoformat(),'host':'node-02','level':'WARN','event':event,'user':user,'source_ip':ip,'synthetic':True}) for m,event in [(8,'SYNTHETIC unusual outbound connection attempt'),(13,'SYNTHETIC host firewall policy alert')])+'\n')
        add('network.csv','csv','Europe/London',-2,'timestamp,event,source_ip,host\n'+f'{base.astimezone(ZoneInfo("Europe/London")).isoformat()},SYNTHETIC repeated denied outbound connection,{ip},sensor-01\n'+'bad-time,SYNTHETIC absent timestamp,203.0.113.9,sensor-01\n')
    return {'scenario_id':scenario_id,'name':name,'description':description,'seed':seed,'label':'SYNTHETIC DATA — NOT A REAL INCIDENT','generated_at':datetime.now(timezone.utc).isoformat(),'files':files,
            'metadata':{'source_ip':ip,'username':user,'clock_skew_included':True,'timezone_variation_included':True,'malformed_or_missing_timestamps_included':True}}
