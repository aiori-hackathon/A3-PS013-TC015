from __future__ import annotations
import csv, io, json, re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

AUTH = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+(.+)$')
APACHE = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)')
MONTHS = {m:i for i,m in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'),1)}

def detect_format(filename: str, text: str) -> str:
    first = next((x for x in text.splitlines() if x.strip()), '')
    low = filename.lower()
    if low.endswith('.csv') or re.search(r'(^|,)\s*(timestamp|time|datetime|@timestamp)\s*,', first, re.I): return 'csv'
    if first.lstrip().startswith('{'): return 'jsonl'
    if APACHE.match(first): return 'apache'
    if 'sshd[' in first or 'sudo[' in first or 'auth.log' in low: return 'auth'
    if re.match(r'^\d{4}-\d\d-\d\dT', first) and re.search(r'action=|\b(?:ALLOW|DENY|DROP|BLOCK)\b|SRC=', first, re.I): return 'firewall'
    return 'text'

def _utc(value: str, timezone_name: str, correction: int) -> datetime:
    raw = value.strip()
    try: dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError as exc: raise ValueError('Timestamp is missing or invalid') from exc
    if dt.tzinfo is None:
        try: dt = dt.replace(tzinfo=ZoneInfo(timezone_name or 'UTC'))
        except ZoneInfoNotFoundError as exc: raise ValueError('Unknown source timezone') from exc
    return dt.astimezone(timezone.utc).replace(tzinfo=None) - __import__('datetime').timedelta(minutes=correction)

def _severity(text: str) -> str:
    low = text.lower()
    if re.search(r'accepted (password|publickey)|sudo|/admin|/export|sql(\s|%20)*(union|select)|firewall allow', low): return 'high'
    if re.search(r'failed password|401|403|400|\.\./|firewall (deny|drop|block)', low): return 'medium'
    return 'info'

def _event(data: dict, original: str, tz: str, correction: int) -> dict:
    stamp = next((data.get(k) for k in ('timestamp','time','datetime','@timestamp','date') if data.get(k)), None)
    if not stamp: raise ValueError('Timestamp is missing')
    ts = _utc(str(stamp), tz, correction)
    desc = str(data.get('event') or data.get('message') or data.get('action') or data.get('request') or original)
    details = ' '.join(str(data.get(k,'')) for k in ('level','user','username','source_ip','client_ip','src_ip','status') if data.get(k))
    full = f'{desc} {details}'.strip()
    return {'timestamp_utc':ts,'original_timestamp':str(stamp),'host':str(data.get('host') or data.get('hostname') or data.get('service') or 'unknown'),
            'source_ip':data.get('source_ip') or data.get('client_ip') or data.get('src_ip') or data.get('src'),
            'username':data.get('user') or data.get('username'),'event_type':str(data.get('event_type') or data.get('type') or data.get('event') or data.get('action') or data.get('level') or 'event'),
            'severity':_severity(full),'description':full,'normalized':data}

def parse_line(line: str, fmt: str, timezone_name: str='UTC', correction: int=0, year: int|None=None) -> dict:
    if fmt == 'csv': raise ValueError('CSV row requires its header mapping')
    if fmt in ('json','jsonl'):
        try: data=json.loads(line)
        except json.JSONDecodeError as exc: raise ValueError(f'Invalid JSON: {exc.msg}') from exc
        if not isinstance(data,dict): raise ValueError('JSON record must be an object')
        return _event(data,line,timezone_name,correction)
    if fmt == 'auth':
        m=AUTH.match(line)
        if not m: raise ValueError('Record does not match supported Linux auth format')
        mon,day,clock,host,message=m.groups(); yr=year or datetime.now(timezone.utc).year
        if mon not in MONTHS: raise ValueError('Authentication timestamp has an unknown month')
        stamp=f'{yr:04}-{MONTHS[mon]:02}-{int(day):02}T{clock}'
        kind='authentication_failure' if 'failed password' in message.lower() else 'authentication_success' if 'accepted ' in message.lower() else 'privilege_escalation' if 'sudo' in message.lower() else 'authentication_event'
        data={'timestamp':stamp,'host':host,'event':message,'event_type':kind}
        user=re.search(r'for\s+(?:invalid user\s+)?([A-Za-z0-9_.-]+)',message) or re.match(r'([A-Za-z0-9_.-]+)\s*:',message)
        ip=re.search(r'\bfrom\s+([0-9a-fA-F:.]+)',message)
        if user: data['user']=user.group(1)
        if ip: data['source_ip']=ip.group(1)
        result=_event(data,line,timezone_name,correction); result['original_timestamp']=stamp; return result
    if fmt == 'apache':
        m=APACHE.match(line)
        if not m: raise ValueError('Record does not match supported Apache/Nginx access format')
        ip,stamp,request,status,size=m.groups()
        try: dt=datetime.strptime(stamp,'%d/%b/%Y:%H:%M:%S %z')
        except ValueError as exc: raise ValueError('Apache timestamp is invalid') from exc
        data={'timestamp':dt.isoformat(),'source_ip':ip,'request':request,'status':status,'bytes':size,'event_type':'http_request'}
        result=_event(data,line,timezone_name,correction); result['description']=f'{request} HTTP {status} ({size} bytes)'; result['severity']=_severity(result['description']); return result
    if fmt == 'firewall':
        m=re.match(r'^(\S+)\s+(\S+)\s+(.*)$',line)
        if not m: raise ValueError('Record does not match supported firewall format')
        stamp,host,rest=m.groups(); data={k.lower():v for k,v in re.findall(r'([A-Za-z_]+)=([^\s]+)',rest)}
        data.update({'timestamp':stamp,'host':host,'event':f"Firewall {data.get('action','event')}"});data['source_ip']=data.get('src') or data.get('source_ip');data['event_type']='firewall'
        return _event(data,line,timezone_name,correction)
    # Generic plain text supports ISO timestamp followed by a message.
    m=re.match(r'^(\d{4}-\d\d-\d\d(?:T|\s)\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)\s+(.+)$',line)
    if not m: raise ValueError('Timestamp is missing or plain-text record is unsupported')
    result=_event({'timestamp':m.group(1),'event':m.group(2)},line,timezone_name,correction);return result

def records_for(text: str, fmt: str, timezone_name: str='UTC', correction: int=0) -> list[tuple[int,str,str,dict|None,str|None]]:
    lines=text.splitlines()
    if fmt!='csv':
        out=[]
        for n,line in enumerate(lines,1):
            if not line.strip(): continue
            try: out.append((n,line,'parsed',parse_line(line,fmt,timezone_name,correction),None))
            except ValueError as exc: out.append((n,line,'gap',None,str(exc)))
        return out
    if not lines: return []
    try: headers=next(csv.reader([lines[0]],strict=True))
    except (csv.Error,StopIteration) as exc: return [(1,lines[0],'gap',None,f'Invalid CSV header: {exc}')]
    header=[h.strip().lower() for h in headers]
    if not any(h in header for h in ('timestamp','time','datetime','@timestamp','date')):
        return [(1,lines[0],'gap',None,'CSV header needs a timestamp/time/datetime column')]
    rows=[(1,lines[0],'metadata',None,None)]
    for line_num,raw in enumerate(lines[1:],2):
        if not raw.strip(): continue
        try: cells=next(csv.reader([raw],strict=True))
        except (csv.Error,StopIteration) as exc: rows.append((line_num,raw,'gap',None,f'Invalid CSV row: {exc}'));continue
        if len(cells)!=len(header): rows.append((line_num,raw,'gap',None,'CSV field count does not match its header'));continue
        data={k:v.strip() for k,v in zip(header,cells)}
        try: rows.append((line_num,raw,'parsed',_event(data,raw,timezone_name,correction),None))
        except ValueError as exc: rows.append((line_num,raw,'gap',None,str(exc)))
    return rows
