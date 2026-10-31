import hashlib, io, json, os, shutil, tempfile, zipfile, sys
from pathlib import Path
from fastapi.testclient import TestClient

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
DATA=Path(__file__).resolve().parent/'runtime-data'
shutil.rmtree(DATA,ignore_errors=True)
DATA.mkdir(parents=True,exist_ok=True)
os.environ['TRACEPOINT_DATA_DIR']=str(DATA)
from app.main import app
from app.synthetic import generate_scenario
from app.database import Base, engine
from app.models import Evidence, NormalizedEvent
from app.database import SessionLocal
from sqlalchemy import select, inspect

client=TestClient(app)

def upload(name,text,fmt='auto',tz='UTC',skew=0,synthetic=False):
    return client.post('/api/evidence',files={'file':(name,text.encode('utf-8'),'text/plain')},data={'format':fmt,'source_timezone':tz,'clock_offset_minutes':str(skew),'synthetic':str(synthetic).lower()})

def test_database_creation_and_status():
    with client:
        r=client.get('/api/status');assert r.status_code==200 and r.json()['database']=='sqlite'
        tables=set(inspect(engine).get_table_names());assert {'evidence','original_log_records','normalized_events','investigations','investigation_events','anomalies','data_sources','audit_records','synthetic_scenarios','investigation_evidence'}<=tables
        assert client.get('/').status_code==200 and client.get('/app.js').status_code==200
        assert {'evidence','events','gaps','investigations','anomalies'} <= r.json()['counts'].keys()

def test_upload_preserves_bytes_hash_verification_and_deduplication():
    raw='timestamp,event,user,source_ip\n2026-10-22T12:00:00Z,login failed,ops,203.0.113.5\n'
    first=upload('auth.csv',raw)
    assert first.status_code==200,first.text
    obj=first.json()['evidence'];eid=obj['id'];assert obj['sha256']==hashlib.sha256(raw.encode()).hexdigest();assert obj['file_size_bytes']==len(raw.encode())
    download=client.get(f'/api/evidence/{eid}/download');assert download.content==raw.encode()
    assert client.get(f'/api/evidence/{eid}/verify').json()['status']=='pass'
    again=upload('copy.csv',raw);assert again.json()['duplicate'] is True;assert again.json()['evidence']['id']!=eid;assert again.json()['evidence']['duplicate_of_id']==eid;assert len(client.get('/api/evidence').json())==2
    stored=DATA/'evidence'/(eid+'.evidence');stored.write_bytes(b'changed bytes')
    assert client.get(f'/api/evidence/{eid}/verify').json()['status']=='fail'

def test_database_persistence_and_foreign_keys():
    r=upload('persist.txt','2026-10-22T12:01:00Z persisted event','text');eid=r.json()['evidence']['id']
    engine.dispose()
    with SessionLocal() as db: assert db.get(Evidence,eid) is not None
    with engine.connect() as con: assert con.exec_driver_sql('PRAGMA foreign_keys').scalar()==1

def test_duplicate_records_are_preserved_and_flagged():
    line='2026-10-22T12:01:00Z repeated event'
    r=upload('duplicate.log',line+'\n'+line+'\n','text');eid=r.json()['evidence']['id']
    rows=client.get('/api/events?evidence_id='+eid).json();assert len(rows)==2 and rows[1]['duplicate_record'] is True
    assert any(a['rule_id']=='duplicate-record' for a in client.get('/api/anomalies?evidence_id='+eid).json())

def test_missing_timezone_is_explicit_and_naive_records_become_gaps():
    raw=b'2026-10-22T12:00:00Z embedded offset works\n2026-10-22T12:01:00Z naive-looking stamp is still UTC-aware\n'
    r=client.post('/api/evidence',files={'file':('times.log',raw,'text/plain')})
    assert r.status_code==200,r.text
    e=r.json()['evidence'];assert e['source_timezone']=='Unspecified'
    # Both timestamps above carry Z and remain normalizable without a source timezone.
    assert e['event_count']==2
    naive=client.post('/api/evidence',files={'file':('naive.log',b'2026-10-22T12:00:00 naive event\n','text/plain')})
    assert naive.status_code==200 and naive.json()['evidence']['parsing_gap_count']==1

def test_rejects_invalid_timezone_and_extreme_clock_offset():
    raw=b'2026-10-22T00:00:00Z event\n'
    bad=client.post('/api/evidence',files={'file':('zone.log',raw,'text/plain')},data={'source_timezone':'Not/AZone'})
    assert bad.status_code==400
    skew=client.post('/api/evidence',files={'file':('skew.log',raw,'text/plain')},data={'clock_offset_minutes':'50000','source_timezone':'UTC'})
    assert skew.status_code==400

def test_upload_size_and_extension_validation():
    too_large='x'*(25*1024*1024+1);r=upload('large.log',too_large,'text');assert r.status_code==413
    bad=client.post('/api/evidence',files={'file':('payload.exe',b'not executable','application/octet-stream')});assert bad.status_code==400

def test_path_traversal_name_is_stored_as_basename():
    r=upload('../outside.txt','2026-10-22T00:00:00Z safe line','text')
    assert r.status_code==200,r.text
    assert r.json()['evidence']['filename']=='outside.txt'
    assert not (DATA/'outside.txt').exists()

def test_csv_json_auth_apache_firewall_parsers_and_timestamp_correction():
    cases=[
      ('multi.csv','timestamp,event,user,source_ip\n2026-10-22T10:00:00Z,login,ada,203.0.113.3\n','auto','UTC',0),
      ('events.jsonl','{"timestamp":"2026-10-22T10:01:00Z","event":"failed login","user":"ada","source_ip":"203.0.113.3"}\n','auto','UTC',0),
      ('auth.log','Oct 22 10:02:00 host sshd[4]: Failed password for ada from 203.0.113.3 port 22 ssh2\n','auto','Asia/Kolkata',30),
      ('access.log','203.0.113.3 - - [22/Oct/2026:10:03:00 +0000] "GET / HTTP/1.1" 200 10\n','auto','UTC',0),
      ('firewall.log','2026-10-22T10:04:00Z edge action=DENY src=203.0.113.3 dst=10.0.0.1 dport=22\n','auto','UTC',0),
    ]
    ids=[]
    for n,txt,fmt,tz,skew in cases:
        r=upload(n,txt,fmt,tz,skew);assert r.status_code==200,r.text;ids.append(r.json()['evidence']['id'])
    rows=client.get('/api/events?source_ip=203.0.113.3&limit=1000').json();assert len(rows)>=5
    assert [x['timestamp_utc'] for x in rows]==sorted(x['timestamp_utc'] for x in rows)
    auth=next(x for x in rows if x['evidence_id']==ids[2]);assert auth['timestamp_utc'].startswith('2026-10-22T04:02:00')
    assert client.get('/api/events?username=ada').json()
    assert client.get('/api/events?event_type=http_request').json()

def test_plain_text_timestamp_with_space_and_invalid_auth_month():
    plain=upload('plain.txt','2026-10-22 10:30:00Z SYNTHETIC plain text record\n','text')
    assert plain.status_code==200 and plain.json()['evidence']['event_count']==1
    malformed=upload('bad-month.log','Xxx 22 10:30:00 host sshd[1]: Failed password for ops from 203.0.113.4 port 22 ssh2\n','auth')
    assert malformed.status_code==200 and malformed.json()['evidence']['parsing_gap_count']==1

def test_missing_invalid_and_malformed_records_remain_gaps():
    raw='{"timestamp":"not-time","event":"bad"}\nNOT_JSON\n{"event":"missing timestamp"}\n'
    r=upload('broken.jsonl',raw);assert r.status_code==200,r.text
    gaps=client.get('/api/gaps?evidence_id='+r.json()['evidence']['id']).json()
    assert len(gaps)==3 and all(g['original_text'] for g in gaps)

def test_investigation_association_report_and_persistence():
    e=upload('case.jsonl','{"timestamp":"2026-10-22T12:10:00Z","event":"failed password","user":"ops","source_ip":"203.0.113.19"}\n')
    eid=e.json()['evidence']['id'];event=client.get('/api/events?evidence_id='+eid).json()[0]
    inv=client.post('/api/investigations',json={'name':'Demo investigation','description':'Synthetic test','manual_baseline_minutes':12,'tool_assisted_minutes':4,'triage_answers':['confirmed with host log']});assert inv.status_code==201
    iid=inv.json()['id'];assert client.post(f'/api/investigations/{iid}/events',json={'ids':[event['id']]}).status_code==200
    data=client.get(f'/api/investigations/{iid}').json();assert data['event_ids']==[event['id']] and eid in data['evidence_ids']
    assert client.patch(f'/api/investigations/{iid}',json={'status':'in_progress','notes':'Reviewed'}).json()['status']=='in_progress'
    report=client.get(f'/api/investigations/{iid}/report?format=json').json();assert len(report['events'])==1
    assert report['triage']['time_saved_minutes']==8 and report['triage']['percentage_improvement']==66.7
    assert 'timestamp_utc' in client.get(f'/api/investigations/{iid}/report?format=csv').text
    assert any(a['action']=='investigation.create' for a in client.get('/api/audit').json())

def test_seeded_scenarios_are_reproducible_and_downloadable():
    for sid in ('ssh-bruteforce','web-application','network-activity'):
        a=client.post(f'/api/scenarios/{sid}/generate?seed=2026').json();b=client.post(f'/api/scenarios/{sid}/generate?seed=2026').json()
        assert a['files']==b['files'];assert a['label'].startswith('SYNTHETIC') and len(a['files'])>=2
        assert any(f['format']=='csv' for f in a['files'])
        assert client.get(f'/api/scenarios/{sid}/download?seed=2026').headers['content-type']=='application/zip'
        zipdata=zipfile.ZipFile(io.BytesIO(client.get(f'/api/scenarios/{sid}/download?seed=2026').content))
        assert any(n.endswith('METADATA.json') for n in zipdata.namelist())

def test_synthetic_and_uploaded_origins_do_not_dedupe_into_each_other():
    scenario=generate_scenario('ssh-bruteforce',611);item=scenario['files'][0]
    real=client.post('/api/evidence',files={'file':(item['filename'],item['text'].encode(),'text/plain')},data={'format':item['format'],'source_timezone':item['source_timezone'],'clock_offset_minutes':str(item['clock_offset_minutes'])})
    assert real.status_code==200 and real.json()['evidence']['synthetic'] is False
    imported=client.post('/api/scenarios/ssh-bruteforce/import?seed=611');assert imported.status_code==200
    digest=hashlib.sha256(item['text'].encode()).hexdigest()
    same=[x for x in client.get('/api/evidence').json() if x['sha256']==digest]
    assert len(same)==2 and {x['synthetic'] for x in same}=={False,True}

def test_import_all_scenarios_gaps_and_reset_keeps_uploaded_evidence():
    real=upload('real-evidence.log','2026-10-22T12:00:00Z normal record','text');real_id=real.json()['evidence']['id']
    total=0
    for sid in ('ssh-bruteforce','web-application','network-activity'):
        r=client.post(f'/api/scenarios/{sid}/import?seed=404');assert r.status_code==200,r.text;total+=len(r.json()['evidence'])
    assert total>=6
    synthetic=client.get('/api/evidence?synthetic=true').json();assert len(synthetic)>=total
    assert client.get('/api/gaps').json()
    findings=client.get('/api/anomalies').json();assert findings and all(x['confidence']=='heuristic' for x in findings)
    synthetic_ids={x['id'] for x in synthetic}
    reset=client.post('/api/synthetic/reset').json();assert reset['removed_evidence_count']>=total
    remaining=client.get('/api/evidence').json();assert any(x['id']==real_id for x in remaining)
    assert not any(a.get('evidence_id') in synthetic_ids for a in client.get('/api/anomalies').json())

def test_backup_file_is_downloadable():
    r=client.post('/api/backup');assert r.status_code==200;assert r.content[:16]==b'SQLite format 3\x00'

def teardown_module():
    client.close();engine.dispose();shutil.rmtree(DATA,ignore_errors=True)


