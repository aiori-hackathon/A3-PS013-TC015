from __future__ import annotations
import csv, hashlib, io, json, os, shutil, sqlite3, uuid, zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from .database import Base, DATA_DIR, EVIDENCE_DIR, SessionLocal, engine, get_db
from .models import (Anomaly, AuditRecord, DataSource, Evidence, Investigation, InvestigationEvidence,
                     InvestigationEvent, NormalizedEvent, OriginalLogRecord, SyntheticScenario, utcnow)
from .parsers import detect_format, records_for
from .schemas import AssociateIds, InvestigationCreate, InvestigationUpdate
from .synthetic import CATALOG, generate_scenario

MAX_UPLOAD_BYTES=25*1024*1024
FRONTEND_DIR=Path(__file__).resolve().parents[2]/'frontend'

def jsonable_dt(x): return x.isoformat()+'Z' if isinstance(x,datetime) else x

def serialize_evidence(x: Evidence):
    return {'id':x.id,'filename':x.filename,'file_size_bytes':x.byte_size,'sha256':x.sha256,'duplicate_of_id':x.duplicate_of_id,'mime_type':x.mime_type,'format':x.detected_format,
            'source_timezone':x.source_timezone,'clock_offset_minutes':x.clock_offset_minutes,'synthetic':x.synthetic,'scenario_id':x.scenario_id,
            'processing_status':x.processing_status,'integrity_status':x.integrity_status,'uploaded_at':jsonable_dt(x.uploaded_at),'record_count':len(x.records),'event_count':len(x.events),
            'parsing_gap_count':sum(r.parse_status=='gap' for r in x.records)}

def serialize_event(x: NormalizedEvent, include_original: bool=False):
    d={'id':x.id,'evidence_id':x.evidence_id,'original_record_id':x.original_record_id,'timestamp_utc':jsonable_dt(x.timestamp_utc),
       'original_timestamp':x.original_timestamp,'source_timezone':x.source_timezone,'clock_offset_minutes':x.clock_offset_minutes,'host':x.host,
       'source_ip':x.source_ip,'username':x.username,'event_type':x.event_type,'severity':x.severity,'description':x.description,'duplicate_record':x.duplicate_record}
    if include_original and x.original_record: d['original_record']=x.original_record.original_text
    return d

def audit(db:Session, action:str, entity_type:str, entity_id:str|None=None, details:dict|None=None):
    db.add(AuditRecord(action=action,entity_type=entity_type,entity_id=entity_id,details_json=json.dumps(details or {},ensure_ascii=False,default=str)))

def _within(path:Path, parent:Path)->bool:
    try: path.resolve().relative_to(parent.resolve()); return True
    except ValueError: return False

def _rule_anomalies(db:Session, evidence:Evidence, events:list[NormalizedEvent], gaps:int):
    fired=[]
    fail_ips={}
    for e in events:
        text=e.description.lower()
        if 'failed password' in text and e.source_ip: fail_ips[e.source_ip]=fail_ips.get(e.source_ip,0)+1
        if any(x in text for x in ('../','union select','/admin/export')):
            fired.append(('suspicious-web-pattern','Suspicious request pattern','Rule matched a traversal, SQL-injection-like, or administrative export string. This is a heuristic finding.'))
    for ip,count in fail_ips.items():
        if count>=3: fired.append(('repeated-auth-failures','Repeated failed authentication',f'{count} failed authentication records from {ip}; rule-based finding, not a confirmed attack.'))
    timed=sorted((e.timestamp_utc for e in events if e.timestamp_utc))
    if any((b-a).total_seconds()>6*3600 for a,b in zip(timed,timed[1:])):
        fired.append(('long-inter-event-gap','Long gap between records','A gap greater than six hours appears within this evidence source. Compare expected log cadence and clock settings; this is a heuristic data-quality finding.'))
    original_order=[e.timestamp_utc for e in events if e.timestamp_utc]
    if any((a-b).total_seconds()>300 for a,b in zip(original_order,original_order[1:])):
        fired.append(('out-of-order-records','Inconsistent record ordering','At least one record is over five minutes earlier than its predecessor after normalization. Review source ordering and clock skew.'))
    if gaps: fired.append(('parser-gaps','Parsing gaps detected',f'{gaps} original record(s) could not be normalized and remain available for review.'))
    for rule,title,desc in fired:
        db.add(Anomaly(evidence_id=evidence.id,rule_id=rule,title=title,description=desc,confidence='heuristic'))

def _ingest(db:Session, filename:str, content:bytes, mime_type:str='application/octet-stream', requested_format:str='auto', source_timezone:str='UTC', clock_offset_minutes:int=0, synthetic:bool=False, scenario_id:str|None=None):
    if len(content)>MAX_UPLOAD_BYTES: raise HTTPException(413,'File exceeds the 25 MiB upload limit')
    if not -1440<=clock_offset_minutes<=1440: raise HTTPException(400,'Clock correction must be between -1440 and 1440 minutes')
    source_timezone=(source_timezone or 'Unspecified').strip()
    if source_timezone!='Unspecified':
        try: from zoneinfo import ZoneInfo; ZoneInfo(source_timezone)
        except Exception as exc: raise HTTPException(400,'Unknown source timezone') from exc
    if not content: raise HTTPException(400,'Empty evidence files are not accepted')
    digest=hashlib.sha256(content).hexdigest()
    existing=db.scalar(select(Evidence).where(Evidence.sha256==digest,Evidence.synthetic.is_(synthetic),Evidence.scenario_id==scenario_id).order_by(Evidence.uploaded_at).limit(1))
    safe_name=Path(filename.replace('\\','/')).name.strip()
    if Path(safe_name).suffix.lower() not in {'.log','.txt','.json','.jsonl','.csv'}: raise HTTPException(400,'Allowed evidence file types: .log, .txt, .json, .jsonl, .csv')
    if not safe_name or safe_name in ('.','..') or len(safe_name)>255 or '\x00' in safe_name: raise HTTPException(400,'Invalid evidence filename')
    try: decoded=content.decode('utf-8-sig')
    except UnicodeDecodeError: decoded=content.decode('utf-8',errors='replace')
    fmt=detect_format(safe_name,decoded) if requested_format=='auto' else requested_format
    if fmt not in {'csv','json','jsonl','auth','apache','firewall','text'}: raise HTTPException(400,'Unsupported log format')
    evidence_id=str(uuid.uuid4());storage_name=evidence_id+'.evidence';target=(EVIDENCE_DIR/storage_name).resolve()
    if not _within(target,EVIDENCE_DIR): raise HTTPException(400,'Invalid evidence storage path')
    temp=EVIDENCE_DIR/(storage_name+'.tmp')
    try:
        temp.write_bytes(content);os.replace(temp,target)
        evidence=Evidence(id=evidence_id,filename=safe_name,storage_name=storage_name,byte_size=len(content),sha256=digest,duplicate_of_id=existing.id if existing else None,mime_type=mime_type[:120],detected_format=fmt,
                          source_timezone=source_timezone[:80],clock_offset_minutes=clock_offset_minutes,synthetic=synthetic,scenario_id=scenario_id,processing_status='processing')
        db.add(evidence);db.flush()
        db.add(DataSource(evidence_id=evidence.id,name=safe_name,log_format=fmt,source_timezone=source_timezone[:80],clock_offset_minutes=clock_offset_minutes))
        parsed_rows=records_for(decoded,fmt,source_timezone,clock_offset_minutes)
        seen=set(); made=[]; gap_count=0
        for line_no,original,status,parsed,error in parsed_rows:
            record=OriginalLogRecord(evidence_id=evidence.id,line_number=line_no,original_text=original,parse_status=status,parse_error=error)
            db.add(record);db.flush()
            if status=='metadata': continue
            if status!='parsed' or not parsed: gap_count+=1;continue
            dup=original in seen;seen.add(original)
            event=NormalizedEvent(evidence_id=evidence.id,original_record_id=record.id,timestamp_utc=parsed['timestamp_utc'],original_timestamp=parsed['original_timestamp'],
                source_timezone=source_timezone[:80],clock_offset_minutes=clock_offset_minutes,host=parsed['host'][:255],source_ip=(str(parsed['source_ip'])[:80] if parsed.get('source_ip') else None),
                username=(str(parsed['username'])[:160] if parsed.get('username') else None),event_type=parsed['event_type'][:120],severity=parsed['severity'],description=parsed['description'],
                normalized_json=json.dumps(parsed['normalized'],ensure_ascii=False,default=str),duplicate_record=dup)
            db.add(event);made.append(event)
            if dup: db.add(Anomaly(evidence_id=evidence.id,rule_id='duplicate-record',title='Duplicate log record',description=f'Line {line_no} repeats a record in this evidence file.',confidence='heuristic'))
        _rule_anomalies(db,evidence,made,gap_count)
        ips={e.source_ip for e in made if e.source_ip}
        for ip in ips:
            source_count=(db.scalar(select(func.count(func.distinct(NormalizedEvent.evidence_id))).where(NormalizedEvent.source_ip==ip,NormalizedEvent.evidence_id!=evidence.id)) or 0)+1
            prior=db.scalar(select(Anomaly).where(Anomaly.evidence_id==evidence.id,Anomaly.rule_id=='cross-source-correlation'))
            if source_count>=2 and not prior: db.add(Anomaly(evidence_id=evidence.id,rule_id='cross-source-correlation',title='Activity linked across evidence sources',description=f'The same source IP {ip} appears in {source_count} evidence sources. Review timestamps and source context; this is a correlation cue, not proof of a single incident.',confidence='heuristic'))
        evidence.processing_status='processed' if not gap_count else 'processed_with_gaps'
        audit(db,'evidence.upload','evidence',evidence.id,{'filename':safe_name,'sha256':digest,'synthetic':synthetic,'scenario_id':scenario_id})
        db.commit();db.refresh(evidence);return evidence,bool(existing)
    except HTTPException:
        db.rollback();temp.unlink(missing_ok=True);target.unlink(missing_ok=True);raise
    except Exception as exc:
        db.rollback();temp.unlink(missing_ok=True);target.unlink(missing_ok=True)
        raise HTTPException(500,f'Evidence processing failed; no database record was committed ({type(exc).__name__})') from exc

@asynccontextmanager
async def lifespan(app:FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app=FastAPI(title='Tracepoint PS-013 API',version='1.0.0',description='Local-first evidence and investigation API. Rule detections are heuristic findings.',lifespan=lifespan)

@app.middleware('http')
async def cap_upload_request(request,call_next):
    if request.method=='POST' and request.url.path=='/api/evidence':
        length=request.headers.get('content-length')
        if length:
            try: too_large=int(length)>MAX_UPLOAD_BYTES+1024*1024
            except ValueError: return JSONResponse({'detail':'Invalid Content-Length'},status_code=400)
            if too_large: return JSONResponse({'detail':'Upload request exceeds the 25 MiB file limit'},status_code=413)
    return await call_next(request)

@app.get('/',response_class=HTMLResponse)
def frontend():
    path=FRONTEND_DIR/'index.html'
    if not path.exists(): raise HTTPException(404,'Frontend files not found')
    return HTMLResponse(path.read_text(encoding='utf-8'))
@app.get('/app.css')
def css(): return FileResponse(FRONTEND_DIR/'app.css',media_type='text/css')
@app.get('/app.js')
def js(): return FileResponse(FRONTEND_DIR/'app.js',media_type='text/javascript')
@app.get('/api/health')
def health(): return {'ok':True,'service':'tracepoint','utc':datetime.now(timezone.utc).isoformat()}
@app.get('/api/status')
def status(db:Session=Depends(get_db)):
    return {'database':'sqlite','database_path':str(engine.url.database),'evidence_storage':str(EVIDENCE_DIR),'counts':{
      'evidence':db.scalar(select(func.count()).select_from(Evidence)) or 0,'events':db.scalar(select(func.count()).select_from(NormalizedEvent)) or 0,
      'gaps':db.scalar(select(func.count()).select_from(OriginalLogRecord).where(OriginalLogRecord.parse_status=='gap')) or 0,
      'investigations':db.scalar(select(func.count()).select_from(Investigation)) or 0,'anomalies':db.scalar(select(func.count()).select_from(Anomaly)) or 0}}

@app.post('/api/evidence')
async def upload_evidence(file:UploadFile=File(...),format:str=Form('auto'),source_timezone:str|None=Form(None),clock_offset_minutes:int=Form(0),synthetic:bool=Form(False),scenario_id:str|None=Form(None),db:Session=Depends(get_db)):
    content=await file.read(MAX_UPLOAD_BYTES+1)
    evidence,duplicate=_ingest(db,file.filename or 'evidence.log',content,file.content_type or 'application/octet-stream',format,source_timezone,clock_offset_minutes,synthetic,scenario_id)
    return {'evidence':serialize_evidence(evidence),'duplicate':duplicate}

@app.get('/api/evidence')
def list_evidence(synthetic:bool|None=None,db:Session=Depends(get_db)):
    stmt=select(Evidence).order_by(Evidence.uploaded_at.desc())
    if synthetic is not None: stmt=stmt.where(Evidence.synthetic==synthetic)
    return [serialize_evidence(x) for x in db.scalars(stmt).all()]
@app.get('/api/evidence/{evidence_id}')
def get_evidence(evidence_id:str,db:Session=Depends(get_db)):
    x=db.get(Evidence,evidence_id)
    if not x: raise HTTPException(404,'Evidence not found')
    d=serialize_evidence(x);d['records']=[{'id':r.id,'line_number':r.line_number,'original_text':r.original_text,'parse_status':r.parse_status,'parse_error':r.parse_error} for r in x.records]
    return d
@app.get('/api/evidence/{evidence_id}/verify')
def verify_evidence(evidence_id:str,db:Session=Depends(get_db)):
    x=db.get(Evidence,evidence_id)
    if not x: raise HTTPException(404,'Evidence not found')
    path=(EVIDENCE_DIR/x.storage_name).resolve()
    exists=_within(path,EVIDENCE_DIR) and path.is_file()
    actual=hashlib.sha256(path.read_bytes()).hexdigest() if exists else None
    passed=actual==x.sha256
    x.integrity_status='pass' if passed else 'fail'
    audit(db,'evidence.verify','evidence',x.id,{'passed':passed,'file_exists':exists});db.commit()
    return {'evidence_id':x.id,'status':'pass' if passed else 'fail','expected_sha256':x.sha256,'actual_sha256':actual,'file_exists':exists,
            'note':'Digest comparison only; this does not prove authenticity or chain of custody.'}
@app.get('/api/evidence/{evidence_id}/download')
def download_evidence(evidence_id:str,db:Session=Depends(get_db)):
    x=db.get(Evidence,evidence_id)
    if not x: raise HTTPException(404,'Evidence not found')
    path=(EVIDENCE_DIR/x.storage_name).resolve()
    if not _within(path,EVIDENCE_DIR) or not path.is_file(): raise HTTPException(404,'Stored evidence file is missing')
    return FileResponse(path,media_type='application/octet-stream',filename=x.filename)

@app.get('/api/events')
def list_events(q:str|None=None,source_ip:str|None=None,username:str|None=None,event_type:str|None=None,severity:str|None=None,evidence_id:str|None=None,
               start:str|None=None,end:str|None=None,skip:int=0,limit:int=Query(250,ge=1,le=1000),db:Session=Depends(get_db)):
    stmt=select(NormalizedEvent).order_by(NormalizedEvent.timestamp_utc,NormalizedEvent.id)
    if q:
        term=f'%{q[:200]}%';stmt=stmt.where(or_(NormalizedEvent.description.ilike(term),NormalizedEvent.source_ip.ilike(term),NormalizedEvent.username.ilike(term),NormalizedEvent.host.ilike(term)))
    if source_ip: stmt=stmt.where(NormalizedEvent.source_ip==source_ip)
    if username: stmt=stmt.where(NormalizedEvent.username==username)
    if event_type: stmt=stmt.where(NormalizedEvent.event_type==event_type)
    if severity: stmt=stmt.where(NormalizedEvent.severity==severity)
    if evidence_id: stmt=stmt.where(NormalizedEvent.evidence_id==evidence_id)
    try:
        if start: stmt=stmt.where(NormalizedEvent.timestamp_utc>=datetime.fromisoformat(start.replace('Z','+00:00')).astimezone(timezone.utc).replace(tzinfo=None))
        if end: stmt=stmt.where(NormalizedEvent.timestamp_utc<=datetime.fromisoformat(end.replace('Z','+00:00')).astimezone(timezone.utc).replace(tzinfo=None))
    except ValueError: raise HTTPException(400,'Invalid date filter; use ISO-8601 timestamps')
    results=db.scalars(stmt.offset(skip).limit(limit)).all()
    return [serialize_event(x,True) for x in results]
@app.get('/api/gaps')
def list_gaps(evidence_id:str|None=None,db:Session=Depends(get_db)):
    stmt=select(OriginalLogRecord).where(OriginalLogRecord.parse_status=='gap').order_by(OriginalLogRecord.evidence_id,OriginalLogRecord.line_number)
    if evidence_id: stmt=stmt.where(OriginalLogRecord.evidence_id==evidence_id)
    return [{'id':x.id,'evidence_id':x.evidence_id,'filename':x.evidence.filename,'line_number':x.line_number,'original_text':x.original_text,'reason':x.parse_error,'synthetic':x.evidence.synthetic} for x in db.scalars(stmt).all()]
@app.get('/api/anomalies')
def list_anomalies(investigation_id:str|None=None,evidence_id:str|None=None,db:Session=Depends(get_db)):
    stmt=select(Anomaly).order_by(Anomaly.created_at.desc())
    if investigation_id: stmt=stmt.where(Anomaly.investigation_id==investigation_id)
    if evidence_id: stmt=stmt.where(Anomaly.evidence_id==evidence_id)
    return [{'id':x.id,'evidence_id':x.evidence_id,'investigation_id':x.investigation_id,'rule_id':x.rule_id,'title':x.title,'description':x.description,'confidence':x.confidence,'synthetic':bool(db.get(Evidence,x.evidence_id).synthetic) if x.evidence_id and db.get(Evidence,x.evidence_id) else False,'created_at':jsonable_dt(x.created_at)} for x in db.scalars(stmt).all()]

@app.get('/api/time-analysis')
def time_analysis(db:Session=Depends(get_db)):
    rows=db.execute(select(Evidence.id,Evidence.filename,Evidence.source_timezone,Evidence.clock_offset_minutes,func.count(NormalizedEvent.id),func.min(NormalizedEvent.timestamp_utc),func.max(NormalizedEvent.timestamp_utc)).outerjoin(NormalizedEvent,NormalizedEvent.evidence_id==Evidence.id).group_by(Evidence.id).order_by(Evidence.filename)).all()
    return [{'evidence_id':r[0],'filename':r[1],'source_timezone':r[2],'clock_offset_minutes':r[3],'event_count':r[4],'first_utc':jsonable_dt(r[5]),'last_utc':jsonable_dt(r[6]),'synthetic':db.get(Evidence,r[0]).synthetic} for r in rows]

@app.post('/api/investigations',status_code=201)
def create_investigation(payload:InvestigationCreate,db:Session=Depends(get_db)):
    x=Investigation(id=str(uuid.uuid4()),name=payload.name.strip(),description=payload.description,notes=payload.notes,triage_answers_json=json.dumps(payload.triage_answers),manual_baseline_minutes=payload.manual_baseline_minutes,tool_assisted_minutes=payload.tool_assisted_minutes)
    if not x.name: raise HTTPException(422,'Investigation name is required')
    db.add(x);audit(db,'investigation.create','investigation',x.id);db.commit();db.refresh(x);return _investigation(x)
def _investigation(x:Investigation):
    return {'id':x.id,'name':x.name,'description':x.description,'status':x.status,'notes':x.notes,'created_at':jsonable_dt(x.created_at),'updated_at':jsonable_dt(x.updated_at),'triage_answers':json.loads(x.triage_answers_json or '[]'),'manual_baseline_minutes':x.manual_baseline_minutes,'tool_assisted_minutes':x.tool_assisted_minutes,
      'evidence_ids':[l.evidence_id for l in x.evidence_links],'event_ids':[l.event_id for l in x.event_links]}
@app.get('/api/investigations')
def list_investigations(db:Session=Depends(get_db)): return [_investigation(x) for x in db.scalars(select(Investigation).order_by(Investigation.updated_at.desc())).all()]
@app.get('/api/investigations/{investigation_id}')
def get_investigation(investigation_id:str,db:Session=Depends(get_db)):
    x=db.get(Investigation,investigation_id)
    if not x: raise HTTPException(404,'Investigation not found')
    d=_investigation(x);d['events']=[serialize_event(db.get(NormalizedEvent,l.event_id),True) for l in x.event_links if db.get(NormalizedEvent,l.event_id)]
    d['evidence']=[serialize_evidence(db.get(Evidence,l.evidence_id)) for l in x.evidence_links if db.get(Evidence,l.evidence_id)]
    eids=[l.evidence_id for l in x.evidence_links]; findings=db.scalars(select(Anomaly).where(or_(Anomaly.investigation_id==x.id,Anomaly.evidence_id.in_(eids) if eids else False))).all();d['anomalies']=[{'id':a.id,'rule_id':a.rule_id,'title':a.title,'description':a.description,'confidence':a.confidence} for a in findings]
    return d
@app.patch('/api/investigations/{investigation_id}')
def update_investigation(investigation_id:str,payload:InvestigationUpdate,db:Session=Depends(get_db)):
    x=db.get(Investigation,investigation_id)
    if not x: raise HTTPException(404,'Investigation not found')
    for k,v in payload.model_dump(exclude_unset=True).items():
        if k in ('manual_baseline_minutes','tool_assisted_minutes'):
            setattr(x,k,v);continue
        if v is None: continue
        if k=='triage_answers': x.triage_answers_json=json.dumps(v)
        else: setattr(x,k,v.strip() if isinstance(v,str) and k=='name' else v)
    x.updated_at=utcnow();audit(db,'investigation.update','investigation',x.id,payload.model_dump(exclude_unset=True));db.commit();db.refresh(x);return _investigation(x)
@app.post('/api/investigations/{investigation_id}/evidence')
def associate_evidence(investigation_id:str,payload:AssociateIds,db:Session=Depends(get_db)):
    x=db.get(Investigation,investigation_id)
    if not x: raise HTTPException(404,'Investigation not found')
    for raw in payload.ids:
        evidence=db.get(Evidence,str(raw))
        if not evidence: raise HTTPException(404,f'Evidence {raw} not found')
        if not db.scalar(select(InvestigationEvidence).where(InvestigationEvidence.investigation_id==x.id,InvestigationEvidence.evidence_id==evidence.id)):
            db.add(InvestigationEvidence(investigation_id=x.id,evidence_id=evidence.id))
    x.updated_at=utcnow();audit(db,'investigation.associate_evidence','investigation',x.id,{'ids':payload.ids});db.commit();return _investigation(x)
@app.post('/api/investigations/{investigation_id}/events')
def associate_events(investigation_id:str,payload:AssociateIds,db:Session=Depends(get_db)):
    x=db.get(Investigation,investigation_id)
    if not x: raise HTTPException(404,'Investigation not found')
    for raw in payload.ids:
        event=db.get(NormalizedEvent,int(raw))
        if not event: raise HTTPException(404,f'Event {raw} not found')
        if not db.scalar(select(InvestigationEvent).where(InvestigationEvent.investigation_id==x.id,InvestigationEvent.event_id==event.id)):
            db.add(InvestigationEvent(investigation_id=x.id,event_id=event.id))
        if not db.scalar(select(InvestigationEvidence).where(InvestigationEvidence.investigation_id==x.id,InvestigationEvidence.evidence_id==event.evidence_id)):
            db.add(InvestigationEvidence(investigation_id=x.id,evidence_id=event.evidence_id))
    x.updated_at=utcnow();audit(db,'investigation.associate_events','investigation',x.id,{'ids':payload.ids});db.commit();return _investigation(x)
@app.get('/api/investigations/{investigation_id}/report')
def report(investigation_id:str,format:str='json',db:Session=Depends(get_db)):
    x=db.get(Investigation,investigation_id)
    if not x: raise HTTPException(404,'Investigation not found')
    ids=[l.event_id for l in x.event_links]
    events=db.scalars(select(NormalizedEvent).where(NormalizedEvent.id.in_(ids)).order_by(NormalizedEvent.timestamp_utc)).all() if ids else []
    evidence=[serialize_evidence(db.get(Evidence,l.evidence_id)) for l in x.evidence_links if db.get(Evidence,l.evidence_id)]
    data={'generated_at':datetime.now(timezone.utc).isoformat(),'investigation':_investigation(x),'evidence':evidence,'events':[serialize_event(e,True) for e in events],
      'gaps':[g for e in evidence for g in list_gaps(e['id'],db)],'anomalies':[{'rule_id':a.rule_id,'title':a.title,'description':a.description,'confidence':a.confidence} for a in db.scalars(select(Anomaly).where(or_(Anomaly.investigation_id==x.id,Anomaly.evidence_id.in_([l.evidence_id for l in x.evidence_links]) if x.evidence_links else False))).all()],
      'triage':{'answers':json.loads(x.triage_answers_json or '[]'),'manual_baseline_minutes':x.manual_baseline_minutes,'tool_assisted_minutes':x.tool_assisted_minutes,'time_saved_minutes':(x.manual_baseline_minutes-x.tool_assisted_minutes) if x.manual_baseline_minutes is not None and x.tool_assisted_minutes is not None else None,'percentage_improvement':round((x.manual_baseline_minutes-x.tool_assisted_minutes)/x.manual_baseline_minutes*100,1) if x.manual_baseline_minutes and x.tool_assisted_minutes is not None else None},
      'limitations':['Rule findings are heuristic, not confirmed incidents. SHA-256 comparison does not establish authenticity or chain of custody.']}
    audit(db,'report.export','investigation',x.id,{'format':format});db.commit()
    if format=='json': return JSONResponse(data)
    if format=='csv':
        out=io.StringIO();w=csv.DictWriter(out,fieldnames=['timestamp_utc','original_timestamp','source_timezone','clock_offset_minutes','source_ip','username','event_type','severity','description','evidence_id','original_record']);w.writeheader()
        for e in data['events']: w.writerow({k:e.get(k,'') for k in w.fieldnames})
        return Response('\ufeff'+out.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':f'attachment; filename="tracepoint-investigation-{x.id}.csv"'})
    raise HTTPException(400,'Report format must be json or csv')

@app.get('/api/scenarios')
def scenarios(): return [{'id':k,'name':v[0],'description':v[1],'synthetic':True} for k,v in CATALOG.items()]
def _store_scenario(db:Session,scenario:dict):
    key=f"{scenario['scenario_id']}:{scenario['seed']}";row=db.get(SyntheticScenario,key)
    if row: row.metadata_json=json.dumps(scenario['metadata']);row.generated_at=utcnow();row.active=True
    else: db.add(SyntheticScenario(id=key,name=scenario['name'],seed=scenario['seed'],metadata_json=json.dumps(scenario['metadata'])))
    audit(db,'scenario.generate','synthetic_scenario',key,{'seed':scenario['seed'],'scenario_id':scenario['scenario_id']});db.commit()
@app.post('/api/scenarios/{scenario_id}/generate')
def generate(scenario_id:str,seed:int=13013,db:Session=Depends(get_db)):
    try: sc=generate_scenario(scenario_id,seed)
    except KeyError: raise HTTPException(404,'Unknown synthetic scenario')
    _store_scenario(db,sc);return sc
@app.get('/api/scenarios/{scenario_id}/download')
def download_scenario(scenario_id:str,seed:int=13013):
    try: sc=generate_scenario(scenario_id,seed)
    except KeyError: raise HTTPException(404,'Unknown synthetic scenario')
    bio=io.BytesIO()
    with zipfile.ZipFile(bio,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('SYNTHETIC-SCENARIO-METADATA.json',json.dumps({k:v for k,v in sc.items() if k!='files'},indent=2))
        for f in sc['files']: z.writestr(Path(f['filename']).name,f['text'])
    bio.seek(0);return StreamingResponse(bio,media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="tracepoint-{scenario_id}-seed-{seed}.zip"'})
@app.post('/api/scenarios/{scenario_id}/import')
def import_scenario(scenario_id:str,seed:int=13013,db:Session=Depends(get_db)):
    try: sc=generate_scenario(scenario_id,seed)
    except KeyError: raise HTTPException(404,'Unknown synthetic scenario')
    _store_scenario(db,sc);items=[]
    for f in sc['files']:
        e,dup=_ingest(db,f['filename'],f['text'].encode('utf-8'),'text/plain',f['format'],f['source_timezone'],f['clock_offset_minutes'],True,f'{scenario_id}:{seed}')
        items.append({'evidence':serialize_evidence(e),'duplicate':dup})
    return {'scenario':{k:v for k,v in sc.items() if k!='files'},'evidence':items}
@app.post('/api/synthetic/reset')
def reset_synthetic(db:Session=Depends(get_db)):
    items=db.scalars(select(Evidence).where(Evidence.synthetic.is_(True))).all();removed=0;ids=[e.id for e in items]
    if ids: db.query(Anomaly).filter(Anomaly.evidence_id.in_(ids)).delete(synchronize_session=False)
    for e in items:
        path=(EVIDENCE_DIR/e.storage_name).resolve()
        if _within(path,EVIDENCE_DIR): path.unlink(missing_ok=True)
        db.delete(e);removed+=1
    db.query(SyntheticScenario).delete(synchronize_session=False);audit(db,'synthetic.reset','synthetic_scenario',None,{'removed_evidence_count':removed});db.commit()
    return {'removed_evidence_count':removed,'message':'Synthetic scenario evidence removed; uploaded evidence was preserved.'}
@app.get('/api/audit')
def audit_log(limit:int=Query(250,ge=1,le=1000),db:Session=Depends(get_db)):
    return [{'id':r.id,'action':r.action,'entity_type':r.entity_type,'entity_id':r.entity_id,'details':json.loads(r.details_json),'created_at':jsonable_dt(r.created_at)} for r in db.scalars(select(AuditRecord).order_by(AuditRecord.created_at.desc()).limit(limit)).all()]
@app.post('/api/backup')
def backup():
    folder=DATA_DIR/'backups';folder.mkdir(parents=True,exist_ok=True);name='tracepoint-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.sqlite3';target=folder/name
    src=sqlite3.connect(str(Path(engine.url.database)));dst=sqlite3.connect(str(target))
    try: src.backup(dst)
    finally: dst.close();src.close()
    return FileResponse(target,media_type='application/vnd.sqlite3',filename=name)

if FRONTEND_DIR.exists(): app.mount('/datasets',StaticFiles(directory=FRONTEND_DIR/'datasets'),name='datasets')
