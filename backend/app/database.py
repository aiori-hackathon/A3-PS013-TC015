from __future__ import annotations
import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get('TRACEPOINT_DATA_DIR', BASE_DIR / 'data')).resolve()
EVIDENCE_DIR = DATA_DIR / 'evidence'
DATABASE_PATH = DATA_DIR / 'tracepoint.sqlite3'
DATABASE_URL = os.environ.get('TRACEPOINT_DATABASE_URL', f'sqlite:///{DATABASE_PATH.as_posix()}')
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

class Base(DeclarativeBase):
    pass

engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {}, future=True)
if DATABASE_URL.startswith('sqlite'):
    @event.listens_for(engine, 'connect')
    def enable_foreign_keys(dbapi_connection, _):
        cursor = dbapi_connection.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.close()

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
