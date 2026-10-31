# Backend — Tracepoint PS-013

The backend is implemented with FastAPI, SQLAlchemy 2.x, and SQLite. Run it from the project folder:

```powershell
py -3 -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

The FastAPI app is `backend/app/main.py`; schema models are in `models.py`, database setup is in `database.py`, parsers in `parsers.py`, and deterministic synthetic data generation in `synthetic.py`. SQLite and evidence bytes are created at `backend/data/` unless `TRACEPOINT_DATA_DIR` is set. The UI is served at `/`, OpenAPI at `/docs`.

All routes are listed in the project `README.md`. Important endpoints include evidence upload and hash verification, event/gap/anomaly queries, investigation CRUD and associations, JSON/CSV reports, seeded scenario preview/import/download, synthetic-only reset, audit reads, and SQLite backup.

The service is unauthenticated and designed for localhost-only demonstration. Keep it bound to `127.0.0.1`. Uploaded originals are stored separately from the database. Back up both `tracepoint.sqlite3` and `evidence/`; a database backup alone does not include original files. SHA-256 matching is not evidence of authenticity or chain of custody.

Run backend tests with `backend\.venv\Scripts\python.exe -m pytest -q backend\tests` from the project folder.
