# Tracepoint PS-013 — operations guide

## Setup

1. In the `IT2PL-project` folder, create the venv and install `backend/requirements.txt` using the commands in `README.md`.
2. Start Uvicorn on `127.0.0.1:8000`, open `http://127.0.0.1:8000/`, and accept the use notice.
3. Confirm the database banner shows the SQLite connection and counts.

## Analyst workflow

1. Choose **Database & investigations**. Generate the SSH scenario using seed `13013`.
2. Review the `SYNTHETIC` metadata, timezone/correction values, and file list. Preview a file and download it individually or as a ZIP.
3. Import the scenario. Tracepoint writes original bytes to `backend/data/evidence/`, inserts evidence/source/original-row/normalized-event/anomaly/audit rows in SQLite, and creates a named investigation from the UI action.
4. Open **Evidence files**. Check the filename, file size, upload timestamp, format, source timezone, correction, and SHA-256. Download an original and run **Verify integrity**.
5. Review the chronological event table and original records. Use source IP, username, event type, severity, date, and text filters. Inspect parsing gaps for malformed or timestamp-invalid rows.
6. Review findings, making clear they are heuristic. The SSH scenario includes repeated authentication failures; the web scenario contains traversal and SQL-injection-like request strings; the network scenario contains denied connections.
7. Create/open an investigation. Associate current evidence/events, add notes, set status, fill triage answers and manual/tool times, then save. Export JSON and CSV; use Print/Save as PDF for a printable copy.
8. Generate and import the web and network scenarios. Reuse a seed to demonstrate repeatable file content.
9. Restart Uvicorn and reload. Confirm database-backed evidence and investigations remain. Back up using `/api/backup`; preserve the evidence directory with the database snapshot.
10. Use **Reset synthetic data** to remove generated evidence only. Confirm user-uploaded evidence remains.

## Important qualifications

Only synthetic or sanitized logs should be used. A matching SHA-256 indicates the stored original bytes have not changed since ingestion; it does not prove collection provenance or chain of custody. Time corrections are manually supplied. Rule findings are not confirmed incidents. This tool does not perform endpoint acquisition, malware removal, or forensic certification.

