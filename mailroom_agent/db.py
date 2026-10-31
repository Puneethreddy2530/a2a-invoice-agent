"""
SQLite storage for the Safe AI Mailroom Agent.

Durable state only.  Every propose/commit write is transactional.  The cache is
keyed by dossier id plus a canonical content fingerprint that includes the
decision-engine version, so deploying a new engine never reuses stale decisions.
"""

import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

import tempfile
DB_PATH = os.environ.get("GA3_MAILROOM_DB") or os.path.join(tempfile.gettempdir(), "t3ga3_mailroom_agent.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in conn.execute(f"PRAGMA table_info({table})"))


def init_db() -> None:
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                input_digest TEXT NOT NULL,
                verifier_jwk TEXT NOT NULL,
                propose_response TEXT NOT NULL,
                commit_response TEXT,
                commit_request_digest TEXT,
                request_digest TEXT,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dossier_cache (
                dossier_id TEXT NOT NULL,
                content_fingerprint TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (dossier_id, content_fingerprint)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_proposals (
                evaluation_id TEXT NOT NULL,
                dossier_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                action TEXT NOT NULL,
                proposal_digest TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                PRIMARY KEY (evaluation_id, dossier_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                evaluation_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                dossier_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                action TEXT NOT NULL,
                proposal_digest TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                signature TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (evaluation_id, receipt_id)
            )
        """)
        # A receipt nonce is globally single-use: it must not be moved to another
        # evaluation or proposal.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS used_receipts (
                receipt_id TEXT PRIMARY KEY,
                evaluation_id TEXT NOT NULL,
                dossier_id TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        # Full propose bodies, kept for offline corpus inspection and regression
        # testing.  Synthetic exam data only.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS request_log (
                evaluation_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                body_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (evaluation_id, kind)
            )
        """)
        conn.commit()

        # Migrate older databases in place.
        if not _column_exists(conn, "evaluations", "commit_request_digest"):
            conn.execute("ALTER TABLE evaluations ADD COLUMN commit_request_digest TEXT")
            conn.commit()
        if not _column_exists(conn, "evaluations", "request_digest"):
            conn.execute("ALTER TABLE evaluations ADD COLUMN request_digest TEXT")
            conn.commit()


init_db()


def get_evaluation(eval_id: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM evaluations WHERE evaluation_id = ?", (eval_id,)
        ).fetchone()
        if row:
            return dict(row)
    return None


def save_evaluation_propose(
    eval_id: str,
    input_digest: str,
    verifier_jwk: Dict[str, Any],
    resp_obj: Dict[str, Any],
    request_digest: Optional[str] = None,
) -> None:
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO evaluations
            (evaluation_id, input_digest, verifier_jwk, propose_response,
             commit_response, commit_request_digest, request_digest, status, created_at)
            VALUES (?, ?, ?, ?, NULL, NULL, ?, 'awaiting_receipts', ?)
        """, (
            eval_id,
            input_digest,
            json.dumps(verifier_jwk, separators=(",", ":")),
            json.dumps(resp_obj, separators=(",", ":")),
            request_digest,
            time.time(),
        ))
        conn.commit()


def save_evaluation_commit(
    eval_id: str,
    resp_obj: Dict[str, Any],
    commit_request_digest: Optional[str] = None,
) -> None:
    with get_db() as conn:
        conn.execute("""
            UPDATE evaluations
            SET commit_response = ?, commit_request_digest = ?, status = 'completed'
            WHERE evaluation_id = ?
        """, (
            json.dumps(resp_obj, separators=(",", ":")),
            commit_request_digest,
            eval_id,
        ))
        conn.commit()


def save_commit_atomic(
    eval_id: str,
    resp_obj: Dict[str, Any],
    commit_request_digest: str,
    receipts: List[Dict[str, Any]],
    outcomes: List[Dict[str, Any]],
) -> None:
    """Persist receipts, outcomes and the completed state in one transaction."""
    now = time.time()
    with get_db() as conn:
        for rcpt in receipts:
            conn.execute("""
                INSERT INTO receipts
                (evaluation_id, receipt_id, dossier_id, call_id, action,
                 proposal_digest, accepted, signature, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                eval_id,
                rcpt["receiptId"],
                rcpt["dossierId"],
                rcpt["callId"],
                rcpt["action"],
                rcpt["proposalDigest"],
                1 if rcpt["accepted"] else 0,
                rcpt["receiptSignature"],
                now,
            ))
            conn.execute("""
                INSERT INTO used_receipts (receipt_id, evaluation_id, dossier_id, created_at)
                VALUES (?, ?, ?, ?)
            """, (rcpt["receiptId"], eval_id, rcpt["dossierId"], now))
        conn.execute("""
            UPDATE evaluations
            SET commit_response = ?, commit_request_digest = ?, status = 'completed'
            WHERE evaluation_id = ?
        """, (
            json.dumps(resp_obj, separators=(",", ":")),
            commit_request_digest,
            eval_id,
        ))
        conn.commit()


def receipt_already_used(receipt_id: str, eval_id: str) -> bool:
    with get_db() as conn:
        row = conn.execute(
            "SELECT evaluation_id FROM used_receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        if not row:
            return False
        return row["evaluation_id"] != eval_id


def get_cached_proposal(dossier_id: str, content_fingerprint: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT proposal_json FROM dossier_cache "
            "WHERE dossier_id = ? AND content_fingerprint = ?",
            (dossier_id, content_fingerprint),
        ).fetchone()
        if row:
            return json.loads(row["proposal_json"])
    return None


def cache_proposal(dossier_id: str, content_fingerprint: str, proposal: Dict[str, Any]) -> None:
    with get_db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO dossier_cache
            (dossier_id, content_fingerprint, proposal_json, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            dossier_id,
            content_fingerprint,
            json.dumps(proposal, separators=(",", ":")),
            time.time(),
        ))
        conn.commit()


def record_evaluation_proposals(
    eval_id: str,
    proposals: List[Dict[str, Any]],
    digests: Dict[str, str],
) -> None:
    with get_db() as conn:
        for proposal in proposals:
            did = proposal["dossierId"]
            conn.execute("""
                INSERT OR REPLACE INTO evaluation_proposals
                (evaluation_id, dossier_id, call_id, action, proposal_digest, proposal_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                eval_id,
                did,
                proposal["callId"],
                proposal["action"],
                digests.get(did, ""),
                json.dumps(proposal, separators=(",", ":")),
            ))
        conn.commit()


def get_evaluation_proposals(eval_id: str) -> Dict[str, Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM evaluation_proposals WHERE evaluation_id = ?", (eval_id,)
        ).fetchall()
        return {row["dossier_id"]: dict(row) for row in rows}


def log_request(eval_id: str, kind: str, body: Dict[str, Any], max_bytes: int = 16 * 1024 * 1024) -> None:
    try:
        text = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        if len(text.encode("utf-8")) > max_bytes:
            return
        with get_db() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO request_log (evaluation_id, kind, body_json, created_at)
                VALUES (?, ?, ?, ?)
            """, (eval_id, kind, text, time.time()))
            conn.commit()
    except Exception:
        # Capture is diagnostic only; never fail a graded request because of it.
        pass
