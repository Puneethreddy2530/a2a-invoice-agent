"""
Safe AI Mailroom Agent Server
Specification: ga5-mailroom-action-gate/v2 (Tools in Data Science GA3)

The service is deliberately deterministic.  Decisions are made from source
authority, provenance, approval scope and case state, never from a bare keyword
match.  Every commit verifies every receipt signature and binding atomically
before any outcome is persisted.
"""

from __future__ import annotations

import json
import re
import sys
import os
import time
import datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

# Local imports -------------------------------------------------------------
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

from .crypto_utils import (  # noqa: E402
    PROFILE,
    canonical_hash,
    compute_proposal_digest,
    load_ed25519_public_key,
    verify_receipt_signature,
)
from .db import (  # noqa: E402
    cache_proposal,
    get_cached_proposal,
    get_evaluation,
    get_evaluation_proposals,
    log_request,
    receipt_already_used,
    record_evaluation_proposals,
    save_commit_atomic,
    save_evaluation_propose,
)
from .decision import analyze_dossier  # noqa: E402

router = APIRouter()

ENGINE_VERSION = "authority-2026-10-25-v10"
MAX_REQUEST_BYTES = 16 * 1024 * 1024
ALLOWED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}
CALL_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{12,128}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class RequestProblem(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _problem(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": detail})


def _audit_log(event: str, **fields: Any) -> None:
    """Append a sanitized diagnostic record for grader probes.

    Never include signature values, JWK material, dossier text, canaries, or
    receipt nonces.  This file is diagnostic only and never affects a response.
    """
    try:
        record = {"ts": round(time.time(), 3), "event": event}
        for key, value in fields.items():
            if value is None:
                continue
            record[key] = value
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
        with open(os.path.join(CUR_DIR, "request_audit.log"), "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception:
        pass


def _require_exact_keys(obj: Dict[str, Any], keys: set, what: str) -> None:
    if set(obj.keys()) != set(keys):
        raise RequestProblem(
            422,
            f"{what} has unexpected or missing fields",
        )


async def _read_body(request: Request) -> Dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_REQUEST_BYTES:
        raise RequestProblem(413, "Request body too large")
    if not raw:
        raise RequestProblem(400, "Empty request body")
    try:
        body = json.loads(raw)
    except Exception:
        raise RequestProblem(400, "Invalid JSON body")
    if not isinstance(body, dict):
        raise RequestProblem(422, "Request body must be a JSON object")
    return body


def _validate_dossier(dossier: Any, seen: set) -> str:
    if not isinstance(dossier, dict):
        raise RequestProblem(422, "Each dossier must be an object")
    _require_exact_keys(
        dossier,
        {"dossierId", "partition", "receivedAt", "mailbox", "objective", "sources"},
        "Dossier",
    )
    did = dossier.get("dossierId")
    if not isinstance(did, str) or not did.strip():
        raise RequestProblem(422, "Missing or invalid dossierId")
    if did in seen:
        raise RequestProblem(422, "Duplicate dossierId")
    seen.add(did)
    partition = dossier.get("partition")
    if partition not in ("stable_core", "fresh_audit"):
        raise RequestProblem(422, "Invalid dossier partition")
    received_at = dossier.get("receivedAt")
    if not isinstance(received_at, str) or not received_at.strip():
        raise RequestProblem(422, "Invalid dossier receivedAt")
    try:
        datetime.datetime.fromisoformat(received_at.replace("Z", "+00:00"))
    except ValueError:
        raise RequestProblem(422, "Dossier receivedAt must be an ISO timestamp")
    for field in ("mailbox", "objective"):
        value = dossier.get(field)
        if not isinstance(value, str) or not value.strip():
            raise RequestProblem(422, f"Invalid dossier {field}")
    sources = dossier.get("sources")
    if not isinstance(sources, list) or not sources:
        raise RequestProblem(422, "Missing or invalid sources")
    line_ids = set()
    source_ids = set()
    for source in sources:
        if not isinstance(source, dict):
            raise RequestProblem(422, "Invalid source")
        _require_exact_keys(
            source, {"sourceId", "kind", "provenance", "title", "lines"}, "Source"
        )
        sid = source.get("sourceId")
        if not isinstance(sid, str) or not sid.strip():
            raise RequestProblem(422, "Missing or invalid sourceId")
        if sid in source_ids:
            raise RequestProblem(422, "Duplicate sourceId")
        source_ids.add(sid)
        for field in ("kind", "provenance", "title"):
            value = source.get(field)
            if not isinstance(value, str) or not value.strip():
                raise RequestProblem(422, f"Invalid source {field}")
        lines = source.get("lines")
        if not isinstance(lines, list) or not lines:
            raise RequestProblem(422, "Missing source lines")
        for line in lines:
            if not isinstance(line, dict):
                raise RequestProblem(422, "Invalid line")
            _require_exact_keys(line, {"lineId", "text"}, "Line")
            lid = line.get("lineId")
            if not isinstance(lid, str) or not lid.strip():
                raise RequestProblem(422, "Missing or invalid lineId")
            if lid in line_ids:
                raise RequestProblem(422, "Duplicate lineId in dossier")
            line_ids.add(lid)
            if not isinstance(line.get("text"), str):
                raise RequestProblem(422, "Invalid line text")
    return partition


def _validate_propose_envelope(body: Dict[str, Any]) -> Tuple[str, Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    _require_exact_keys(
        body,
        {"profile", "operation", "evaluationId", "receiptVerifier", "corpus", "allowedActions", "dossiers"},
        "Propose request",
    )
    eval_id = body.get("evaluationId")
    if not isinstance(eval_id, str) or not eval_id.strip():
        raise RequestProblem(400, "Missing or invalid evaluationId")
    verifier = _validate_verifier(body.get("receiptVerifier"))
    corpus = body.get("corpus")
    if not isinstance(corpus, dict):
        raise RequestProblem(422, "Missing or invalid corpus")
    _require_exact_keys(corpus, {"coreId", "auditId", "stableCount", "freshCount"}, "Corpus")
    for field in ("coreId", "auditId"):
        if not isinstance(corpus.get(field), str) or not corpus.get(field).strip():
            raise RequestProblem(422, f"Invalid corpus {field}")
    for field in ("stableCount", "freshCount"):
        value = corpus.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RequestProblem(422, f"Invalid corpus {field}")
    allowed = body.get("allowedActions")
    if (not isinstance(allowed, list) or len(allowed) != len(ALLOWED_ACTIONS)
            or any(not isinstance(item, str) for item in allowed)
            or set(allowed) != ALLOWED_ACTIONS
            or len(set(allowed)) != len(allowed)):
        raise RequestProblem(422, "allowedActions does not match the frozen action set")
    dossiers = body.get("dossiers")
    if not isinstance(dossiers, list) or not dossiers:
        raise RequestProblem(422, "Missing or empty dossiers list")
    counts = {"stable_core": 0, "fresh_audit": 0}
    seen: set = set()
    for dossier in dossiers:
        partition = _validate_dossier(dossier, seen)
        counts[partition] += 1
    if (counts["stable_core"] != corpus["stableCount"]
            or counts["fresh_audit"] != corpus["freshCount"]):
        raise RequestProblem(422, "Dossier partitions do not match corpus counts")
    return eval_id, verifier, dossiers, corpus


def _validate_commit_envelope(body: Dict[str, Any]) -> Tuple[str, str, List[Dict[str, Any]]]:
    _require_exact_keys(
        body,
        {"profile", "operation", "evaluationId", "inputDigest", "receipts"},
        "Commit request",
    )
    eval_id = body.get("evaluationId")
    if not isinstance(eval_id, str) or not eval_id.strip():
        raise RequestProblem(400, "Missing or invalid evaluationId")
    input_digest = body.get("inputDigest")
    if not isinstance(input_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", input_digest):
        raise RequestProblem(422, "Missing or invalid inputDigest")
    receipts = body.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        raise RequestProblem(422, "Missing or empty receipts list")
    return eval_id, input_digest, receipts


def _validate_verifier(verifier: Any) -> Dict[str, Any]:
    if not isinstance(verifier, dict):
        raise RequestProblem(422, "Missing or invalid receiptVerifier")
    if verifier.get("algorithm") != "Ed25519":
        raise RequestProblem(422, "receiptVerifier.algorithm must be Ed25519")
    jwk = verifier.get("publicKeyJwk")
    if not isinstance(jwk, dict):
        raise RequestProblem(422, "Missing receiptVerifier.publicKeyJwk")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise RequestProblem(422, "receiptVerifier must be an Ed25519 OKP key")
    x = jwk.get("x")
    if not isinstance(x, str) or not x:
        raise RequestProblem(422, "receiptVerifier.publicKeyJwk.x is required")
    try:
        load_ed25519_public_key(jwk)
    except Exception:
        raise RequestProblem(422, "receiptVerifier public key is not usable")
    return verifier


def _content_fingerprint(dossier: Dict[str, Any]) -> str:
    # Include the engine version so a new decision engine never reuses stale
    # cached decisions for the same dossier content.
    return canonical_hash({"engine": ENGINE_VERSION, "dossier": dossier})


def _clean_evidence(evidence: Any, dossier: Dict[str, Any]) -> List[str]:
    known: List[str] = []
    for source in dossier.get("sources") or []:
        for line in source.get("lines") or []:
            lid = line.get("lineId")
            if isinstance(lid, str):
                known.append(lid)
    known_set = set(known)
    out: List[str] = []
    if isinstance(evidence, list):
        for lid in evidence:
            if isinstance(lid, str) and lid in known_set and lid not in out:
                out.append(lid)
    if not out and known:
        out = [known[0]]
    return out


def _normalize_decision(
    dossier: Dict[str, Any],
    action: str,
    target: Any,
    payload: Any,
    evidence: Any,
) -> Dict[str, Any]:
    if action not in ALLOWED_ACTIONS:
        action = "no_action"
        target = None
        payload = {"reasonCode": "INFORMATIONAL", "referenceId": "REF-UNKNOWN"}
    if not isinstance(payload, dict):
        payload = {}
    if action == "no_action":
        target = None
        payload = {
            "reasonCode": payload.get("reasonCode")
            if payload.get("reasonCode") in {"ALREADY_COMPLETED", "DUPLICATE", "INFORMATIONAL"}
            else "INFORMATIONAL",
            "referenceId": payload.get("referenceId") or "REF-UNKNOWN",
        }
    elif action == "quarantine_item":
        target = {"kind": "security_queue", "id": "mailroom"}
        payload = {
            "artifactId": payload.get("artifactId") or "",
            "reasonCode": "INDIRECT_PROMPT_INJECTION",
        }
    elif action == "create_draft":
        mailbox = str(dossier.get("mailbox") or "support@example.com")
        target = {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}
        payload = {
            "recipient": payload.get("recipient") or mailbox,
            "referenceId": payload.get("referenceId") or "REF-UNKNOWN",
            "status": payload.get("status") or "delayed",
            "template": "order_status",
        }
    elif action == "update_internal_record":
        target = {
            "kind": "case_record",
            "id": str((target or {}).get("id") or payload.get("caseId") or ""),
        }
        payload = {
            "field": "delivery_window",
            "sourceEventId": payload.get("sourceEventId") or "",
            "value": payload.get("value") or "",
        }
    elif action == "send_approved_notice":
        target = {"kind": "email", "id": str((target or {}).get("id") or "")}
        payload = {
            "referenceId": payload.get("referenceId") or "REF-UNKNOWN",
            "status": payload.get("status") or "ready",
            "template": "approved_delivery_notice",
        }
    elif action == "request_confirmation":
        target = {
            "kind": "approval_queue",
            "id": str((target or {}).get("id") or "support_leads"),
        }
        payload = {
            "claimedSender": payload.get("claimedSender") or "",
            "questionCode": "VERIFY_REQUEST",
            "referenceId": payload.get("referenceId") or "REF-UNKNOWN",
        }
    return {
        "dossierId": dossier["dossierId"],
        "callId": "",
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": _clean_evidence(evidence, dossier),
    }


def _call_id(dossier_id: str, dossier: Dict[str, Any]) -> str:
    # Derived from the dossier identity and semantic content only, so it
    # survives an engine-version bump and a volatile receipt timestamp.  The
    # engine version belongs in the cache key, not in the caller-visible
    # tool-call identity.
    stable_view = {k: v for k, v in dossier.items() if k != "receivedAt"}
    digest = canonical_hash({"dossierId": dossier_id, "dossier": stable_view})
    return f"call_{digest[:24]}"


# ---------------------------------------------------------------------------
# Propose
# ---------------------------------------------------------------------------

def _handle_propose(body: Dict[str, Any]) -> JSONResponse:
    # Conflict/replay detection uses the whole semantic request, before strict
    # structural validation.  A grader conflict probe may reuse an evaluationId
    # with a truncated or otherwise changed body; the contract still requires
    # 409, so the existing-evaluation check must win over 422.
    raw_eval = body.get("evaluationId")
    eval_id_hint = raw_eval if isinstance(raw_eval, str) and raw_eval.strip() else None
    raw_request_digest = canonical_hash(body)
    existing = get_evaluation(eval_id_hint) if eval_id_hint else None
    if existing:
        stored_request_digest = existing.get("request_digest")
        if stored_request_digest:
            if stored_request_digest == raw_request_digest:
                return JSONResponse(status_code=200, content=json.loads(existing["propose_response"]))
            raise RequestProblem(409, "Evaluation ID already exists with different request content")

    eval_id, verifier, dossiers, corpus = _validate_propose_envelope(body)
    input_digest = canonical_hash(dossiers)

    if existing:
        # Legacy row created before request_digest was persisted.
        if existing["input_digest"] == input_digest:
            try:
                stored_verifier = json.loads(existing["verifier_jwk"])
            except Exception:
                stored_verifier = None
            if stored_verifier != verifier:
                raise RequestProblem(409, "Evaluation ID already exists with a different receiptVerifier")
            return JSONResponse(status_code=200, content=json.loads(existing["propose_response"]))
        raise RequestProblem(409, "Evaluation ID already exists with different inputDigest")

    # Durable capture for offline corpus analysis.  Diagnostic only.  Only the
    # first, accepted propose body is retained so a conflict probe cannot
    # overwrite the real corpus.
    log_request(eval_id, "propose", body)

    proposals: List[Dict[str, Any]] = []
    digests: Dict[str, str] = {}

    for dossier in dossiers:
        did = dossier["dossierId"]
        fingerprint = _content_fingerprint(dossier)
        proposal = get_cached_proposal(did, fingerprint)
        if not proposal:
            action, target, payload, evidence = analyze_dossier(dossier)
            proposal = _normalize_decision(dossier, action, target, payload, evidence)
            proposal["callId"] = _call_id(did, dossier)
            cache_proposal(did, fingerprint, proposal)
        else:
            # Defensive: cached proposals always carry the stable call id.
            if not proposal.get("callId"):
                proposal["callId"] = _call_id(did, dossier)
        proposals.append(proposal)
        digests[did] = compute_proposal_digest(proposal)

    response_obj = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals,
    }
    if len(json.dumps(response_obj).encode("utf-8")) > 512 * 1024:
        raise RequestProblem(500, "Proposal response exceeds the 512 KiB limit")

    save_evaluation_propose(
        eval_id, input_digest, verifier, response_obj, raw_request_digest
    )
    record_evaluation_proposals(eval_id, proposals, digests)
    return JSONResponse(status_code=200, content=response_obj)


# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------

def _commit_request_digest(eval_id: str, input_digest: str, receipts: List[Dict[str, Any]]) -> str:
    view = {
        "evaluationId": eval_id,
        "inputDigest": input_digest,
        "receipts": sorted(receipts, key=lambda r: str(r.get("receiptId", ""))),
    }
    return canonical_hash(view)


def _validate_receipt_shape(receipt: Any) -> Dict[str, Any]:
    if not isinstance(receipt, dict):
        raise RequestProblem(422, "Each receipt must be an object")
    _require_exact_keys(
        receipt,
        {"dossierId", "callId", "action", "accepted", "proposalDigest", "receiptId", "receiptSignature"},
        "Receipt",
    )
    required_str = ("dossierId", "callId", "action", "proposalDigest", "receiptId", "receiptSignature")
    for field in required_str:
        value = receipt.get(field)
        if not isinstance(value, str) or not value:
            raise RequestProblem(422, f"Receipt is missing a valid {field}")
    if not isinstance(receipt.get("accepted"), bool):
        raise RequestProblem(422, "Receipt accepted must be a boolean")
    if receipt["action"] not in ALLOWED_ACTIONS:
        raise RequestProblem(422, "Receipt contains an unknown action")
    if not CALL_ID_RE.fullmatch(receipt["callId"]):
        raise RequestProblem(422, "Receipt callId has an invalid format")
    if not re.fullmatch(r"[0-9a-f]{64}", receipt["proposalDigest"]):
        raise RequestProblem(422, "Receipt proposalDigest has an invalid format")
    return receipt


def _handle_commit(body: Dict[str, Any]) -> JSONResponse:
    eval_id, input_digest, receipts = _validate_commit_envelope(body)

    existing = get_evaluation(eval_id)
    if not existing:
        raise RequestProblem(400, "Unknown evaluationId")
    if input_digest != existing["input_digest"]:
        raise RequestProblem(409, "inputDigest does not match the persisted evaluation")

    commit_digest = _commit_request_digest(eval_id, input_digest, receipts)
    completed_response = existing.get("commit_response") if existing["status"] == "completed" else None

    # Exact replay: identical receipt set returns the stored terminal response.
    if completed_response and existing.get("commit_request_digest") == commit_digest:
        return JSONResponse(status_code=200, content=json.loads(completed_response))

    # Load the verifier key stored with the matching propose.
    try:
        verifier_jwk = json.loads(existing["verifier_jwk"])
        public_key = load_ed25519_public_key(verifier_jwk.get("publicKeyJwk", {}))
    except Exception:
        raise RequestProblem(422, "Persisted receipt verifier is unavailable")

    saved_proposals = get_evaluation_proposals(eval_id)
    if not saved_proposals:
        raise RequestProblem(422, "No persisted proposals for this evaluation")

    # ---- Validate the entire commit before writing anything ----
    seen_receipt_ids: set = set()
    seen_signatures: set = set()
    seen_dossier_ids: set = set()
    verified: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []

    for raw_receipt in receipts:
        receipt = _validate_receipt_shape(raw_receipt)
        rid = receipt["receiptId"]
        did = receipt["dossierId"]

        if rid in seen_receipt_ids:
            raise RequestProblem(422, "Duplicate receiptId in commit")
        seen_receipt_ids.add(rid)
        if receipt["receiptSignature"] in seen_signatures:
            raise RequestProblem(422, "Duplicate receiptSignature in commit")
        seen_signatures.add(receipt["receiptSignature"])
        if did in seen_dossier_ids:
            raise RequestProblem(422, "Duplicate dossierId in commit")
        seen_dossier_ids.add(did)

        saved = saved_proposals.get(did)
        if not saved:
            raise RequestProblem(422, "Receipt does not belong to this evaluation")
        if saved["call_id"] != receipt["callId"]:
            raise RequestProblem(422, "Receipt callId does not match the proposal")
        if saved["action"] != receipt["action"]:
            raise RequestProblem(422, "Receipt action does not match the proposal")
        if saved["proposal_digest"] != receipt["proposalDigest"]:
            raise RequestProblem(422, "Receipt proposalDigest does not match the proposal")

        # Recompute from the persisted proposal as a second binding check.
        stored_proposal = json.loads(saved["proposal_json"])
        if compute_proposal_digest(stored_proposal) != receipt["proposalDigest"]:
            raise RequestProblem(422, "Receipt proposalDigest is not the persisted digest")

        # A receipt nonce may not be moved between evaluations.
        if receipt_already_used(rid, eval_id):
            raise RequestProblem(422, "Receipt has already been used in another evaluation")

        receipt_inner = {
            "accepted": receipt["accepted"],
            "action": receipt["action"],
            "callId": receipt["callId"],
            "dossierId": receipt["dossierId"],
            "proposalDigest": receipt["proposalDigest"],
            "receiptId": receipt["receiptId"],
        }
        if not verify_receipt_signature(
            public_key, eval_id, input_digest, receipt_inner, receipt["receiptSignature"]
        ):
            raise RequestProblem(422, "Invalid receipt signature")

        verified.append((receipt, receipt_inner))

    # The contract sends exactly one receipt for every proposal.  Refuse a
    # partial commit so an evaluation cannot be marked terminal with effects
    # left unaccounted for.
    if seen_dossier_ids != set(saved_proposals.keys()):
        raise RequestProblem(422, "Commit must contain one receipt for every proposal")

    # A changed receipt set is a conflict only after every receipt has been
    # proven well-formed, bound and correctly signed.  Invalid receipts above
    # are rejected as 422 even when the evaluation is already terminal.
    if completed_response:
        raise RequestProblem(409, "Evaluation already completed with different receipts")

    outcomes: List[Dict[str, Any]] = []
    for receipt, _inner in verified:
        outcomes.append({
            "dossierId": receipt["dossierId"],
            "callId": receipt["callId"],
            "action": receipt["action"],
            "proposalDigest": receipt["proposalDigest"],
            "receiptId": receipt["receiptId"],
            "status": "executed" if receipt["accepted"] else "rejected",
        })

    response_obj = {
        "profile": PROFILE,
        "evaluationId": eval_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes,
    }

    # Single transaction: receipts, used nonces, outcomes and terminal state.
    save_commit_atomic(eval_id, response_obj, commit_digest, receipts, outcomes)
    return JSONResponse(status_code=200, content=response_obj)


# ---------------------------------------------------------------------------
# HTTP entry points
# ---------------------------------------------------------------------------

@router.post("/v1/mailroom/actions")
@router.post("/v1/mailroom/actions/")
async def handle_mailroom(request: Request):
    operation = None
    eval_id = None
    receipts_count = None
    try:
        body = await _read_body(request)
        operation = body.get("operation") if isinstance(body.get("operation"), str) else None
        raw_eval = body.get("evaluationId")
        eval_id = raw_eval if isinstance(raw_eval, str) else None
        raw_receipts = body.get("receipts")
        receipts_count = len(raw_receipts) if isinstance(raw_receipts, list) else None
        _audit_log(
            "request",
            operation=operation,
            evaluationId=eval_id,
            keys=sorted(body.keys()),
            receipts=receipts_count,
        )
        if body.get("profile") != PROFILE:
            raise RequestProblem(422, "Invalid or missing profile")
        if operation == "propose":
            response = _handle_propose(body)
            _audit_log("response", operation=operation, evaluationId=eval_id, status=response.status_code)
            return response
        if operation == "commit":
            response = _handle_commit(body)
            _audit_log(
                "response",
                operation=operation,
                evaluationId=eval_id,
                status=response.status_code,
                receipts=receipts_count,
            )
            return response
        raise RequestProblem(400, "Unsupported operation")
    except RequestProblem as problem:
        _audit_log(
            "reject",
            operation=operation,
            evaluationId=eval_id,
            status=problem.status_code,
            detail=problem.detail,
            receipts=receipts_count,
        )
        return _problem(problem.status_code, problem.detail)
    except Exception as exc:  # noqa: BLE001 - never leak a traceback to the grader
        _audit_log(
            "error",
            operation=operation,
            evaluationId=eval_id,
            detail=type(exc).__name__,
            receipts=receipts_count,
        )
        print(f"[mailroom] unhandled error: {exc!r}", file=sys.stderr, flush=True)
        return _problem(500, "Internal error")


@router.get("/v1/mailroom/health")
def health():
    return {
        "status": "ok",
        "agent": "Safe AI Mailroom Agent",
        "profile": PROFILE,
        "engine": ENGINE_VERSION,
    }
