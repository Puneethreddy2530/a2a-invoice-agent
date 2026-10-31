"""
Cryptographic and Canonical Hashing Utilities for Safe AI Mailroom
Specification: ga5-mailroom-action-gate/v2
"""

import json
import base64
import hashlib
from typing import Dict, Any, List
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

PROFILE = "ga5-mailroom-action-gate/v2"

def canonical_json_bytes(obj: Any) -> bytes:
    """Returns UTF-8 bytes of recursively key-sorted, compact JSON."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def canonical_hash(obj: Any) -> str:
    """Computes lowercase SHA-256 hex digest of canonical JSON bytes."""
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()

def normalize_proposal(p: Dict[str, Any]) -> Dict[str, Any]:
    """
    Keeps exactly dossierId, callId, action, target (null when absent),
    payload, and evidence (sorted strings).
    """
    return {
        "dossierId": p.get("dossierId"),
        "callId": p.get("callId"),
        "action": p.get("action"),
        "target": p.get("target") if p.get("target") is not None else None,
        "payload": p.get("payload", {}),
        "evidence": sorted(p.get("evidence", []))
    }

def compute_proposal_digest(p: Dict[str, Any]) -> str:
    """Computes SHA-256 of normalized proposal."""
    norm = normalize_proposal(p)
    return hashlib.sha256(canonical_json_bytes(norm)).hexdigest()

def load_ed25519_public_key(jwk: Dict[str, Any]) -> ed25519.Ed25519PublicKey:
    """Imports Ed25519 public key from JWK."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"Unsupported key type: {jwk.get('kty')}/{jwk.get('crv')}")
    x_b64 = jwk.get("x", "")
    # Add padding if required
    x_b64 += "=" * ((4 - len(x_b64) % 4) % 4)
    raw_bytes = base64.urlsafe_b64decode(x_b64)
    return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)

def verify_receipt_signature(
    public_key: ed25519.Ed25519PublicKey,
    eval_id: str,
    input_digest: str,
    receipt_data: Dict[str, Any],
    signature_b64: str
) -> bool:
    """
    Verifies receipt signature against canonical JSON format:
    {
      "profile": "ga5-mailroom-action-gate/v2",
      "evaluationId": eval_id,
      "inputDigest": input_digest,
      "receipt": receipt_data (excluding signature)
    }
    """
    try:
        canonical_doc = {
            "profile": PROFILE,
            "evaluationId": eval_id,
            "inputDigest": input_digest,
            "receipt": receipt_data
        }
        msg_bytes = canonical_json_bytes(canonical_doc)
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, msg_bytes)
        return True
    except (InvalidSignature, Exception):
        return False
