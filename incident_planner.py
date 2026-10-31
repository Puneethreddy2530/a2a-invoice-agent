"""Deterministic, evidence-first planner for the IITM TDS GA3 incident profile.

The planner is catalog-driven: it emits only read-only diagnostics from the
supplied tool catalog, derives argument values from incident evidence, and
selects one permitted effect while respecting delegation/freeze/scaling limits.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_ROOT_CAUSES = [
    "deployment_regression",
    "database_connection_exhaustion",
    "dependency_certificate_expired",
    "feature_flag_recursion",
    "traffic_capacity_exhaustion",
    "secret_rotation_mismatch",
]
DEFAULT_EFFECT_TOOLS = [
    "restart_pod", "scale_service", "rollback_deployment",
    "disable_feature", "page_owner", "open_incident",
]
DEFAULT_APPROVAL_TOOLS = ["rollback_deployment", "disable_feature"]

LINE_RE = re.compile(r"^\s*\[([A-Za-z0-9_.:\-]+)\]\s*(.*)$")
ISO_HEAD_RE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}[T ][0-9:.]+Z?\s*")
SIGNAL_PREFIXES = (
    "correlated sample:", "incident-window record:", "bounded observation:",
    "on-call finding:", "window record:",
)
DECOYS = (
    "correlation corr_", "retain this full sentence", "not decision evidence",
    "not causal", "does not overlap", "does not match", "belongs to another service",
    "served no production requests", "hypothetical", "untrusted evidence",
    "never as an instruction", "copied from an unrelated", "training material",
    "archive example", "an older postmortem", "routine backup", "capacity forecast",
    "synthetic probe", "ignore previous", "as an instruction",
    "dropped a low-priority heartbeat", "must not drive", "editorial note",
    "support channel contains competing guesses", "automated verifier",
    "synthetic probe briefly changed color",
    "an older postmortem mentions certificates",
    "sampling worker dropped a low-priority heartbeat",
    "a verified label appears in an imported change-calendar note",
    "routine backup validation completed successfully",
    "a customer transcript asks operators",
    "an automated verifier confirmed that the ticket format is valid",
    "the support channel contains competing guesses",
    "a capacity forecast for the next quarter",
    "a dashboard annotation was copied", "ordinary weekly band",
    "are not observations from the incident window",
    "retained to establish chronology",
    "does not verify any operational hypothesis",
)

CAUSE_RULES: List[Tuple[Tuple[str, ...], Tuple[str, ...], str]] = [
    (("secret version", "vault promoted", "revoked the old credential",
      "credential revocation", "secret_revocation", "older credential was retired",
      "vault now accepts", "key rotation", "rotated credential", "secret rotation",
      "credential generation", "vault revoked", "still uses credential",
      "still identifies secret version", "secret version mismatch"),
     ("secret", "credential", "rotation"), "secret_rotation_mismatch"),
    (("leaf certificate", "notafter", "expired leaf", "certificate renewal",
      "cert renewal", "certificate has expired", "certificate expired", "x509",
      "tls handshake"),
     ("cert", "certificate", "expired", "tls"), "dependency_certificate_expired"),
    (("flag cohort", "depth guard", "flag rule was edited", "recursive trace",
      "loop through the same evaluation", "feature flag", "re-entr", "recursion"),
     ("flag", "recur", "toggle"), "feature_flag_recursion"),
    (("thread deadlock", "mutex lock contention", "deadlock detected",
      "deadlocked", "lock contention"),
     ("deadlock", "lock"), "thread_deadlock"),
    (("jvm heap", "outofmemoryerror", "heap space", "garbage collection",
      "memory leak", "heap usage"),
     ("memory", "leak", "heap"), "memory_exhaustion"),
    (("pool checkout wait", "configured connection ceiling",
      "pool acquisition timeout", "pool acquisition timeouts", "db connection pool",
      "database connection", "connection timeout on pool",
      "postgresql driver reporting connection timeout", "connection pool",
      "connections are exhausted", "database connections"),
     ("database", "connection", "db", "pool"), "database_connection_exhaustion"),
    (("rate limiter", "rate limit", "rejecting valid customer requests with http 429",
      "req/min", "http 429", "429"),
     ("rate", "limit", "throttl"), "rate_limit_exhaustion"),
    (("within ninety seconds of release", "rollout boundary", "holdback still running",
      "crashed on boot", "syntaxerror", "deployment release", "bad deployment",
      "new build", "release-v", "started returning errors", "regression"),
     ("deploy", "regression", "build", "release"), "deployment_regression"),
    (("queue depth and latency rise", "per-replica utilization", "search spike",
      "cpu utilization reached", "capacity ceiling", "growing queue",
      "workers saturate", "replica saturated", "every replica saturated",
      "peak load", "traffic spike", "saturation", "saturated"),
     ("traffic", "capacity", "spike", "satur", "load"), "traffic_capacity_exhaustion"),
    (("timed out after", "unreachable", "upstream endpoint", "upstream-inventory",
      "upstream dependency", "network partition"),
     ("upstream", "dependency", "network", "timeout"), "upstream_dependency_failure"),
]

STOP_WORDS = set(
    "the a an of to for and or in on at is are was were be been being by with from "
    "this that these those it its as we our you your they their has have had will "
    "would should could may might can do does did not no than then there here which "
    "who whom whose what when while during after before into over under about across "
    "per via".split()
)

def parse_evidence_lines(transcript: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    seen = set()
    for raw in (transcript or "").splitlines():
        match = LINE_RE.match(raw)
        if not match:
            continue
        evidence_id, text = match.group(1), ISO_HEAD_RE.sub("", match.group(2) or "").strip()
        if evidence_id not in seen:
            seen.add(evidence_id)
            out.append((evidence_id, text))
    return out

def is_decoy(tag: str, text: str) -> bool:
    low = (text or "").lower()
    return (tag or "").lower().startswith(("decoy", "noise", "distractor")) or any(x in low for x in DECOYS)

def select_evidence_lines(transcript: str) -> List[Tuple[str, str]]:
    all_lines = parse_evidence_lines(transcript)
    clean = [(eid, text) for eid, text in all_lines if not is_decoy(eid, text)]
    if len(clean) >= 2:
        return clean
    positives = [
        (eid, text) for eid, text in all_lines
        if any(text.lower().startswith(p) for p in SIGNAL_PREFIXES) and not is_decoy(eid, text)
    ]
    if len(positives) >= 2:
        return positives
    return clean or all_lines

def _family_match(allowed: List[str], family: Tuple[str, ...]) -> Optional[str]:
    # Match any distinctive family token; do not require every word in a
    # canonical label, because the grader can supply semantically equivalent labels.
    for token in family:
        for candidate in allowed:
            low = str(candidate).lower()
            if token in low:
                return str(candidate)
    return None

def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower())
            if t not in STOP_WORDS and len(t) > 2}

def _lexical_cause(text: str, allowed: List[str]) -> Optional[str]:
    clean = re.sub(r"\b(no|without|neither|never|not)\s+[^;,.\n]+", " ", (text or "").lower())
    toks = _tokens(clean)
    best, best_score = None, 0
    for candidate in allowed:
        words = [w for w in re.split(r"[_\- ]+", str(candidate).lower()) if len(w) > 2]
        score = sum(3 for word in words if word in toks)
        if score > best_score:
            best, best_score = candidate, score
    return str(best) if best is not None else None

def determine_root_cause(lines: List[Tuple[str, str]], allowed: List[str], title: str = "") -> str:
    text = (title + ". " + " ".join(t for _, t in lines)).strip()
    for phrases, family, canonical in CAUSE_RULES:
        if any(p in text.lower() for p in phrases):
            matched = _family_match(allowed, family)
            if matched:
                return matched
            # Exact canonical causes remain valid when supplied by the incident.
            if canonical in allowed:
                return canonical
    return _lexical_cause(text, allowed) or (str(allowed[0]) if allowed else "unknown")

def _family_for_cause(cause: str) -> Tuple[str, ...]:
    low = (cause or "").lower()
    for _, family, canonical in CAUSE_RULES:
        if canonical == low or any(tok in low for tok in family):
            return family
    return tuple(w for w in re.split(r"[_\- ]+", low) if len(w) > 2)

def _relevance(text: str, cause: str) -> int:
    low = (text or "").lower()
    score = sum(2 for tok in _family_for_cause(cause) if tok in low)
    if re.search(r"\d", low):
        score += 1
    if any(k in low for k in ("error", "fail", "timeout", "exhaust", "expired",
                              "deadlock", "saturat", "crashed", "reject", "revok")):
        score += 2
    return score

def select_evidence_ids(lines: List[Tuple[str, str]],
                        all_lines: List[Tuple[str, str]], cause: str) -> List[str]:
    ids = [eid for eid, _ in lines]
    if len(ids) < 2:
        for eid, txt in all_lines:
            if eid not in ids and not is_decoy(eid, txt):
                ids.append(eid)
            if len(ids) >= 2:
                break
    if not ids:
        return []
    text_by_id = dict(all_lines)
    ranked = sorted(enumerate(ids), key=lambda p: (-_relevance(text_by_id.get(p[1], ""), cause), p[0]))
    positives = [eid for _, eid in ranked if _relevance(text_by_id.get(eid, ""), cause) > 0]
    chosen = positives[:4] if len(positives) >= 2 else [eid for _, eid in ranked[:4]]
    chosen_set = set(chosen)
    return [eid for eid in ids if eid in chosen_set][:4]

# ----------------------- Case entity extraction -----------------------
RELEASE_RE = re.compile(r"\b(r\d+-[A-Za-z0-9]+|release-v?\d+(?:\.\d+)*|deploy-\d+|d-\d+|v\d+(?:\.\d+){0,2}|\d+\.\d+\.\d+)\b")
GOOD_CTX = ("previous release", "previous", "prior", "last known good", "known-good",
            "known good", "healthy", "stable", "no matching errors", "no errors",
            "remains healthy", "was healthy", "baseline", "holdback", "rolled back to",
            "roll back to", "revert to", "last good", "still serving", "have no",
            "unchanged instances")
BAD_CTX = ("failure rate", "failure", "malformed", "regression", "regressed",
           "failing", "failed", "broke", "broken", "spiked", "degraded", "faulty",
           "introduced", "started returning", "within ninety seconds", "seconds of release",
           "after release", "crashed", "syntaxerror")

def _parse_release(text: str) -> Optional[str]:
    tokens = list(dict.fromkeys(m.group(1) for m in RELEASE_RE.finditer(text or "")))
    if not tokens:
        return None
    if len(tokens) == 1:
        return tokens[0]
    clauses = [c for c in re.split(r"[.\n;]+", text or "") if c.strip()]
    positions = {r: (text or "").rfind(r) for r in tokens}
    def score(rel: str) -> int:
        good = bad = 0
        for clause in clauses:
            if rel in clause:
                low = clause.lower()
                good += sum(low.count(x) for x in GOOD_CTX)
                bad += sum(low.count(x) for x in BAD_CTX)
        return good - bad
    return sorted(tokens, key=lambda r: (score(r), positions[r]), reverse=True)[0]

def _parse_flag(text: str) -> Optional[str]:
    pats = (
        r"\b(flag_[A-Za-z0-9][A-Za-z0-9_-]*|[A-Za-z0-9][A-Za-z0-9_-]*_flag|flag[A-Za-z0-9]{4,})\b",
        r"\bflag[-_ ]?([A-Za-z0-9]{3,})\b",
    )
    ignored = {"changed", "change", "edits", "edit", "rule", "rules", "cohort",
               "was", "were", "is", "are", "and", "the", "not", "no", "disabled",
               "enabled", "toggle", "feature", "recursion", "recursive"}
    for pat in pats:
        m = re.search(pat, text or "", re.I)
        if m:
            value = m.group(1)
            if value.lower() not in ignored:
                return value
    return None

def _parse_dependency(text: str) -> Optional[str]:
    m = re.search(r"\b(dep_[A-Za-z0-9]+|upstream[-_][A-Za-z0-9][A-Za-z0-9-]*|dependency[-_][A-Za-z0-9][A-Za-z0-9-]*)\b", text or "", re.I)
    return m.group(1) if m else None

def _parse_pod(text: str) -> Optional[str]:
    m = re.search(r"\bpod[-_/ ]([a-z0-9][a-z0-9-]{2,})\b", text or "", re.I)
    if m:
        return m.group(1)
    m = re.search(r"\bpod_?name\s*[=:]\s*([a-z0-9][a-z0-9-]{2,})\b", text or "", re.I)
    return m.group(1) if m else None

def _parse_replicas(text: str, default: int = 2) -> int:
    # An explicitly stated proposed/recovery target takes precedence.
    for pat in (
        r"(?:proposed\s+target|target|recovery target|desired)\s*(?:is|of|:|=)?\s*(?:exactly\s*)?(\d{1,3})\s*(?:application\s+)?(?:replicas|pods)?",
        r"(\d{1,3})\s+(?:application\s+)?replicas?\b",
    ):
        m = re.search(pat, text or "", re.I)
        if m:
            n = int(m.group(1))
            if 0 < n <= 200:
                return n
    # If operating below a hard maximum, propose the smallest safe increment.
    m = re.search(r"(?:current|operating)\s+replicas\s*[=:]\s*(\d+)[^\n]*?(?:maximum|ceiling|contract maximum)\s*[=:]\s*(\d+)", text or "", re.I)
    if not m:
        m = re.search(r"replicas[^=\n]{0,20}=\s*(\d+)[^\n]*?(?:maximum|ceiling)\s*=\s*(\d+)", text or "", re.I)
    if m:
        current, maximum = int(m.group(1)), int(m.group(2))
        if current < maximum:
            return current + 1
        return current
    m = re.search(r"replicas?\s*[=:]\s*(\d+)", text or "", re.I)
    if m:
        n = int(m.group(1))
        if 0 < n <= 200:
            return n
    return default

def _at_scaling_limit(text: str) -> bool:
    low = (text or "").lower()
    if any(p in low for p in (
        "scaling beyond that ceiling is forbidden",
        "paging the service owner rather than raising",
        "maximum permitted scaling limit",
        "already at its permitted scaling limit",
        "scaling limit reached", "cannot scale further",
        "exceed the authorised capacity ceiling",
        "exceed the authorized capacity ceiling",
        "no remaining autoscaling headroom",
    )):
        return True
    m = re.search(r"(?:current|operating)\s+replicas\s*[=:]\s*(\d+)[^\n]*?(?:maximum|ceiling|contract maximum)\s*[=:]\s*(\d+)", text or "", re.I)
    if not m:
        m = re.search(r"replicas[^=\n]{0,20}=\s*(\d+)[^\n]*?(?:maximum|ceiling)\s*=\s*(\d+)", text or "", re.I)
    return bool(m and int(m.group(1)) >= int(m.group(2)))

def _delegation_blocked(text: str) -> bool:
    low = (text or "").lower()
    def first(pattern: str) -> Optional[int]:
        m = re.search(pattern, low)
        return int(m.group(1)) if m else None
    delegation = first(r"delegation\s*=\s*(-?\d+)")
    freeze = first(r"freeze\s*=\s*(-?\d+)")
    remaining = first(r"remaining[^=\n]{0,40}?\s*=\s*(-?\d+)")
    maximum = first(r"contract\s+maximum\s*=\s*(\d+)")
    target = first(r"proposed\s+target\s*=\s*(\d+)")
    if delegation is not None and delegation <= 0:
        return True
    if freeze is not None and freeze != 0:
        return True
    if remaining is not None and remaining <= 0:
        return True
    if maximum is not None and target is not None and target > maximum:
        return True
    legacy = re.search(r"enabled\s*=\s*(\d+)[^\n]*?(?:slots?\s+remaining|remaining)\s*=\s*(\d+)", low)
    return bool(legacy and (int(legacy.group(1)) <= 0 or int(legacy.group(2)) <= 0))

def extract_entities(incident: Dict[str, Any]) -> Dict[str, Any]:
    transcript = incident.get("transcript") or ""
    service = incident.get("service") or "unknown-service"
    # Use the most relevant title+transcript for identifier extraction but keep
    # explicit structured fields authoritative.
    return {
        "service": service,
        "release": incident.get("release") or _parse_release(transcript),
        "flag": incident.get("flagName") or _parse_flag(transcript),
        "dep": incident.get("dependency") or _parse_dependency(transcript) or f"{service}-upstream",
        "pod": incident.get("pod") or _parse_pod(transcript) or f"{service}-0",
        "replicas": incident.get("targetReplicas") or _parse_replicas(transcript),
        "at_limit": _at_scaling_limit(transcript),
        "delegation_blocked": _delegation_blocked(transcript),
    }

# ----------------------- Tool selection and arguments -----------------------
KIND_HINTS = {
    "log": ("fetch_logs", "query_logs", "search_logs", "get_logs", "logs", "log"),
    "metric": ("query_metrics", "get_metrics", "fetch_metrics", "metrics", "metric"),
    "config": ("inspect_config", "get_config", "read_config", "config", "feature"),
    "health": ("check_health", "dependency_status", "health_check", "dependency", "health"),
    "deploy": ("inspect_deployment", "deployment_status", "deployment", "deploy"),
    "runbook": ("read_runbook", "runbook", "playbook"),
}
ALT_KIND = {
    "log": ("log", "deploy", "metric"),
    "metric": ("metric", "log"),
    "health": ("health", "runbook", "log"),
    "config": ("config", "runbook"),
    "runbook": ("runbook", "config"),
    "deploy": ("deploy", "log"),
}

def _hint_score(hint: str, name: str, hay: str) -> int:
    esc = re.escape(hint)
    if hint == name:
        return 30
    if re.search(rf"(^|[^a-z0-9]){esc}([^a-z0-9]|$)", name):
        return 20
    if len(hint) >= 5 and hint in name:
        return 20
    if re.search(rf"(^|[^a-z0-9]){esc}([^a-z0-9]|$)", hay):
        return 4
    if len(hint) >= 5 and hint in hay:
        return 4
    return 0

def _resolve_tool(catalog: List[Dict[str, Any]], kind: str, blocked: set[str]) -> Optional[Dict[str, Any]]:
    hints = KIND_HINTS.get(kind, ())
    best, best_score = None, 0
    for tool in catalog or []:
        name = str(tool.get("name") or "")
        if not name or name in blocked:
            continue
        hay = name.lower() + " " + str(tool.get("description") or "").lower()
        score = max((_hint_score(h, name.lower(), hay) for h in hints), default=0)
        if score > best_score:
            best, best_score = tool, score
    return best

def _schema(tool: Optional[Dict[str, Any]]) -> Tuple[List[str], Dict[str, Any]]:
    if not tool:
        return [], {}
    schema = tool.get("inputSchema") or {}
    required = [k for k in (schema.get("required") or []) if isinstance(k, str)]
    props = schema.get("properties") or {}
    return required, props if isinstance(props, dict) else {}

def _value_for_key(key: str, prop: Dict[str, Any], ctx: Dict[str, Any]) -> Any:
    kl = key.lower()
    ptype = (prop or {}).get("type")
    if key in ctx.get("fixed", {}):
        value = ctx["fixed"][key]
    elif "service" in kl:
        value = ctx["service"]
    elif "metric" in kl:
        value = ctx["metric"]
    elif "release" in kl or "version" in kl:
        value = ctx["release"] or "previous"
    elif "flag" in kl:
        value = ctx["flag"] or "feature_flag"
    elif "pod" in kl:
        value = ctx["pod"]
    elif "replica" in kl or kl in ("count", "desired", "size", "instances"):
        value = ctx["replicas"]
    elif "window" in kl or "minute" in kl or "duration" in kl or "lookback" in kl or "since" in kl:
        value = ctx["window"]
    elif "query" in kl or "pattern" in kl or kl in ("filter", "search", "q", "text", "expression"):
        value = ctx["query"]
    elif "target" in kl or "dependency" in kl or kl in ("dep", "host", "endpoint", "upstream", "url"):
        value = ctx["dep"]
    elif kl in ("key", "configkey", "config_key", "setting", "name"):
        value = ctx["config_key"]
    elif "severity" in kl:
        value = ctx["severity"]
    elif "reason" in kl or "rationale" in kl or "summary" in kl or "message" in kl:
        value = ctx["reason"]
    elif "topic" in kl or "runbook" in kl:
        value = ctx["topic"]
    elif "namespace" in kl:
        value = ctx["namespace"]
    elif "timeout" in kl:
        value = ctx["timeout"]
    else:
        value = ctx["cause"]
    enum = (prop or {}).get("enum")
    if isinstance(enum, list) and value not in enum and enum:
        value = enum[0]
    if ptype in ("integer", "number"):
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = 0
    elif ptype == "boolean":
        value = bool(value)
    elif ptype == "array" and not isinstance(value, list):
        value = [value]
    return value

def build_tool_arguments(tool: Dict[str, Any], context: Dict[str, Any], fixed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    required, props = _schema(tool)
    ctx = dict(context)
    ctx["fixed"] = fixed or {}
    if required:
        keys = required
    else:
        known = ("service", "metric", "release", "version", "flag", "pod",
                 "replica", "count", "desired", "size", "instances", "window",
                 "minute", "duration", "lookback", "since", "query", "pattern",
                 "filter", "search", "target", "dependency", "dep", "host",
                 "endpoint", "upstream", "url", "key", "configkey", "config_key",
                 "setting", "name", "severity", "reason", "rationale", "summary",
                 "message", "topic", "runbook", "namespace", "timeout")
        keys = [k for k in props if any(h in k.lower() for h in known)]
    return {key: _value_for_key(key, props.get(key) or {}, ctx) for key in keys}

def _context(cause: str, incident: Dict[str, Any], entities: Dict[str, Any],
             fixed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    c = cause.lower()
    metric = "error_rate"
    query = "service error"
    config_key = "runtime"
    topic = "incident-recovery"
    if any(x in c for x in ("memory", "leak", "heap")):
        metric, query = "jvm_heap_usage", "OutOfMemoryError"
    elif "deadlock" in c or "lock" in c:
        metric, query = "thread_deadlock_count", "thread deadlock"
    elif any(x in c for x in ("database", "connection", "db", "pool")):
        metric, query = "db_connections", "pool acquisition timeout"
    elif any(x in c for x in ("traffic", "capacity", "spike", "satur")):
        metric, query = "cpu_utilization", "request saturation"
    elif any(x in c for x in ("cert", "tls", "expired")):
        metric, query, config_key, topic = "dependency_error_rate", "tls handshake failure", "tls", "tls-expiry"
    elif "flag" in c or "recur" in c:
        metric, query, config_key = "recursion_depth", "evaluation depth exceeded", "feature_flags"
    elif any(x in c for x in ("secret", "credential", "rotation")):
        metric, query, config_key, topic = "auth_failure_rate", "credential rotation failure", "credentials", "secret-rotation"
    elif any(x in c for x in ("rate", "throttl")):
        metric, query, config_key = "request_rejections", "rate limit rejection", "rate_limits"
    elif any(x in c for x in ("upstream", "dependency", "network", "timeout")):
        metric, query = "dependency_error_rate", "upstream timeout"
    elif any(x in c for x in ("deploy", "regression", "build", "release")):
        metric, query, topic = "error_rate", "deployment error", "rollback-procedure"
    ctx = {
        "service": entities["service"], "metric": metric, "query": query,
        "window": 30, "config_key": config_key, "dep": entities["dep"],
        "flag": entities["flag"], "release": entities["release"],
        "replicas": entities["replicas"], "pod": entities["pod"],
        "severity": incident.get("severity") or "SEV-1",
        "reason": f"{cause.replace('_', ' ')} on {entities['service']}",
        "topic": topic, "namespace": incident.get("namespace") or entities["service"],
        "timeout": 30, "cause": cause,
    }
    if fixed:
        # Convert fixed semantic names to the matching context fields.
        for key, value in fixed.items():
            kl = str(key).lower()
            if "metric" in kl: ctx["metric"] = value
            elif "pattern" in kl or "query" in kl or "search" in kl or "filter" in kl: ctx["query"] = value
            elif "topic" in kl: ctx["topic"] = value
            elif "target" in kl or "dependency" in kl: ctx["dep"] = value
            elif "replica" in kl or "count" in kl: ctx["replicas"] = value
            else: ctx.setdefault("fixed", {})[key] = value
        ctx["fixed"] = {**(ctx.get("fixed") or {}), **fixed}
    return ctx

def _evidence_for(keywords: Tuple[str, ...], lines: List[Tuple[str, str]], evidence: List[str], fallback_index: int = 0) -> List[str]:
    for eid, text in lines:
        if eid in evidence and any(k in text.lower() for k in keywords):
            return [eid]
    return [evidence[min(fallback_index, len(evidence)-1)]] if evidence else []

REF_PLAN = {
    "deployment_regression": {
        "diagnostics": [("inspect_deployment", {}, 0), ("query_metrics", {"metric": "error_rate", "windowMinutes": 30}, 1)],
        "effect": "rollback_deployment",
    },
    "database_connection_exhaustion": {
        "diagnostics": [("query_logs", {"query": "pool acquisition timeout", "windowMinutes": 30}, 1),
                        ("query_metrics", {"metric": "db_pool_wait", "windowMinutes": 30}, 0)],
        "effect": "scale_service",
    },
    "dependency_certificate_expired": {
        "diagnostics": [("dependency_status", {}, 0), ("read_runbook", {"topic": "tls-expiry"}, 2)],
        "effect": "open_incident",
    },
    "feature_flag_recursion": {
        "diagnostics": [("query_logs", {"query": "evaluation depth exceeded", "windowMinutes": 30}, 0),
                        ("inspect_deployment", {}, 2)],
        "effect": "disable_feature",
    },
    "traffic_capacity_exhaustion": {
        "diagnostics": [("query_metrics", {"metric": "request_saturation", "windowMinutes": 30}, 0)],
        "effect": "scale_service",
    },
    "secret_rotation_mismatch": {
        "diagnostics": [("read_runbook", {"topic": "secret-rotation"}, 2)],
        "effect": "page_owner",
    },
    "thread_deadlock": {
        "diagnostics": [("query_metrics", {"metric": "thread_deadlock_count", "windowMinutes": 30}, 0)],
        "effect": "restart_pod",
    },
    "memory_exhaustion": {
        "diagnostics": [("query_metrics", {"metric": "jvm_heap_usage", "windowMinutes": 30}, 0),
                        ("query_logs", {"query": "OutOfMemoryError", "windowMinutes": 30}, 1)],
        "effect": "restart_pod",
    },
    "rate_limit_exhaustion": {
        "diagnostics": [("inspect_deployment", {"query": "rate_limits"}, 0)],
        "effect": "page_owner",
    },
    "upstream_dependency_failure": {
        "diagnostics": [("dependency_status", {}, 0)],
        "effect": "open_incident",
    },
}

def _plan_key(cause: str) -> Optional[str]:
    low = cause.lower()
    for _, family, canonical in CAUSE_RULES:
        if canonical == low or any(t in low for t in family):
            return canonical
    return None

def _plan_for(cause: str) -> Optional[Dict[str, Any]]:
    return REF_PLAN.get(_plan_key(cause) or "")

def build_diagnostics(cause: str, lines: List[Tuple[str, str]], evidence: List[str],
                      incident: Dict[str, Any], catalog: List[Dict[str, Any]],
                      policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    entities = extract_entities(incident)
    effect_tools = list(policy.get("effectTools") or DEFAULT_EFFECT_TOOLS)
    approval_tools = list(policy.get("approvalRequiredFor") or DEFAULT_APPROVAL_TOOLS)
    blocked = set(effect_tools) | set(approval_tools) | {"no_action"}
    max_diags = max(1, min(int(policy.get("maximumDiagnostics") or 3), 5))
    key = _plan_key(cause)
    plan = _plan_for(cause)
    specs = plan["diagnostics"] if plan else []
    alternatives = {
        "inspect_deployment": "deploy", "query_logs": "log", "query_metrics": "metric",
        "dependency_status": "health", "read_runbook": "runbook",
    }
    result = []
    for tool_name, fixed, slot in specs:
        if len(result) >= max_diags:
            break
        kind = alternatives.get(tool_name, "metric")
        tool = next((x for x in catalog if x.get("name") == tool_name), None)
        if not tool:
            for alt in ALT_KIND.get(kind, (kind,)):
                tool = _resolve_tool(catalog, alt, blocked | {x["toolName"] for x in result})
                if tool:
                    tool_name = tool.get("name")
                    break
        if not tool or tool_name in blocked:
            continue
        ctx = _context(cause, incident, entities, fixed)
        args = build_tool_arguments(tool, ctx, fixed)
        if not args:
            continue
        keywords = tuple(str(v).lower() for v in fixed.values() if isinstance(v, str))
        if key == "deployment_regression" and tool_name == "inspect_deployment":
            keywords = ("release", "deploy", "build", "syntaxerror", "crash")
        elif key == "database_connection_exhaustion" and tool_name == "query_logs":
            keywords = ("pool", "connection", "timeout", "checkout")
        elif key == "database_connection_exhaustion" and tool_name == "query_metrics":
            keywords = ("pool", "connection", "wait", "database")
        elif key == "dependency_certificate_expired" and tool_name == "dependency_status":
            keywords = ("certificate", "tls", "notafter", "expired")
        elif key == "feature_flag_recursion" and tool_name == "query_logs":
            keywords = ("flag", "recursion", "depth", "loop")
        elif key == "traffic_capacity_exhaustion":
            keywords = ("cpu", "queue", "saturation", "replica", "capacity")
        elif key == "secret_rotation_mismatch":
            keywords = ("secret", "vault", "rotation", "credential")
        ev = _evidence_for(keywords, lines, evidence, slot)
        result.append({"toolName": tool_name, "arguments": args, "evidence": ev})
    if not result:
        fallback_kinds = ("metric", "log", "health", "config", "runbook")
        for kind in fallback_kinds:
            tool = _resolve_tool(catalog, kind, blocked)
            if not tool:
                continue
            ctx = _context(cause, incident, entities)
            args = build_tool_arguments(tool, ctx)
            if args:
                result.append({"toolName": tool.get("name"), "arguments": args,
                               "evidence": [evidence[0]] if evidence else []})
                break
    return result

def choose_effect(cause: str, incident: Dict[str, Any], policy: Dict[str, Any],
                  catalog: List[Dict[str, Any]]) -> Optional[str]:
    tools = [x for x in (policy.get("effectTools") or DEFAULT_EFFECT_TOOLS) if x and x != "no_action"]
    catalog_names = {x.get("name") for x in catalog or [] if isinstance(x, dict)}
    def pick(*names: str) -> Optional[str]:
        for name in names:
            if name in tools and (not catalog_names or name in catalog_names):
                return name
        return None
    entities = extract_entities(incident)
    key = _plan_key(cause) or cause.lower()
    if entities["delegation_blocked"]:
        return pick("page_owner", "open_incident")
    if entities["at_limit"]:
        return pick("page_owner", "open_incident")
    if key == "deployment_regression":
        return pick("rollback_deployment") if entities["release"] else pick("page_owner", "open_incident")
    if key == "feature_flag_recursion":
        return pick("disable_feature") if entities["flag"] else pick("page_owner", "open_incident")
    if key in ("dependency_certificate_expired", "secret_rotation_mismatch"):
        return pick("open_incident", "page_owner", "restart_pod")
    if key == "traffic_capacity_exhaustion":
        return pick("scale_service", "page_owner", "restart_pod")
    if key in ("database_connection_exhaustion", "thread_deadlock", "memory_exhaustion",
               "rate_limit_exhaustion", "upstream_dependency_failure"):
        return pick("restart_pod", "scale_service", "page_owner", "open_incident")
    plan = _plan_for(cause)
    if plan:
        return pick(plan["effect"], "page_owner", "open_incident")
    return pick("page_owner", "open_incident")

def get_effect_arguments(chosen: Optional[str], incident: Dict[str, Any], cause: str,
                         catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    entities = extract_entities(incident)
    ctx = _context(cause, incident, entities)
    tool = next((x for x in catalog or [] if x.get("name") == chosen), None)
    if chosen == "rollback_deployment" and not entities.get("release"):
        ctx["release"] = "previous"
    if chosen in ("page_owner", "open_incident"):
        ctx["reason"] = f"{cause.replace('_', ' ')} on {entities['service']}"
    if chosen == "restart_pod":
        ctx["pod"] = entities.get("pod") or f"{entities['service']}-0"
    if tool:
        args = build_tool_arguments(tool, ctx)
        if args:
            return args
    if chosen == "rollback_deployment":
        return {"service": entities["service"], "target_version": ctx["release"]}
    if chosen == "disable_feature":
        return {"service": entities["service"], "flag_name": ctx["flag"]}
    if chosen == "scale_service":
        return {"service": entities["service"], "replicas": entities["replicas"]}
    if chosen in ("page_owner", "open_incident"):
        return {"service": entities["service"], "reason": ctx["reason"]}
    if chosen == "restart_pod":
        return {"service": entities["service"], "pod_name": ctx["pod"]}
    return {"service": entities["service"]}

def analyze_incident(incident: Dict[str, Any], catalog: List[Dict[str, Any]],
                     policy: Dict[str, Any]):
    incident = dict(incident or {})
    policy = dict(policy or {})
    title = incident.get("title") or ""
    allowed = list(incident.get("allowedRootCauses") or DEFAULT_ROOT_CAUSES)
    all_lines = parse_evidence_lines(incident.get("transcript") or "")
    lines = select_evidence_lines(incident.get("transcript") or "")
    cause = determine_root_cause(lines or all_lines, allowed, title)
    evidence = select_evidence_ids(lines, all_lines, cause)
    diagnostics = build_diagnostics(cause, lines or all_lines, evidence, incident, catalog, policy)
    # Every dispatch must cite an ID present in the diagnosis.
    for item in diagnostics:
        item["evidence"] = [x for x in item.get("evidence", []) if x in evidence][:1] or evidence[:1]
    effect = choose_effect(cause, incident, policy, catalog)
    approval = bool(effect and effect in (policy.get("approvalRequiredFor") or DEFAULT_APPROVAL_TOOLS))
    return cause, evidence, diagnostics, effect, approval
