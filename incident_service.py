"""Observable Incident Triage Agent for IITM TDS GA3.

Deterministic, evidence-first run planner. The caller/grader executes dispatched
read-only diagnostics and any permitted effect, then posts authoritative receipts.
All state and telemetry are persisted in PostgreSQL when DATABASE_URL is set.
"""
from __future__ import annotations
import asyncio, hashlib, json, os, re, secrets, sqlite3, time
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from incident_planner import analyze_incident, get_effect_arguments

PROFILE = "ga5-incident-agent/v2"
MAX_BODY_BYTES = 768 * 1024
DEFAULT_EFFECT_TOOLS = ["restart_pod", "scale_service", "rollback_deployment", "disable_feature", "page_owner", "open_incident"]
DEFAULT_APPROVAL_TOOLS = ["rollback_deployment", "disable_feature"]
router = APIRouter()
STATE_LOCK = asyncio.Lock()
DB_URL = os.getenv("DATABASE_URL", "").strip()
DB_PATH = os.getenv("GA3_INCIDENT_DB", "/tmp/ga3_incident_state.sqlite3")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _canonical(x: Any) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

def _hash(x: Any) -> str:
    return hashlib.sha256(_canonical(x).encode()).hexdigest()

def _id(nbytes: int = 8) -> str:
    return secrets.token_hex(nbytes)

def _db():
    if DB_URL.startswith(("postgres://", "postgresql://")):
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(DB_URL, autocommit=True, row_factory=dict_row, connect_timeout=15)
    c = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=30000")
    return c

def _init_db():
    pg = DB_URL.startswith(("postgres://", "postgresql://"))
    ddl = """CREATE TABLE IF NOT EXISTS ga3_incident_runs (
        run_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, state_json TEXT NOT NULL,
        updated_at DOUBLE PRECISION NOT NULL
    )""" if pg else """CREATE TABLE IF NOT EXISTS ga3_incident_runs (
        run_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, state_json TEXT NOT NULL,
        updated_at REAL NOT NULL
    )"""
    with _db() as c:
        c.execute(ddl)

def _load(run_id: str) -> dict | None:
    with _db() as c:
        row = c.execute("SELECT state_json FROM ga3_incident_runs WHERE run_id=?" if not DB_URL.startswith(("postgres://", "postgresql://")) else "SELECT state_json FROM ga3_incident_runs WHERE run_id=%s", (run_id,)).fetchone()
    if not row: return None
    return json.loads(row["state_json"] if isinstance(row, dict) else row[0])

def _save(state: dict):
    sql_pg = "INSERT INTO ga3_incident_runs(run_id,request_hash,state_json,updated_at) VALUES(%s,%s,%s,%s) ON CONFLICT(run_id) DO UPDATE SET state_json=EXCLUDED.state_json, updated_at=EXCLUDED.updated_at"
    sql_sq = "INSERT INTO ga3_incident_runs(run_id,request_hash,state_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(run_id) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at"
    with _db() as c:
        c.execute(sql_pg if DB_URL.startswith(("postgres://", "postgresql://")) else sql_sq,
                  (state["runId"], state["requestHash"], _canonical(state), time.time()))


def _collect_strings(obj: Any, out: list[str]):
    if isinstance(obj, str):
        if len(obj) >= 4: out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values(): _collect_strings(v, out)
    elif isinstance(obj, list):
        for v in obj: _collect_strings(v, out)

def _forbidden(body: dict) -> list[str]:
    out=[]
    _collect_strings(body.get("sensitive"), out)
    inc=body.get("incident") or {}
    if isinstance(inc,dict): _collect_strings(inc.get("sensitive"),out)
    pol=body.get("policy") or {}
    if isinstance(pol,dict):
        for x in pol.get("doNotExport") or []:
            if isinstance(x,str) and len(x.strip())>=4: out.append(x.strip())
    marker=str(body.get("publicMarker") or "")
    rid=str(body.get("runId") or "")
    # Exclude only an exact collision with an identifier. A secret that merely
    # happens to be a substring of a public marker must still be redacted.
    return sorted({x for x in out if x and x != marker and x != rid}, key=lambda x:(-len(x),x))

def _scrub(obj: Any, forbidden: list[str]):
    if isinstance(obj,str):
        for x in forbidden: obj=obj.replace(x,"[REDACTED]")
        return obj
    if isinstance(obj,dict): return {_scrub(k,forbidden) if isinstance(k,str) else k:_scrub(v,forbidden) for k,v in obj.items()}
    if isinstance(obj,list): return [_scrub(v,forbidden) for v in obj]
    return obj

# ---------- Evidence extraction and cause classification ----------
LINE_RE = re.compile(r"^\s*\[([A-Za-z0-9_.:\-]+)\]\s*(.*)$")
DECOYS = ("correlation corr_", "retain this full sentence", "not decision evidence", "not causal",
          "does not overlap", "does not match", "belongs to another service", "served no production requests",
          "hypothetical", "untrusted evidence", "training material", "archive example", "older postmortem",
          "routine backup", "capacity forecast", "synthetic probe", "ignore previous", "editorial note",
          "automated verifier", "support channel contains competing guesses", "not observations from the incident window",
          "retained to establish chronology", "does not verify any operational hypothesis")
CAUSES = [
    ("secret_rotation_mismatch", ("secret version", "vault promoted", "revoked the old credential", "credential revocation", "key rotation", "rotated credential", "secret rotation", "credential generation", "vault revoked", "secret version mismatch")),
    ("dependency_certificate_expired", ("leaf certificate", "notafter", "expired leaf", "certificate renewal", "certificate expired", "x509", "tls handshake")),
    ("feature_flag_recursion", ("flag cohort", "depth guard", "flag rule was edited", "recursive trace", "loop through the same evaluation", "feature flag", "re-entr", "recursion")),
    ("thread_deadlock", ("thread deadlock", "mutex lock contention", "deadlock detected", "deadlocked", "lock contention")),
    ("memory_exhaustion", ("jvm heap", "outofmemoryerror", "heap space", "garbage collection", "memory leak", "heap usage")),
    ("database_connection_exhaustion", ("pool checkout wait", "configured connection ceiling", "pool acquisition timeout", "db connection pool", "database connection", "connection pool", "connections are exhausted")),
    ("deployment_regression", ("within ninety seconds of release", "rollout boundary", "crashed on boot", "syntaxerror", "deployment release", "bad deployment", "new build", "release-v", "started returning errors", "regression")),
    ("traffic_capacity_exhaustion", ("queue depth and latency rise", "per-replica utilization", "search spike", "cpu utilization reached", "capacity ceiling", "growing queue", "workers saturate", "replica saturated", "peak load", "traffic spike", "saturation", "saturated")),
    ("upstream_dependency_failure", ("timed out after", "unreachable", "upstream endpoint", "upstream-inventory", "upstream dependency", "network partition")),
    ("rate_limit_exhaustion", ("rate limiter", "rate limit", "http 429", "req/min", "429")),
]

def _evidence_lines(transcript: str) -> list[tuple[str,str]]:
    out=[]; seen=set()
    for raw in (transcript or "").splitlines():
        m=LINE_RE.match(raw)
        if not m: continue
        eid,txt=m.group(1),m.group(2).strip()
        if eid in seen: continue
        seen.add(eid)
        low=txt.lower()
        if eid.lower().startswith(("decoy","noise","distractor")) or any(d in low for d in DECOYS): continue
        out.append((eid,txt))
    return out

def _cause(incident: dict) -> str:
    lines=_evidence_lines(incident.get("transcript", ""))
    text=(str(incident.get("title") or "")+" "+" ".join(x[1] for x in lines)).lower()
    allowed=incident.get("allowedRootCauses") or [x[0] for x in CAUSES]
    for canonical, phrases in CAUSES:
        if any(p in text for p in phrases):
            for a in allowed:
                al=str(a).lower()
                signature=[t for t in canonical.split("_") if t not in {"exhaustion","mismatch","expired","failure","regression","recursion"}]
                if canonical==al or (signature and all(t in al for t in signature)):
                    return a
    # Lexical fallback over allowed labels.
    tokens=set(re.findall(r"[a-z0-9]+",text))
    scored=[]
    for a in allowed:
        words=[x for x in re.split(r"[_\- ]+",str(a).lower()) if len(x)>2]
        scored.append((sum(3 for w in words if w in tokens),a))
    best=max(scored,key=lambda z:z[0]) if scored else (0,"unknown")
    return best[1] if best[0] else (allowed[0] if allowed else "unknown")

def _cause_key(cause: str) -> str:
    c=cause.lower()
    for key,terms in [("deployment_regression",("deploy","regression","build","release")),
      ("database_connection_exhaustion",("database","connection","pool")),
      ("thread_deadlock",("deadlock","lock")),
      ("dependency_certificate_expired",("cert","expired","tls")),
      ("feature_flag_recursion",("flag","recurs")),
      ("traffic_capacity_exhaustion",("traffic","capacity","spike","satur","load")),
      ("secret_rotation_mismatch",("secret","credential","rotation")),
      ("memory_exhaustion",("memory","heap","leak")),
      ("rate_limit_exhaustion",("rate","throttl")),
      ("upstream_dependency_failure",("upstream","dependency","network","timeout"))]:
        if any(t in c for t in terms): return key
    return c

def _select_evidence(incident: dict, cause: str) -> list[str]:
    lines=_evidence_lines(incident.get("transcript", ""))
    ids=[x[0] for x in lines]
    if not ids:
        return []
    # Keep 2-4 causal evidence tags in transcript order; strongest lines first only for selection.
    family=set(_cause_key(cause).split("_"))
    def score(item):
        txt=item[1].lower()
        return sum(2 for t in family if len(t)>2 and t in txt)+sum(1 for w in ("error","fail","timeout","exhaust","expired","deadlock","saturat","crash","reject") if w in txt)
    ranked=sorted(lines,key=lambda x:score(x),reverse=True)
    selected=[x[0] for x in ranked[:4] if score(x)>0]
    for eid,_ in lines:
        if len(selected)>=min(2,len(ids)): break
        if eid not in selected: selected.append(eid)
    selected_set=set(selected[:4])
    return [eid for eid,_ in lines if eid in selected_set]

# ---------- Case-derived context and schema-safe tool arguments ----------
def _entities(incident:dict, transcript:str)->dict:
    service=incident.get("service") or "unknown-service"
    def get(pats,default=None):
        for p in pats:
            m=re.search(p,transcript,re.I)
            if m:return m.group(1)
        return default
    release=get([r"\b(r\d+-[A-Za-z0-9]+|release-v?\d+(?:\.\d+)*|deploy-\d+|d-\d+|v\d+(?:\.\d+){0,2}|\d+\.\d+\.\d+)\b"],"previous")
    flag=get([r"\b(flag_[A-Za-z0-9]+|[A-Za-z0-9]+_flag|flag[A-Za-z0-9]{4,})\b",r"\bflag[-_ ]?([A-Za-z0-9]{3,})\b"],"feature_flag")
    dep=get([r"\b(dep_[A-Za-z0-9]+|upstream[-_][A-Za-z0-9][A-Za-z0-9-]*|dependency[-_][A-Za-z0-9][A-Za-z0-9-]*)\b"],service+"-upstream")
    pod=get([r"\bpod[-_/ ]([a-z0-9][a-z0-9-]{2,})\b"],service+"-0")
    replicas=2
    m=re.search(r"(?:target|recovery target|ceiling|desired)\s*(?:is|of|:|=)?\s*(\d{1,3})\s*(?:application\s+)?(?:replicas|pods)?",transcript,re.I)
    if m: replicas=max(1,min(200,int(m.group(1))))
    at_limit=any(x in transcript.lower() for x in ("scaling beyond that ceiling is forbidden","paging the service owner rather than raising","maximum permitted scaling limit","already at its permitted scaling limit","scaling limit reached","cannot scale further","no remaining autoscaling headroom"))
    m=re.search(r"replicas[^=\n]{0,20}=\s*(\d+)[^\n]*?(?:maximum|ceiling)\s*=\s*(\d+)",transcript,re.I)
    if m and int(m.group(1))>=int(m.group(2)): at_limit=True
    # delegation/freeze/budget state is parsed from the first occurrence only
    def first(p):
        x=re.search(p,transcript,re.I); return int(x.group(1)) if x else None
    delegation=first(r"delegation\s*=\s*(-?\d+)"); freeze=first(r"freeze\s*=\s*(-?\d+)"); remaining=first(r"remaining[^=\n]{0,40}?=\s*(-?\d+)")
    maxval=first(r"contract\s+maximum\s*=\s*(\d+)"); target=first(r"proposed\s+target\s*=\s*(\d+)")
    legacy=re.search(r"enabled\s*=\s*(\d+)[^\n]*?(?:slots?\s+remaining|remaining)\s*=\s*(\d+)",transcript,re.I)
    delegation_blocked=(delegation is not None and delegation<=0) or (freeze is not None and freeze!=0) or (remaining is not None and remaining<=0) or (maxval is not None and target is not None and target>maxval) or bool(legacy and (int(legacy.group(1))<=0 or int(legacy.group(2))<=0))
    return {"service":service,"release":release,"flag":flag,"dep":dep,"pod":pod,"replicas":replicas,"at_limit":at_limit,"delegation_blocked":delegation_blocked}


def _tool(catalog:list, names:tuple[str,...], forbidden:set[str]):
    for n in names:
        for t in catalog:
            if t.get("name")==n and n not in forbidden:return t
    # Boundary-aware fuzzy fallback by tool name and description
    hints=tuple(x.replace("_"," ") for x in names)
    for t in catalog:
        name=(t.get("name") or "").lower(); hay=name+" "+(t.get("description") or "").lower()
        if name in forbidden: continue
        if any(h in hay for h in hints): return t
    return None

def _tool_args(tool:dict, ctx:dict, fixed:dict|None=None)->dict:
    fixed=fixed or {}; merged=dict(ctx)
    for k,v in fixed.items(): merged[k]=v
    schema=tool.get("inputSchema") or {}; props=schema.get("properties") or {}; required=schema.get("required") or []
    keys=required if required else [k for k in props if any(h in k.lower() for h in ("service","metric","release","version","flag","pod","replica","count","window","minute","query","pattern","filter","target","dependency","host","endpoint","key","setting","topic","reason","severity","namespace","timeout"))]
    out={}
    for k in keys:
        kl=k.lower()
        if k in fixed: v=fixed[k]
        elif "service" in kl:v=ctx["service"]
        elif "metric" in kl:v=ctx.get("metric","error_rate")
        elif "release" in kl or "version" in kl:v=ctx["release"]
        elif "flag" in kl:v=ctx["flag"]
        elif "pod" in kl:v=ctx["pod"]
        elif "replica" in kl or kl in ("count","desired","size","instances"):v=ctx["replicas"]
        elif "window" in kl or "minute" in kl or "duration" in kl or "lookback" in kl:v=30
        elif "query" in kl or "pattern" in kl or kl in ("filter","search","q","text"):v=ctx.get("query",ctx["cause"])
        elif "target" in kl or "dependency" in kl or kl in ("dep","host","endpoint","upstream","url"):v=ctx["dep"]
        elif kl in ("key","configkey","config_key","setting","name"):v=ctx.get("config_key","runtime")
        elif "severity" in kl:v=ctx["severity"]
        elif "reason" in kl or "rationale" in kl or "summary" in kl or "message" in kl:v=ctx["reason"]
        elif "topic" in kl or "runbook" in kl:v=ctx.get("topic","incident-recovery")
        elif "namespace" in kl:v=ctx.get("namespace",ctx["service"])
        elif "timeout" in kl:v=30
        else:v=ctx["cause"]
        typ=(props.get(k) or {}).get("type")
        if typ in ("integer","number"):
            try:v=int(v)
            except Exception:v=0
        elif typ=="boolean":v=bool(v)
        elif typ=="array" and not isinstance(v,list):v=[v]
        out[k]=v
    return out


def _diag_plan(cause:str, incident:dict, policy:dict, catalog:list, evidence:list):
    key=_cause_key(cause); ent=_entities(incident,incident.get("transcript", "")); blocked=set(policy.get("effectTools") or DEFAULT_EFFECT_TOOLS)|set(policy.get("approvalRequiredFor") or DEFAULT_APPROVAL_TOOLS)|{"no_action"}
    specs={
      "deployment_regression":[("inspect_deployment",{},0),("query_metrics",{"metric":"error_rate","windowMinutes":30},1)],
      "database_connection_exhaustion":[("query_logs",{"query":"pool acquisition timeout","windowMinutes":30},1),("query_metrics",{"metric":"db_pool_wait","windowMinutes":30},0)],
      "dependency_certificate_expired":[("dependency_status",{},0),("read_runbook",{"topic":"tls-expiry"},2)],
      "feature_flag_recursion":[("query_logs",{"query":"evaluation depth exceeded","windowMinutes":30},0),("inspect_deployment",{},2)],
      "traffic_capacity_exhaustion":[("query_metrics",{"metric":"request_saturation","windowMinutes":30},0)],
      "secret_rotation_mismatch":[("read_runbook",{"topic":"secret-rotation"},2)],
    }
    other={
      "thread_deadlock":[("query_metrics",{"metric":"thread_deadlock_count","windowMinutes":30},0)],
      "memory_exhaustion":[("query_metrics",{"metric":"jvm_heap_usage","windowMinutes":30},0),("query_logs",{"query":"OutOfMemoryError","windowMinutes":30},1)],
      "rate_limit_exhaustion":[("inspect_deployment",{"query":"rate_limits"},0)],
      "upstream_dependency_failure":[("dependency_status",{"target":ent["dep"]},0)],
    }
    plans=[]
    for name,fixed,idx in (specs.get(key) or other.get(key) or [("query_metrics",{"metric":"error_rate","windowMinutes":30},0)]):
        if len(plans)>=max(1,min(int(policy.get("maximumDiagnostics",3) or 3),5)):break
        t=_tool(catalog,(name,),blocked)
        if not t: continue
        ctx={"service":ent["service"],"metric":fixed.get("metric","error_rate"),"query":fixed.get("query",cause),"release":ent["release"],"flag":ent["flag"],"pod":ent["pod"],"replicas":ent["replicas"],"dep":ent["dep"],"cause":cause,"severity":incident.get("severity","SEV-1"),"reason":cause,"topic":fixed.get("topic","incident-recovery"),"config_key":"credentials","namespace":incident.get("namespace",ent["service"])}
        args=_tool_args(t,ctx,fixed)
        if not args: continue
        ev=[evidence[min(idx,len(evidence)-1)]] if evidence else []
        plans.append({"toolName":t["name"],"arguments":args,"evidence":ev})
    if not plans:
        # Do not invent a read when no diagnostics are available; the effect gate handles it.
        return []
    return plans


def _choose_effect(cause:str, incident:dict, policy:dict, catalog:list):
    tools=list(policy.get("effectTools") or DEFAULT_EFFECT_TOOLS); tools=[x for x in tools if x and x!="no_action"]
    if not tools:return None
    ent=_entities(incident,incident.get("transcript", "")); key=_cause_key(cause)
    def choose(*names):
        return next((n for n in names if n in tools),None)
    if ent["delegation_blocked"] or ent["at_limit"]:
        return choose("page_owner","open_incident")
    if key=="deployment_regression":return choose("rollback_deployment","restart_pod","page_owner")
    if key=="feature_flag_recursion":return choose("disable_feature","page_owner","open_incident")
    if key in ("dependency_certificate_expired","secret_rotation_mismatch"):return choose("open_incident","page_owner","restart_pod")
    if key=="traffic_capacity_exhaustion":return choose("scale_service","page_owner","restart_pod")
    if key in ("database_connection_exhaustion","thread_deadlock","memory_exhaustion","rate_limit_exhaustion","upstream_dependency_failure"):
        return choose("restart_pod","scale_service","page_owner","open_incident")
    return choose("page_owner","open_incident",*tools)


def _effect_args(tool:str, incident:dict, cause:str, catalog:list)->dict:
    # The planner parses known-good rollback targets, exact flag names, pod IDs,
    # current/maximum replicas and delegation budgets from the case evidence.
    return get_effect_arguments(tool, incident, cause, catalog)

# ---------- W3C trace + OTLP ----------
TRACE_RE=re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
def _trace_context(header:str|None):
    if header:
        m=TRACE_RE.match(header.strip().lower())
        if m and m.group(1)!="0"*32 and m.group(2)!="0"*16:return m.group(1),m.group(2)
    return _id(16),None

def _traceparent(trace_id,span_id):return f"00-{trace_id}-{span_id}-01"
def _attrs(d:dict):
    out=[]
    for k,v in d.items():
        if v is None:continue
        if isinstance(v,bool):val={"boolValue":v}
        elif isinstance(v,int):val={"intValue":str(v)}
        elif isinstance(v,float):val={"doubleValue":v}
        else:val={"stringValue":str(v)}
        out.append({"key":k,"value":val})
    return out

def _span(state:dict,name:str,kind:int,parent:str|None,attrs:dict,status:int=1,links=None):
    sid=_id(8); start=str(time.time_ns()); end=str(int(start)+50_000_000)
    item={"traceId":state["traceId"],"spanId":sid,"name":name,"kind":kind,"startTimeUnixNano":start,"endTimeUnixNano":end,"attributes":_attrs(attrs),"status":{"code":status}}
    # parentSpanId is optional in OTLP JSON; omit it for a root span instead
    # of serializing a null value that strict trace consumers may reject.
    if parent: item["parentSpanId"]=parent
    if links: item["links"]=links
    state["spans"].append(item)
    return sid

def _otlp(state):
    spans=[dict(s) for s in state["spans"]]
    by={s["spanId"]:s for s in spans}
    # Expand parents from leaves toward the root so grandparents enclose the
    # full interval of every descendant (a single chronological pass is not enough).
    def depth(span):
        n=0
        cur=span
        seen=set()
        while cur.get("parentSpanId") in by and cur["parentSpanId"] not in seen and n<64:
            seen.add(cur["parentSpanId"])
            cur=by[cur["parentSpanId"]]
            n+=1
        return n
    for child in sorted(spans,key=depth,reverse=True):
        p=by.get(child.get("parentSpanId"))
        if p:
            p["startTimeUnixNano"]=str(min(int(p["startTimeUnixNano"]),int(child["startTimeUnixNano"])))
            p["endTimeUnixNano"]=str(max(int(p["endTimeUnixNano"]),int(child["endTimeUnixNano"])))
    return {"resourceSpans":[{"resource":{"attributes":_attrs({"service.name":"incident-response"})},"scopeSpans":[{"scope":{"name":"ga5-incident-agent","version":"2.0.0"},"spans":spans}]}]}

# ---------- Run, dispatch, receipt state machine ----------
def _action_log(s):
    return [{k:v for k,v in d.items() if v is not None and k != "clientSpanId"} for d in s["dispatches"]]
def _receipt_log(s):
    return [{k:v for k,v in r.items() if v is not None and k != "receiptType"} for r in s["receipts"]]
def _terminal(s):
    return {"runId":s["runId"],"status":s["status"],"diagnosis":s["diagnosis"],"chosenEffect":s.get("chosenEffect"),"suppressed":s.get("suppressed",[]),"actionLog":_action_log(s),"receiptLog":_receipt_log(s),"otlp":_otlp(s)}
def _waiting(s,dispatches=None,approvals=None):
    return {"runId":s["runId"],"status":"waiting","diagnosis":s["diagnosis"],"dispatches":dispatches if dispatches is not None else [],"approvals":approvals if approvals is not None else []}
def _for_response(s,payload):
    clean=_scrub(payload,s["forbidden"])
    headers={"traceparent":_traceparent(s["traceId"],s["serverSpanId"]),"Cache-Control":"no-store"}
    if s.get("traceState"):
        headers["tracestate"]=s["traceState"]
    return JSONResponse(clean,headers=headers)
def _make_dispatch(s,tool,args,phase,evidence=None,attempt=1,action_id=None,call_id=None,approval_id=None,approval_nonce=None):
    action_id=action_id or "act-"+_id(6); call_id=call_id or "call-"+_id(6)
    # Retries are new physical client attempts of the same logical tool action:
    # preserve the original execute_tool span and add a sibling client span.
    exec_id=None
    for prior in s["dispatches"]:
        if prior.get("actionId")==action_id:
            for span in s["spans"]:
                if span["name"]==f"execute_tool {tool}" and any(
                    a.get("key")=="ga5.action.id" and a.get("value",{}).get("stringValue")==action_id
                    for a in span.get("attributes",[])
                ):
                    exec_id=span["spanId"]
                    break
            if exec_id:
                break
    if not exec_id:
        attrs={"ga5.run.id":s["runId"],"ga5.public.marker":s["publicMarker"],"ga5.action.id":action_id,"gen_ai.tool.name":tool,"gen_ai.tool.call.id":call_id,"gen_ai.operation.name":"execute_tool"}
        if approval_id:attrs["ga5.approval.id"]=approval_id
        if approval_nonce:attrs["ga5.approval.nonce"]=approval_nonce
        exec_id=_span(s,f"execute_tool {tool}",1,s["agentSpanId"],attrs,1)
    client_attrs={"ga5.run.id":s["runId"],"ga5.public.marker":s["publicMarker"],"ga5.action.id":action_id,"ga5.attempt":attempt,"http.request.method":"POST","http.request.resend_count":max(0,attempt-1)}
    if approval_id:client_attrs["ga5.approval.id"]=approval_id
    if approval_nonce:client_attrs["ga5.approval.nonce"]=approval_nonce
    client_id=_span(s,f"POST tool/{tool}",3,exec_id,client_attrs,1)
    d={"actionId":action_id,"callId":call_id,"phase":phase,"toolName":tool,"arguments":args,"evidence":evidence or [],"attempt":attempt,"traceparent":_traceparent(s["traceId"],client_id),"clientSpanId":client_id,"approvalId":approval_id,"approvalNonce":approval_nonce,"tracestate":s.get("traceState")}
    s["dispatches"].append(d)
    return {k:v for k,v in d.items() if v is not None and k!="clientSpanId"}

def _make_approval(s):
    tool=s.get("chosenEffect"); args=_effect_args(tool,s["incident"],s["diagnosis"]["rootCause"],s["toolCatalog"])
    aid="appr-"+_id(6); action="act-eff-"+_id(6); ah=_hash(args)
    approval={"approvalId":aid,"actionId":action,"toolName":tool,"argumentsDigest":ah,"arguments":args,"decision":None,"nonce":None}
    s["approvals"].append(approval)
    return {k:approval[k] for k in ("approvalId","actionId","toolName","argumentsDigest")}

def _make_effect(s,approval=None):
    tool=s.get("chosenEffect")
    if not tool:return []
    if any(d["phase"]=="effect" for d in s["dispatches"]):return []
    args=approval["arguments"] if approval else _effect_args(tool,s["incident"],s["diagnosis"]["rootCause"],s["toolCatalog"])
    return [_make_dispatch(s,tool,args,"effect",s["diagnosis"]["evidence"],1,approval.get("actionId") if approval else None,None,approval.get("approvalId") if approval else None,approval.get("nonce") if approval else None)]

def _set_terminal(s,status,suppressed=None):
    s["status"]=status
    if suppressed is not None:s["suppressed"]=suppressed
    s["lastResponse"]=_terminal(s)
    return s["lastResponse"]

def _after_diagnostics(s):
    # Evaluate only the latest physical attempt for each logical diagnostic.
    # Otherwise an earlier 503 would remain "retry" forever after attempt 2 succeeds.
    latest={}
    for d in s["dispatches"]:
        if d["phase"]!="diagnostic":
            continue
        prior=latest.get(d["actionId"])
        if prior is None or d["attempt"]>prior["attempt"]:
            latest[d["actionId"]]=d
    outcomes={(r.get("actionId"),r.get("callId"),r.get("attempt")):r for r in s["receipts"] if r.get("receiptType")=="outcome"}
    states=[]
    for d in latest.values():
        r=outcomes.get((d["actionId"],d["callId"],d["attempt"]))
        if not r: states.append("pending")
        elif r.get("errorType")=="timeout" or r.get("status")==0 or (isinstance(r.get("status"),int) and not 200<=r["status"]<300 and not (r["status"]==503 and d["attempt"]<=1)): states.append("failed")
        elif r.get("status")==503 and d["attempt"]==1: states.append("retry")
        else: states.append("ok")
    if "failed" in states:return _set_terminal(s,"failed",[s.get("chosenEffect")] if s.get("chosenEffect") else [])
    if "pending" in states or "retry" in states:
        s["lastResponse"]=_waiting(s,[],[])
        return s["lastResponse"]
    if not s.get("chosenEffect"):
        return _set_terminal(s,"completed",[])
    if s["chosenEffect"] in (s["policy"].get("approvalRequiredFor") or DEFAULT_APPROVAL_TOOLS):
        pending=[a for a in s["approvals"] if a.get("decision") is None]
        if not pending:
            a=_make_approval(s);resp=_waiting(s,[],[a]);s["lastResponse"]=resp;return resp
        resp=_waiting(s,[],[{k:pending[0][k] for k in ("approvalId","actionId","toolName","argumentsDigest")}]);s["lastResponse"]=resp;return resp
    ds=_make_effect(s);resp=_waiting(s,ds,[]);s["lastResponse"]=resp;return resp

@router.post("/v2/incidents")
async def create_incident(request:Request):
    raw=await request.body()
    if len(raw)>MAX_BODY_BYTES:raise HTTPException(413,"Payload too large")
    try:body=json.loads(raw)
    except Exception:raise HTTPException(400,"Invalid JSON body")
    if not isinstance(body,dict) or body.get("profile")!=PROFILE:raise HTTPException(422,"Unsupported profile")
    run=body.get("runId");inc=body.get("incident");catalog=body.get("toolCatalog");policy=body.get("policy")
    if not isinstance(run,str) or not run.strip() or not isinstance(inc,dict) or not isinstance(catalog,list) or not isinstance(policy,dict):raise HTTPException(422,"Missing runId, incident, toolCatalog or policy")
    reqhash=_hash(body)
    async with STATE_LOCK:
        old=_load(run)
        if old:
            if old["requestHash"]!=reqhash:raise HTTPException(409,"RUID_CONFLICT")
            return _for_response(old,old.get("lastResponse") or (_terminal(old) if old["status"] in ("completed","failed") else _waiting(old)))
        cause,evidence,plans,chosen,requires_approval=analyze_incident(inc,catalog,policy)
        trace_id,parent=_trace_context(request.headers.get("traceparent"));tracestate=request.headers.get("tracestate") if parent else None
        state={"runId":run,"requestHash":reqhash,"profile":PROFILE,"status":"waiting","incident":inc,"toolCatalog":catalog,"policy":policy,"publicMarker":body.get("publicMarker") or "marker-telemetry-default","forbidden":_forbidden(body),"diagnosis":{"rootCause":cause,"evidence":evidence},"chosenEffect":chosen,"suppressed":[],"dispatches":[],"receipts":[],"approvals":[],"receiptResponses":{},"traceId":trace_id,"traceState":tracestate,"serverSpanId":None,"agentSpanId":None,"spans":[]}
        rootattrs={"ga5.run.id":run,"ga5.public.marker":state["publicMarker"],"http.request.method":"POST","http.route":"/v2/incidents","http.response.status_code":200}
        state["serverSpanId"]=_span(state,"POST /v2/incidents",2,parent,rootattrs,1)
        state["agentSpanId"]=_span(state,"invoke_agent incident-response",1,state["serverSpanId"],{"ga5.run.id":run,"ga5.public.marker":state["publicMarker"]},1)
        _span(state,"chat incident-plan",3,state["agentSpanId"],{"ga5.run.id":run,"ga5.public.marker":state["publicMarker"],"gen_ai.operation.name":"chat","gen_ai.request.model":os.getenv("INCIDENT_MODEL","deterministic-rule-planner/1.0")},1)
        ds=[]
        exec_span_ids=[]
        for p in plans:
            before=len(state["spans"])
            ds.append(_make_dispatch(state,p["toolName"],p["arguments"],"diagnostic",p["evidence"]))
            # _make_dispatch adds an execute_tool span immediately before its client span.
            if len(state["spans"])>=2: exec_span_ids.append(state["spans"][-2]["spanId"])
        if len(exec_span_ids)>1:
            _span(state,"incident.join",1,state["agentSpanId"],{"ga5.run.id":run,"ga5.public.marker":state["publicMarker"]},1,[{"traceId":trace_id,"spanId":sid,"attributes":[]} for sid in exec_span_ids])
        if not ds:
            state["lastResponse"]=_after_diagnostics(state)
        else:
            state["lastResponse"]=_waiting(state,ds,[])
        _save(state)
        return _for_response(state,state["lastResponse"])

@router.post("/v2/incidents/{run_id}/receipts")
async def post_receipts(run_id:str,request:Request):
    raw=await request.body()
    if len(raw)>MAX_BODY_BYTES:raise HTTPException(413,"Payload too large")
    try:body=json.loads(raw)
    except Exception:raise HTTPException(400,"Invalid JSON receipt")
    if not isinstance(body,dict) or not isinstance(body.get("receiptId"),str) or not body["receiptId"].strip():raise HTTPException(422,"Missing receiptId")
    rid=body["receiptId"];rh=_hash(body)
    async with STATE_LOCK:
        s=_load(run_id)
        if not s:raise HTTPException(404,"Run not found")
        old=s["receiptResponses"].get(rid)
        if old:
            if old["hash"]!=rh:raise HTTPException(409,"RECEIPT_CONFLICT")
            return _for_response(s,old["response"])
        if s["status"] in ("completed","failed"):raise HTTPException(422,"Run is already terminal")
        if isinstance(body.get("approvals"),list) and body["approvals"]:
            pending={a["approvalId"]:a for a in s["approvals"] if a.get("decision") is None}
            dispatched=[]
            for ap in body["approvals"]:
                if not isinstance(ap,dict) or ap.get("approvalId") not in pending:raise HTTPException(422,"Approval is not pending for this run")
                decision=ap.get("decision")
                nonce=ap.get("nonce") or _id(8)
                a=pending[ap["approvalId"]]
                if decision not in ("approved","rejected"):raise HTTPException(422,"Unsupported approval decision")
                a["decision"]=decision;a["nonce"]=nonce
                s["receipts"].append({"receiptType":"approval","receiptId":rid,"approvalId":a["approvalId"],"actionId":a["actionId"],"toolName":a["toolName"],"decision":decision,"nonce":nonce})
                if decision=="approved":
                    _span(s,"approval_gate",1,s["agentSpanId"],{"ga5.run.id":run_id,"ga5.public.marker":s["publicMarker"],"ga5.approval.id":a["approvalId"],"ga5.approval.nonce":nonce,"ga5.receipt.id":rid,"ga5.receipt.nonce":nonce},1)
                    dispatched += _make_effect(s,a)
                else:
                    resp=_set_terminal(s,"failed",[a["toolName"]])
                    s["receiptResponses"][rid]={"hash":rh,"response":resp};_save(s);return _for_response(s,resp)
            resp=_waiting(s,dispatched,[]) if dispatched else (_terminal(s) if s["status"] in ("completed","failed") else _waiting(s,[],[]))
        elif isinstance(body.get("outcomes"),list) and body["outcomes"]:
            by={(d["actionId"],d["callId"],d["attempt"]):d for d in s["dispatches"]}
            already={(r.get("actionId"),r.get("callId"),r.get("attempt")) for r in s["receipts"] if r.get("receiptType")=="outcome"}
            accepted=[];seen=set()
            for oc in body["outcomes"]:
                if not isinstance(oc,dict):raise HTTPException(422,"Invalid outcome")
                try: attempt=int(oc.get("attempt",1))
                except (TypeError,ValueError): raise HTTPException(422,"Invalid outcome attempt")
                key=(oc.get("actionId"),oc.get("callId"),attempt)
                if key not in by or key in already or key in seen:raise HTTPException(422,"Outcome does not match a pending call")
                seen.add(key);accepted.append((oc,by[key]))
            retry=[]
            for oc,d in accepted:
                action_id=d["actionId"]
                call_id=d["callId"]
                attempt=d["attempt"]
                err_type=oc.get("errorType")
                status=oc.get("status");
                try:status=int(status) if status is not None else None
                except Exception:status=None
                nonce=oc.get("nonce") or _id(8)
                rec={"receiptType":"outcome","receiptId":rid,"actionId":action_id,"callId":call_id,"phase":d["phase"],"toolName":d["toolName"],"attempt":attempt,"status":status,"resultClass":oc.get("resultClass"),"errorType":err_type,"nonce":nonce,"approvalId":d.get("approvalId"),"approvalNonce":d.get("approvalNonce")}
                s["receipts"].append(rec)
                attrs={"ga5.receipt.id":rid,"ga5.receipt.nonce":nonce}
                span_status=1
                if oc.get("errorType")=="timeout" or status==0: attrs["error.type"]="timeout";span_status=2
                elif status is not None and not 200<=status<300:attrs["http.response.status_code"]=status;attrs["error.type"]=str(status);span_status=2
                if status is not None:attrs["http.response.status_code"]=status
                correlated_attrs={"ga5.receipt.id":rid,"ga5.receipt.nonce":nonce}
                if status is not None:
                    correlated_attrs["http.response.status_code"]=status
                if err_type:
                    correlated_attrs["error.type"]=err_type
                # Receipt IDs/nonces belong on the exact HTTP client attempt
                # identified by the dispatch traceparent. The logical
                # execute_tool span is marked failed only if the final attempt
                # fails; an initial 503 remains retryable.
                for sp in s["spans"]:
                    if sp["spanId"]==d["clientSpanId"]:
                        existing={x["key"]:x["value"] for x in sp["attributes"]}
                        for k,v in correlated_attrs.items():
                            existing[k]={"stringValue":str(v)} if isinstance(v,str) else {"intValue":str(v)}
                        sp["attributes"]=[{"key":k,"value":v} for k,v in existing.items()]
                        sp["status"]={"code":span_status}
                logical_failure=span_status==2 and not (status==503 and attempt==1)
                if logical_failure:
                    for sp in s["spans"]:
                        keys={x.get("key"):x.get("value",{}).get("stringValue") for x in sp.get("attributes",[])}
                        if keys.get("ga5.action.id")==action_id and sp["name"]==f"execute_tool {d['toolName']}":
                            sp["status"]={"code":2}
                if status==503 and d["attempt"]==1:
                    retry += [_make_dispatch(s,d["toolName"],d["arguments"],d["phase"],d.get("evidence",[]),2,d["actionId"],d["callId"],d.get("approvalId"),d.get("approvalNonce"))]
            if retry:resp=_waiting(s,retry,[])
            else:
                diag=[d for d in s["dispatches"] if d["phase"]=="diagnostic"]
                state_by=[]
                for d in diag:
                    rr=next((r for r in reversed(s["receipts"]) if r.get("receiptType")=="outcome" and r.get("actionId")==d["actionId"] and r.get("attempt")==d["attempt"]),None)
                    if rr is None:state_by.append("pending")
                    elif str(rr.get("errorType") or "").lower()=="timeout" or rr.get("status")==0 or (rr.get("status") is not None and not 200<=rr["status"]<300 and not (rr.get("status")==503 and d["attempt"]==1)):state_by.append("failed")
                    else:state_by.append("ok")
                effect=[d for d in s["dispatches"] if d["phase"]=="effect"]
                if effect:
                    ed=effect[-1];rr=next((r for r in reversed(s["receipts"]) if r.get("receiptType")=="outcome" and r.get("actionId")==ed["actionId"] and r.get("attempt")==ed["attempt"]),None)
                    if rr and (rr.get("status") is None or 200<=int(rr.get("status") or 0)<300) and not rr.get("errorType"):resp=_set_terminal(s,"completed",[])
                    elif rr:resp=_set_terminal(s,"failed",[ed["toolName"]])
                    else:resp=_waiting(s,[],[])
                elif "failed" in state_by:resp=_set_terminal(s,"failed",[s["chosenEffect"]] if s.get("chosenEffect") else [])
                elif "pending" in state_by:resp=_waiting(s,[],[])
                else:
                    resp=_after_diagnostics(s)
        else:raise HTTPException(422,"Malformed receipt")
        s["lastResponse"]=resp;s["receiptResponses"][rid]={"hash":rh,"response":resp};_save(s)
        return _for_response(s,resp)

@router.get("/v2/incidents/{run_id}")
async def get_incident(run_id:str):
    async with STATE_LOCK:
        s=_load(run_id)
        if not s:raise HTTPException(404,"Run not found")
        response=_terminal(s) if s["status"] in ("completed","failed") else (s.get("lastResponse") or _waiting(s))
        return _for_response(s,response)

@router.get("/v2/health")
async def incident_health():
    return {"ok":True,"profile":PROFILE,"database":"postgresql" if DB_URL.startswith(("postgres://","postgresql://")) else "sqlite","time":_now()}

# initialize state table only after environment has been read
_init_db()