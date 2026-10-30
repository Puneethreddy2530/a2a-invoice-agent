"""Contract smoke tests for the GA3 invoice claim/proposal/receipt workflow."""
import os
import tempfile

_TMP = tempfile.NamedTemporaryFile(prefix="ga3-a2a-", suffix=".sqlite3", delete=False)
_TMP.close()
os.environ["DATABASE_PATH"] = _TMP.name
os.environ.pop("DATABASE_URL", None)

import main
main.init_db()

# Provide deterministic AI output for protocol/lifecycle tests. The test still
# verifies that evidence IDs are source-grounded and validated by the agent.
async def fake_model(packages):
    proposals=[]
    for p in packages:
        refs=main.collect_evidence_refs(p)
        action=p.get("testAction", "hold_invoice")
        proposals.append({
            "packageId":p["packageId"],
            "action":action,
            "facts":{"vendorName":p.get("vendorName", "Acme Ltd"),"invoiceNumber":p["invoiceNumber"],"amountMinor":int(p.get("amountMinor",12500)),"currency":p.get("currency", "INR")},
            "evidenceRefs":refs[:3],
            "rationale":f"{refs[0]} identifies the invoice record; {refs[1]} is the supporting purchase-order evidence; {refs[2]} gives independent approval context. The proposal is {action} based on the package controls.",
        })
    return proposals
main.call_model=fake_model

from fastapi.testclient import TestClient
client=TestClient(main.app)

A="Bearer tenant-A"
B="Bearer tenant-B"
H={"Authorization":A,"A2A-Version":"1.0","Content-Type":"application/a2a+json"}
BATCH=main.BATCH_MT
RESULTS=main.RESULTS_MT

def package(pid="pkg-1", inv="INV-1"):
    return {
        "packageId":pid,
        "invoiceNumber":inv,
        "vendorName":"Acme Ltd",
        "amountMinor":12500,
        "currency":"INR",
        "documents":[
            {"documentId":"DOC-INVOICE-1","text":"Invoice INV-1 from Acme Ltd total INR 125.00 [DOC-INVOICE-1]"},
            {"documentId":"DOC-PO-1","text":"Purchase order matched [DOC-PO-1]"},
            {"documentId":"DOC-APPROVAL-1","text":"Approval recorded [DOC-APPROVAL-1]"},
        ]
    }

def send_batch(mid="m-1", pkg=None, token=A):
    msg={"messageId":mid,"contextId":"ctx-1","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-1","packages":[pkg or package()]}}]}
    return client.post("/message:send",headers={"Authorization":token,"A2A-Version":"1.0","Content-Type":"application/a2a+json"},json={"message":msg}),msg

# Public card shape and exact custom GA5 modes.
card=client.get("/.well-known/agent-card.json").json()
assert card["skills"][0]["id"]=="invoice_action_agent"
assert card["supportedInterfaces"][0]["protocolBinding"]=="HTTP+JSON"
assert card["supportedInterfaces"][0]["url"].endswith("/a2a/")
assert card["supportedInterfaces"][0]["url"]=="http://testserver/a2a/"
assert BATCH in card["defaultInputModes"] and RESULTS in card["defaultInputModes"]
assert main.PROPOSALS_MT in card["defaultOutputModes"] and main.RECEIPTS_MT in card["defaultOutputModes"]

# Correct auth, version, media-type checks.
assert client.get("/a2a/tasks").status_code==401
assert client.get("/a2a/tasks",headers={"Authorization":A,"A2A-Version":"1.0"}).status_code==200
assert client.get("/tasks",headers={"Authorization":"Basic x","A2A-Version":"1.0"}).status_code==401
assert client.get("/tasks",headers={"Authorization":A,"A2A-Version":"2.0"}).status_code==400
assert client.post("/a2a/message:send",headers={"Authorization":A,"A2A-Version":"1.0","Content-Type":"application/json"},json={}).status_code==415
assert client.post("/a2a/message:send",headers={"Authorization":A,"A2A-Version":"2.0","Content-Type":"application/a2a+json"},json={}).status_code==400

# Initial batch creates input-required proposal artifact.
r,msg=send_batch()
assert r.status_code==200,r.text
body=r.json(); assert "task" in body
T=body["task"]
assert T["status"]["state"]=="TASK_STATE_INPUT_REQUIRED"
prop=T["artifacts"][0]["parts"][0]
assert prop["mediaType"]==main.PROPOSALS_MT
proposal=prop["data"]["proposals"][0]
assert len(proposal["evidenceRefs"])==3
assert all(x in msg["parts"][0]["data"]["packages"][0]["documents"][i]["text"] for i,x in enumerate(proposal["evidenceRefs"]))

# Principal isolation: another Bearer token sees no task and cannot read task.
other=client.get("/tasks",headers={"Authorization":B,"A2A-Version":"1.0"})
assert other.status_code==200 and other.json()["tasks"]==[]
assert client.get(f"/tasks/{T['id']}",headers={"Authorization":B,"A2A-Version":"1.0"}).status_code==404
assert client.get("/tasks",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["tasks"]

# Same message/payload replays exact task; conflicting payload cannot create another task.
replay=client.post("/message:send",headers=H,json={"message":msg})
assert replay.status_code==200 and replay.json()["task"]["id"]==T["id"]
conflict_msg={**msg,"parts":[{"mediaType":BATCH,"data":{"batchId":"batch-1","packages":[package(inv="INV-OTHER")]}}]}
conflict=client.post("/message:send",headers=H,json={"message":conflict_msg})
assert conflict.status_code==409

# Correct continuation accepts exact actionId + action + nonce and stores receipt artifact.
result_msg={"messageId":"m-2","contextId":T["contextId"],"taskId":T["id"],"role":"user","parts":[{"mediaType":RESULTS,"data":{"batchId":"batch-1","results":[{"packageId":proposal["packageId"],"actionId":proposal["actionId"],"action":proposal["action"],"outcome":"ACCEPTED","receiptNonce":"nonce-1"}]}}]}
continued=client.post("/message:send",headers=H,json={"message":result_msg})
assert continued.status_code==200,continued.text
CT=continued.json()["task"]
assert CT["status"]["state"]=="TASK_STATE_COMPLETED"
receipt=CT["artifacts"][-1]["parts"][0]
assert receipt["mediaType"]==main.RECEIPTS_MT
assert receipt["data"]["executions"][0]["receiptNonce"]=="nonce-1"
# Terminal replay returns exact completed task; terminal task rejects new continuation.
assert client.post("/message:send",headers=H,json={"message":result_msg}).json()["task"]["id"]==T["id"]
invalid={**result_msg,"messageId":"m-3"}
assert client.post("/message:send",headers=H,json={"message":invalid}).status_code==409

# Cancellation protected and state transitions only from input-required.
r,msg2=send_batch("m-4",package("pkg-2","INV-2"))
T2=r.json()["task"]
assert client.post(f"/tasks/{T2['id']}:cancel",headers={"Authorization":A,"A2A-Version":"1.0","Content-Type":"application/a2a+json"}).status_code==200
assert client.get(f"/tasks/{T2['id']}",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["status"]["state"]=="TASK_STATE_CANCELED"
assert client.post(f"/tasks/{T2['id']}:cancel",headers={"Authorization":A,"A2A-Version":"1.0","Content-Type":"application/a2a+json"}).status_code==409
assert client.post(f"/tasks/{T['id']}:cancel",headers={"Authorization":A,"A2A-Version":"1.0","Content-Type":"application/a2a+json"}).status_code==409

# Invalid/incomplete receipt batches leave the task INPUT_REQUIRED.
r,msg3=send_batch("m-5",package("pkg-3","INV-3")); T3=r.json()["task"]
p3=T3["artifacts"][0]["parts"][0]["data"]["proposals"][0]
bad_msg={"messageId":"m-6","contextId":T3["contextId"],"taskId":T3["id"],"role":"user","parts":[{"mediaType":RESULTS,"data":{"batchId":"batch-1","results":[]}}]}
assert client.post("/message:send",headers=H,json={"message":bad_msg}).status_code==409
assert client.get(f"/tasks/{T3['id']}",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["status"]["state"]=="TASK_STATE_INPUT_REQUIRED"

# Authenticated audit and isolation probes are principal scoped.
assert client.get("/audit/actions",headers={"Authorization":A,"A2A-Version":"1.0"}).status_code==200
assert client.get("/audit/receipts",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["receipts"]
assert client.get("/isolation-probe",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["cross_principal_reads"] is False

# Concurrent identical initial messages converge to one stored task.
from concurrent.futures import ThreadPoolExecutor
concurrent_message={"messageId":"m-concurrent","contextId":"ctx-concurrent","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-concurrent","packages":[package("pkg-concurrent","INV-CONCURRENT")]}}]}
def post_concurrent_initial(_):
    return client.post("/message:send",headers=H,json={"message":concurrent_message})
with ThreadPoolExecutor(max_workers=4) as pool:
    concurrent_responses=list(pool.map(post_concurrent_initial,range(4)))
assert all(x.status_code==200 for x in concurrent_responses),[x.text for x in concurrent_responses]
concurrent_ids={x.json()["task"]["id"] for x in concurrent_responses}
assert len(concurrent_ids)==1,concurrent_ids

# Accepted settlement is recorded only after the caller supplies the result nonce.
def settle_and_continue(mid, invoice_number, batch_id, nonce):
    pkg=package(f"settle-{mid}", invoice_number)
    pkg["testAction"]="settle_invoice"
    msg={"messageId":mid,"contextId":f"ctx-{mid}","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":batch_id,"packages":[pkg]}}]}
    created=client.post("/message:send",headers=H,json={"message":msg})
    assert created.status_code==200,created.text
    task=created.json()["task"]
    proposal=task["artifacts"][0]["parts"][0]["data"]["proposals"][0]
    assert proposal["action"]=="settle_invoice",proposal
    result={"messageId":mid+"-result","contextId":task["contextId"],"taskId":task["id"],"role":"user","parts":[{"mediaType":RESULTS,"data":{"batchId":batch_id,"results":[{"packageId":proposal["packageId"],"actionId":proposal["actionId"],"action":proposal["action"],"outcome":"ACCEPTED","receiptNonce":nonce}]}}]}
    done=client.post("/message:send",headers=H,json={"message":result})
    assert done.status_code==200,done.text
    return task, proposal, done.json()["task"]

# Persisted accepted same invoice identity is a duplicate, but a different invoice number with the same amount is not.
settled_task, settled_proposal, settled_done=settle_and_continue("m-settle-1","INV-PAID-1","batch-settle-1","receipt-settle-1")
assert settled_done["status"]["state"]=="TASK_STATE_COMPLETED"
# Build a new package with the exact same vendor and invoice number.
pdup=package("pkg-dup","INV-PAID-1"); pdup["testAction"]="settle_invoice"
md={"messageId":"m-dup","contextId":"ctx-dup","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-dup","packages":[pdup]}}]}
rdup=client.post("/message:send",headers=H,json={"message":md})
assert rdup.status_code==200,rdup.text
assert rdup.json()["task"]["artifacts"][0]["parts"][0]["data"]["proposals"][0]["action"]=="reject_duplicate"
# Same amount and vendor, different invoice number remains independently payable.
new_task,new_prop,new_done=settle_and_continue("m-settle-2","INV-PAID-2","batch-settle-2","receipt-settle-2")
assert new_prop["action"]=="settle_invoice"

# Durability: reinitialising the app schema must not lose committed tasks/receipts.
main.init_db()
assert client.get(f"/tasks/{settled_done['id']}",headers={"Authorization":A,"A2A-Version":"1.0"}).status_code==200
assert client.get(f"/tasks/{settled_done['id']}",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["status"]["state"]=="TASK_STATE_COMPLETED"
assert client.get("/audit/receipts",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["receipts"]

# Audit retention limits prune per principal and event type.
os.environ["AUDIT_ACTION_CAP"]="2"
os.environ["AUDIT_RECEIPT_CAP"]="1"
with main.transaction() as con:
    for i in range(5):
        main.add_audit(con, main.principal_for_token("tenant-A"), "action", "cap-task", f"p{i}", "hold_invoice", None, {"i":i})
        main.add_audit(con, main.principal_for_token("tenant-A"), "receipt", "cap-task", f"p{i}", "hold_invoice", f"n{i}", {"i":i})
    main.prune_audit(con, main.principal_for_token("tenant-A"), "action")
    main.prune_audit(con, main.principal_for_token("tenant-A"), "receipt")
with main.db_conn() as con:
    assert con.execute("SELECT COUNT(*) AS n FROM invoice_a2a_audit WHERE principal=? AND event_type='action'", (main.principal_for_token("tenant-A"),)).fetchone()["n"]<=2
    assert con.execute("SELECT COUNT(*) AS n FROM invoice_a2a_audit WHERE principal=? AND event_type='receipt'", (main.principal_for_token("tenant-A"),)).fetchone()["n"]<=1

print("PASS: custom Agent Card, custom media modes, Bearer auth, version/media rejection, task isolation, proposal evidence, lifecycle continuation, receipt nonce binding, idempotent replay/conflict, cancellation, audit, and per-principal storage.")
os.unlink(_TMP.name)