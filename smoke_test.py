"""Contract smoke tests for the GA3 invoice claim/proposal/receipt workflow."""
import os
import json
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
            {"documentId":"DOC-PO-1","text":"Purchase order matched [DOC-PO-1]. Goods received and GRN accepted [DOC-GRN-1]."},
            {"documentId":"DOC-APPROVAL-1","text":"Invoice explicitly approved for payment by Alice; approval status: approved [DOC-APPROVAL-1]. Vendor bank details verified and unchanged [DOC-BANK-1]."},
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
assert all(x.strip("[]") in json.dumps(msg["parts"][0]["data"]["packages"][0]) for x in proposal["evidenceRefs"])

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

# Case-specific controls: each invoice is classified from its own controlling facts.
case_packages=[]
base_safe=package("case-safe","INV-CASE-SAFE"); base_safe["testAction"]="settle_invoice"; case_packages.append(base_safe)
pending=package("case-approval","INV-CASE-APPROVAL"); pending["testAction"]="settle_invoice"; pending["approvalStatus"]="pending"; case_packages.append(pending)
bank=package("case-bank","INV-CASE-BANK"); bank["testAction"]="settle_invoice"; bank["bankDetailsChanged"]=True; case_packages.append(bank)
dispute=package("case-dispute","INV-CASE-DISPUTE"); dispute["testAction"]="settle_invoice"; dispute["disputed"]=True; case_packages.append(dispute)
paid_case=package("case-duplicate","INV-CASE-DUP"); paid_case["testAction"]="settle_invoice"; paid_case["paymentHistory"]=[{"invoiceNumber":"INV-CASE-DUP","status":"paid"}]; case_packages.append(paid_case)
case_msg={"messageId":"m-case-matrix","contextId":"ctx-case-matrix","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-case-matrix","packages":case_packages}}]}
case_resp=client.post("/message:send",headers=H,json={"message":case_msg})
assert case_resp.status_code==200,case_resp.text
case_actions={x["packageId"]:x["action"] for x in case_resp.json()["task"]["artifacts"][0]["parts"][0]["data"]["proposals"]}
assert case_actions=={"case-safe":"settle_invoice","case-approval":"request_approval","case-bank":"open_exception","case-dispute":"hold_invoice","case-duplicate":"reject_duplicate"},case_actions

over=package("case-over-limit","INV-OVER-LIMIT"); over["testAction"]="settle_invoice"; over["approvalLimitMinor"]=5000
limit_msg={"messageId":"m-over-limit","contextId":"ctx-over-limit","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-over-limit","packages":[over]}}]}
limit_resp=client.post("/message:send",headers=H,json={"message":limit_msg})
assert limit_resp.status_code==200,limit_resp.text
assert limit_resp.json()["task"]["artifacts"][0]["parts"][0]["data"]["proposals"][0]["action"]=="request_approval"
settlement_cap=package("case-settlement-cap","INV-SETTLEMENT-CAP"); settlement_cap["testAction"]="settle_invoice"; settlement_cap["settlementCapMinor"]=5000
cap_msg={"messageId":"m-settlement-cap","contextId":"ctx-settlement-cap","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-settlement-cap","packages":[settlement_cap]}}]}
cap_resp=client.post("/message:send",headers=H,json={"message":cap_msg})
assert cap_resp.status_code==200,cap_resp.text
assert cap_resp.json()["task"]["artifacts"][0]["parts"][0]["data"]["proposals"][0]["action"]=="request_approval"
# The request is bounded before inference/action creation.
over_batch={"messageId":"m-over-batch-cap","contextId":"ctx-over-batch-cap","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-over-batch-cap","packages":[package(f"cap-{i}",f"INV-CAP-{i}") for i in range(101)]}}]}
assert client.post("/message:send",headers=H,json={"message":over_batch}).status_code==400

# Durability: reinitialising the app schema must not lose committed tasks/receipts.
main.init_db()
assert client.get(f"/tasks/{settled_done['id']}",headers={"Authorization":A,"A2A-Version":"1.0"}).status_code==200
assert client.get(f"/tasks/{settled_done['id']}",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["status"]["state"]=="TASK_STATE_COMPLETED"
assert client.get("/audit/receipts",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["receipts"]
# Initial message and completed continuation both replay from persistent storage after re-init.
settle_initial_msg={"messageId":"m-settle-1","contextId":"ctx-m-settle-1","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-settle-1","packages":[{**package("settle-m-settle-1","INV-PAID-1"),"testAction":"settle_invoice"}]}}]}
assert client.post("/message:send",headers=H,json={"message":settle_initial_msg}).json()["task"]["id"]==settled_task["id"]
settle_result_msg={"messageId":"m-settle-1-result","contextId":settled_task["contextId"],"taskId":settled_task["id"],"role":"user","parts":[{"mediaType":RESULTS,"data":{"batchId":"batch-settle-1","results":[{"packageId":settled_proposal["packageId"],"actionId":settled_proposal["actionId"],"action":settled_proposal["action"],"outcome":"ACCEPTED","receiptNonce":"receipt-settle-1"}]}}]}
assert client.post("/message:send",headers=H,json={"message":settle_result_msg}).json()["task"]["id"]==settled_done["id"]

# Cancel-vs-receipt race: exactly one terminal transition wins.
race_pkg=package("pkg-cancel-race","INV-CANCEL-RACE"); race_pkg["testAction"]="settle_invoice"
race_msg={"messageId":"m-cancel-race-init","contextId":"ctx-cancel-race","role":"user","parts":[{"mediaType":BATCH,"data":{"batchId":"batch-cancel-race","packages":[race_pkg]}}]}
race_created=client.post("/message:send",headers=H,json={"message":race_msg}); assert race_created.status_code==200,race_created.text
race_task=race_created.json()["task"]
race_prop=race_task["artifacts"][0]["parts"][0]["data"]["proposals"][0]
race_result={"messageId":"m-cancel-race-result","contextId":race_task["contextId"],"taskId":race_task["id"],"role":"user","parts":[{"mediaType":RESULTS,"data":{"batchId":"batch-cancel-race","results":[{"packageId":race_prop["packageId"],"actionId":race_prop["actionId"],"action":race_prop["action"],"outcome":"ACCEPTED","receiptNonce":"nonce-cancel-race"}]}}]}
from threading import Barrier
barrier=Barrier(2)
def race_cancel(_):
    barrier.wait()
    return client.post(f"/tasks/{race_task['id']}:cancel",headers=H)
def race_receipt(_):
    barrier.wait()
    return client.post("/message:send",headers=H,json={"message":race_result})
with ThreadPoolExecutor(max_workers=2) as pool:
    f_cancel=pool.submit(race_cancel,0); f_receipt=pool.submit(race_receipt,1)
    cancel_response=f_cancel.result(); receipt_response=f_receipt.result()
assert sorted([cancel_response.status_code,receipt_response.status_code])==[200,409],(cancel_response.status_code,receipt_response.status_code,cancel_response.text,receipt_response.text)
race_final=client.get(f"/tasks/{race_task['id']}",headers={"Authorization":A,"A2A-Version":"1.0"}).json()
assert race_final["status"]["state"] in {"TASK_STATE_CANCELED","TASK_STATE_COMPLETED"}
late_result={**race_result,"messageId":"m-cancel-race-late"}
if race_final["status"]["state"]=="TASK_STATE_CANCELED":
    assert client.post("/message:send",headers=H,json={"message":late_result}).status_code==409
else:
    assert client.post(f"/tasks/{race_task['id']}:cancel",headers=H).status_code==409

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
assert len(client.get("/audit/actions?limit=5000",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["events"])<=2
assert len(client.get("/audit/receipts?limit=5000",headers={"Authorization":A,"A2A-Version":"1.0"}).json()["receipts"])<=1

print("PASS: custom Agent Card, custom media modes, Bearer auth, version/media rejection, task isolation, proposal evidence, lifecycle continuation, receipt nonce binding, idempotent replay/conflict, cancellation, audit, and per-principal storage.")
os.unlink(_TMP.name)