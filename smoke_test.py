"""Local protocol, lifecycle, audit, and idempotent payment regression tests."""
import os
import tempfile
import threading
from collections import Counter

_tmp = tempfile.NamedTemporaryFile(prefix="invoice-agent-", suffix=".sqlite3", delete=False)
_tmp.close()
os.environ["DATABASE_PATH"] = _tmp.name
os.environ.pop("DATABASE_URL", None)
os.environ.pop("A2A_API_TOKEN", None)

import main  # noqa: E402
main.init_db()


def submit(message_id: str, invoice_number: str, amount: str, limit: str, approval: str = "approved for payment"):
    text = (
        "Acme Supplies\n"
        f"Invoice Number: {invoice_number}\n"
        f"Invoice Total: USD {amount}\n"
        f"Approval limit: USD {limit}\n"
        f"Invoice {approval} by Finance Manager."
    )
    message = {"messageId": message_id, "contextId": "smoke-test-context", "role": "user", "parts": [{"text": text}]}
    return main.process_invoice({"message": message}, message)


def data(task):
    return task["artifacts"][0]["parts"][0]["data"]


# Payment receipt, identity-based duplicate, and distinct invoice with same amount.
first = submit("req-1", "INV-100", "450.00", "500.00")
assert data(first)["action"] == "PAY", data(first)
receipt = data(first)["payment"]["receipt"]
assert receipt["receipt_id"] and receipt["invoice_binding"]["invoice_number"] == "INV-100"
assert data(first)["evidence_ids"] and data(first)["decision_basis"]
assert data(first)["deduplication"]["amount_is_part_of_identity"] is False

same_invoice = submit("req-2", "INV-100", "450.00", "500.00", "not approved")
assert data(same_invoice)["action"] == "DO_NOT_PAY_DUPLICATE", data(same_invoice)
assert data(same_invoice)["payment"]["receipt"]["receipt_id"] == receipt["receipt_id"]

same_amount_new_invoice = submit("req-3", "INV-101", "450.00", "500.00")
assert data(same_amount_new_invoice)["action"] == "PAY", data(same_amount_new_invoice)
assert data(same_amount_new_invoice)["payment"]["receipt"]["receipt_id"] != receipt["receipt_id"]

over_limit = submit("req-4", "INV-102", "900.00", "500.00")
assert data(over_limit)["action"] == "REQUEST_APPROVAL", data(over_limit)
assert over_limit["status"]["state"] == "TASK_STATE_INPUT_REQUIRED"

# Same messageId + same payload is a persistent replay; different payload conflicts.
message = {"messageId": "req-5", "contextId": "smoke-test-context", "role": "user", "parts": [{"text": "Acme Supplies\nInvoice Number: INV-105\nInvoice Total: USD 25\nInvoice approved for payment. Approval limit: USD 30"}]}
replay_task = main.process_invoice({"message": message}, message)
replay_again = main.process_invoice({"message": message}, message)
assert replay_task["id"] == replay_again["id"]
conflicting = {"messageId": "req-5", "contextId": "smoke-test-context", "role": "user", "parts": [{"text": "Different request"}]}
try:
    main.process_invoice({"message": conflicting}, conflicting)
    raise AssertionError("reused messageId with a different body was accepted")
except main.AgentError as exc:
    assert exc.code == "IDEMPOTENCY_KEY_REUSED"

# Continue an approval-required task with approval evidence; same task id, same context.
initial_msg = {"messageId": "req-6", "contextId": "continuation-context", "role": "user", "parts": [{"text": "Acme Supplies\nInvoice Number: INV-106\nInvoice Total: USD 200\nApproval limit: USD 250"}]}
waiting = main.process_invoice({"message": initial_msg}, initial_msg)
assert waiting["status"]["state"] == "TASK_STATE_INPUT_REQUIRED", waiting
approval_msg = {"messageId": "req-7", "contextId": "continuation-context", "role": "user", "parts": [{"text": "Invoice INV-106 approved for payment by Finance Manager."}]}
continued = main.process_invoice({"taskId": waiting["id"], "contextId": "continuation-context", "message": approval_msg}, approval_msg)
assert continued["id"] == waiting["id"]
assert data(continued)["action"] == "PAY", data(continued)

# Invalid continuation on a completed task must be rejected.
try:
    main.process_invoice({"taskId": first["id"], "contextId": first["contextId"], "message": {"messageId": "req-8", "parts": [{"text": "try to continue"}]}}, {"messageId": "req-8", "parts": [{"text": "try to continue"}]})
    raise AssertionError("completed task accepted a continuation")
except main.AgentError as exc:
    assert exc.code == "INVALID_CONTINUATION"

# Task cancel is allowed for input-required work but cannot cancel a paid task.
canceled = main.cancel_task(waiting["id"] + "-not-found")
assert hasattr(canceled, "status_code") and canceled.status_code == 404
blocked_cancel = main.cancel_task(first["id"])
assert hasattr(blocked_cancel, "status_code") and blocked_cancel.status_code == 409
cancel_msg = {"messageId": "req-cancel", "contextId": "cancel-context", "role": "user", "parts": [{"text": "Acme Supplies\nInvoice Number: INV-CANCEL\nInvoice Total: USD 10\nApproval limit: USD 50"}]}
cancel_waiting = main.process_invoice({"message": cancel_msg}, cancel_msg)
assert cancel_waiting["status"]["state"] == "TASK_STATE_INPUT_REQUIRED"
cancelled = main.cancel_task(cancel_waiting["id"])
assert cancelled["status"]["state"] == "TASK_STATE_CANCELED"

# Auth and protocol-level checks via ASGI test client.
try:
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    assert client.get("/tasks").status_code == 401
    assert client.post("/message:send", json={}).status_code == 401
    card = client.get("/.well-known/agent-card.json").json()
    assert card["supportedInterfaces"][0]["url"].endswith("/")
    assert card["url"].endswith("/")
    assert any(skill["id"] == "invoice-processing" for skill in card["skills"])
    assert "application/a2a+json" in card["defaultInputModes"]
    assert card["skills"] and card["security"]
    assert client.post("/message:send", headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"}, json={}).status_code == 415
    assert client.post("/message:send", headers={"Authorization": "Bearer test-token", "Content-Type": "application/a2a+json", "A2A-Version": "99.0"}, content=b"{}").status_code == 400
    assert client.get("/tasks", headers={"Authorization": "Bearer test-token"}).status_code == 200
    assert client.post("/tasks/not-a-task:cancel").status_code == 401
    assert client.post("/tasks/cancel", headers={"Authorization": "Bearer test-token", "Content-Type": "application/a2a+json"}, json={"id": "missing"}).status_code == 404
    # Domain conflicts on HTTP+JSON message:send remain A2A task responses
    # (HTTP 200) with a failed task and explicit error payload, not transport 409.
    h = {"Authorization": "Bearer test-token", "Content-Type": "application/a2a+json", "A2A-Version": "1.0"}
    body_a = {"message": {"messageId": "http-conflict-1", "contextId": "http-conflict", "role": "user", "parts": [{"text": "first payload"}]}}
    first_http = client.post("/message:send", headers=h, json=body_a)
    assert first_http.status_code == 200, first_http.text
    body_b = {"message": {"messageId": "http-conflict-1", "contextId": "http-conflict", "role": "user", "parts": [{"text": "different payload"}]}}
    conflict_http = client.post("/message:send", headers=h, json=body_b)
    assert conflict_http.status_code == 200, conflict_http.text
    conflict_data = conflict_http.json()["artifacts"][0]["parts"][0]["data"]
    assert conflict_http.json()["status"]["state"] == "TASK_STATE_FAILED"
    assert conflict_data["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"
    assert conflict_data["side_effects"] == "none"
    invalid_continuation = client.post("/message:send", headers=h, json={"taskId": first["id"], "message": {"messageId": "http-invalid-cont", "contextId": first["contextId"], "parts": [{"text": "should not continue"}]}})
    assert invalid_continuation.status_code == 409, invalid_continuation.text
except Exception as exc:
    if exc.__class__.__name__ == "TypeError" and "TestClient" in str(exc):
        print("NOTE: ASGI TestClient is unavailable in this environment; protocol checks skipped.")
    else:
        raise

# Persisted replay survives database reinitialization (as on process restart).
main.init_db()
assert main.process_invoice({"message": message}, message)["id"] == replay_task["id"]

# Concurrent copies of the same invoice can reserve/settle at most once.
barrier = threading.Barrier(6)
race_results = []
race_errors = []
def race_worker(index):
    msg = {"messageId": f"race-{index}", "contextId": "race-context", "role": "user", "parts": [{"text": "Acme Race Supplies\nInvoice Number: RACE-777\nInvoice Total: USD 77.00\nApproval limit: USD 100.00\nInvoice RACE-777 approved for payment."}]}
    try:
        barrier.wait()
        task = main.process_invoice({"message": msg}, msg)
        race_results.append(data(task))
    except Exception as exc:
        race_errors.append(repr(exc))
threads = [threading.Thread(target=race_worker, args=(i,)) for i in range(6)]
for thread in threads: thread.start()
for thread in threads: thread.join()
assert not race_errors and len(race_results) == 6, race_errors
assert sum(item["action"] == "PAY" for item in race_results) == 1, Counter(item["action"] for item in race_results)
assert all(item["action"] in {"PAY", "DO_NOT_PAY_DUPLICATE", "HOLD_FOR_RECONCILIATION"} for item in race_results)
receipts = {
    item.get("payment", {}).get("receipt", {}).get("receipt_id")
    for item in race_results
    if isinstance(item.get("payment", {}).get("receipt"), dict)
    and item["payment"]["receipt"].get("receipt_id")
}
assert len(receipts) == 1, receipts

# Audit retention caps are enforced independently for actions and receipts.
os.environ["AUDIT_ACTION_CAP"] = "2"
os.environ["AUDIT_RECEIPT_CAP"] = "1"
for n in range(5):
    main.write_audit("action", None, None, f"CAP_TEST_{n}", {})
for n in range(3):
    main.write_audit("receipt", None, None, "CAP_RECEIPT", {"receipt_id": f"cap-{n}"})
with main.db_conn() as conn:
    assert conn.execute("SELECT COUNT(*) AS n FROM audit_events WHERE event_type='action'").fetchone()["n"] <= 2
    assert conn.execute("SELECT COUNT(*) AS n FROM audit_events WHERE event_type='receipt'").fetchone()["n"] <= 1

assert main.isolation_probe()["available"] is True
assert len(main.audit_actions(type("R", (), {"headers": {"authorization": "Bearer test-token"}})())["events"]) >= 1
assert len(main.audit_receipts(type("R", (), {"headers": {"authorization": "Bearer test-token"}})())["receipts"]) >= 1
print("PASS: receipt binding, identity dedupe, distinct-invoice payment, approval continuation, idempotency conflict, persistent replay, task lifecycle, cancellation safety, Bearer auth, A2A media/version rejection, bounded audit, isolation probe and concurrent exactly-once settlement.")

try:
    os.unlink(_tmp.name)
except OSError:
    pass
