"""Local smoke test for decision gates and idempotent invoice identity."""
import os
import tempfile

_tmp = tempfile.NamedTemporaryFile(prefix="invoice-agent-", suffix=".sqlite3", delete=False)
_tmp.close()
os.environ["DATABASE_PATH"] = _tmp.name
os.environ.pop("DATABASE_URL", None)

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
    message = {
        "messageId": message_id,
        "contextId": "smoke-test-context",
        "role": "user",
        "parts": [{"kind": "text", "text": text}],
    }
    task = main.process_invoice({"message": message}, message)
    return task["artifacts"][0]["parts"][0]["data"]


first = submit("req-1", "INV-100", "450.00", "500.00")
assert first["action"] == "PAY", first
assert first["payment"]["receipt"]["receipt_id"], first

same_invoice = submit("req-2", "INV-100", "450.00", "500.00", "not approved")
assert same_invoice["action"] == "DO_NOT_PAY_DUPLICATE", same_invoice

same_amount_new_invoice = submit("req-3", "INV-101", "450.00", "500.00")
assert same_amount_new_invoice["action"] == "PAY", same_amount_new_invoice

over_limit = submit("req-4", "INV-102", "900.00", "500.00")
assert over_limit["action"] == "REQUEST_APPROVAL", over_limit

same_message_retry = submit("req-1", "INV-999", "100.00", "200.00")
assert same_message_retry["task_id"] == first["task_id"] if "task_id" in first else same_message_retry["invoice"]["invoice_number"] == "INV-100"

print("PASS: payment receipt, same-invoice duplicate guard, distinct invoice identity, over-limit approval gate, and message replay.")
print("Ledger:", main.ledger_summary())
try:
    os.unlink(_tmp.name)
except OSError:
    pass
