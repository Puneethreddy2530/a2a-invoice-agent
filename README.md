# A2A Invoice Agent

A public HTTPS A2A invoice-processing service. It extracts invoice and approval facts with an OpenAI-compatible LLM, verifies that cited quotations occur in the supplied documents, applies deterministic payment gates, stores task/payment state, and returns a receipt when settlement succeeds.

## 1. What it implements

- A2A JSON-RPC at `POST /` (also `/a2a/`, `/a2a`, and `/a2a/json`).
- A2A HTTP+JSON message endpoint at `POST /message:send`; A2A POSTs require `Content-Type: application/a2a+json`.
- Agent discovery at `GET /.well-known/agent-card.json` and the legacy `GET /.well-known/agent.json`.
- Public `GET /health` and `GET /.well-known/agent-card.json`; Bearer-protected `GET /tasks`, `GET /tasks/{task_id}`, audit endpoints and ledger summary.
- Text parts, structured data parts, legacy base64 FileParts, A2A raw-file parts, and HTTP(S) document URLs. PDF text is extracted with PyMuPDF.
- AI extraction through an OpenAI-compatible Chat Completions endpoint. The model is used to understand the package; deterministic controls decide whether a payment can proceed.
- Evidence citations. Each quote returned as evidence must be a verbatim substring of the referenced document.
- Durable task, message replay, invoice, receipt-binding and bounded audit records in SQLite (local) or PostgreSQL (recommended for cloud hosting).
- Invoice identity is `normalized vendor + normalized invoice number`. Amount is deliberately NOT part of the duplicate key. A different invoice number with the same amount can be paid separately.
- Atomic payment reservation, deterministic idempotency key, persistent request replay, task continuation/cancellation, stored receipt binding, and no automatic retry after an uncertain external payment outcome.

## 2. Payment safety rules

The agent pays only when all identity fields and a positive amount are extracted, there is explicit invoice approval or a documented automatic-approval policy, and the amount is within the documented/configured limit (or within an explicit approved amount).

It requests approval when the evidence is insufficient or the amount is above the limit. It holds disputed invoices, invoices with changed bank details, and uncertain payment outcomes. A void/cancelled invoice is rejected.

The ledger checks an exact invoice identity before processing any new copy. A previously paid invoice is marked `DO_NOT_PAY_DUPLICATE`; the same invoice identity with a different amount is held as an identity conflict. A different invoice number is a different invoice, even if its amount is identical.

**Sandbox note:** with no `PAYMENT_EXECUTOR_URL`, a successful `PAY` action creates a durable *simulated* receipt in the local ledger. It does not move real money. To connect a real/sandbox payment service, set `PAYMENT_EXECUTOR_URL` to the payment endpoint explicitly supplied by your assignment or payment provider. The agent sends a stable `Idempotency-Key` and expects a receipt identifier (`receipt_id`, `id`, or `payment_id`). If the result is uncertain or no receipt identifier is returned, it blocks retries and reports `HOLD_FOR_RECONCILIATION`.

## 3. Configure an AI provider

For an IITM AI Pipe token, use these environment variables in your hosting dashboard (do not commit the token to GitHub and do not paste it into the assignment URL field):

```env
LLM_BASE_URL=https://aipipe.org/openrouter/v1
LLM_API_KEY=YOUR_AIPIPE_TOKEN
LLM_MODEL=openai/gpt-4.1-nano
```

A native OpenAI-compatible provider or a local Ollama OpenAI-compatible server can also be used by changing `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`. If AI credentials are absent or the model endpoint fails, the service falls back to conservative text rules; configure a working model for the assignment's AI-understanding requirement.

## 4. Run locally (Windows PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:LLM_BASE_URL = "https://aipipe.org/openrouter/v1"
$env:LLM_API_KEY = "YOUR_AIPIPE_TOKEN"
$env:LLM_MODEL = "openai/gpt-4.1-nano"
$env:DATABASE_PATH = ".\data\invoices.sqlite3"

uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000/health` to verify the app. A local URL is not accepted by the assignment; deploy it to a public HTTPS host before submitting.

## 5. Deploy publicly on Render

1. Extract this project ZIP and upload the files to a new GitHub repository (the `Dockerfile`, `main.py`, `requirements.txt`, and `render.yaml` must be at the repository root).
2. In Render, create a **PostgreSQL** database. Copy its **Internal Database URL**.
3. Create a **Web Service** connected to that GitHub repository. Select Docker/runtime from the included `Dockerfile`; Render detects it automatically.
4. Add these environment variables to the Web Service:

   ```env
   DATABASE_URL=<the PostgreSQL Internal Database URL>
   LLM_BASE_URL=https://aipipe.org/openrouter/v1
   LLM_API_KEY=<your AI Pipe token>
   LLM_MODEL=openai/gpt-4.1-nano
   A2A_API_TOKEN=<optional long random token; omit if evaluator supplies its own Bearer token>
   ```

5. Deploy. The Agent Card derives its public origin from the incoming HTTPS request. You may set `PUBLIC_BASE_URL` to the service's HTTPS origin (no trailing slash) if your host sits behind a proxy that does not forward the public host/protocol headers.
6. Verify these URLs in a browser:
   - `https://your-agent.onrender.com/health`
   - `https://your-agent.onrender.com/.well-known/agent-card.json`
7. Enter the service origin **`https://your-agent.onrender.com/`** into the assignment's **A2A interface base URL** field. The Agent Card advertises this exact root interface; the JSON-RPC binding is also available at `/a2a/`.

Use PostgreSQL for cloud state. Do not rely on SQLite on a free Render web instance: its local filesystem is ephemeral. Render's free Postgres is persistent across web-service restarts but has a 30-day lifetime, so use a longer-lived managed Postgres database if the assignment needs state beyond that period.

## 6. A2A request contract

### JSON-RPC (recommended)

`POST https://<host>/` (or `POST https://<host>/a2a/`) with `Content-Type: application/a2a+json` and a non-empty `Authorization: Bearer <token>` header.

```json
{
  "jsonrpc": "2.0",
  "id": "request-1",
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "unique-message-id-1",
      "role": "user",
      "parts": [
        {
          "kind": "text",
          "text": "Please review the attached invoice package."
        },
        {
          "kind": "file",
          "file": {
            "name": "invoice.pdf",
            "mimeType": "application/pdf",
            "bytes": "BASE64_ENCODED_FILE_BYTES"
          }
        }
      ]
    }
  }
}
```

The endpoint also accepts A2A raw file parts (`{"raw":"BASE64...","mediaType":"application/pdf","filename":"invoice.pdf"}`) and data parts (`{"data":{"documents":[{"name":"invoice.txt","text":"..."}]}}`). `SendMessage` and `message:send` method aliases are accepted as well.

### HTTP+JSON

`POST https://<host>/message:send` with `Content-Type: application/a2a+json` and a non-empty `Authorization: Bearer <token>` header.

```json
{
  "message": {
    "messageId": "unique-message-id-2",
    "role": "user",
    "parts": [
      {"text": "Vendor: Acme Supplies\nInvoice Number: INV-100\nInvoice Total: USD 450.00"},
      {"data": {"documents": [
        {"name": "approval.txt", "text": "Invoice INV-100 approved for payment. Approval limit: USD 500."}
      ]}}
    ]
  }
}
```

### Response

The JSON-RPC response contains a task with an `artifacts` array. The `invoice-decision` artifact includes a structured `data` part and a readable `text` part. The structured result includes:

- `action`: `PAY`, `REQUEST_APPROVAL`, `REQUEST_INFORMATION`, `REJECT`, `HOLD`, `DO_NOT_PAY_DUPLICATE`, `HOLD_INVOICE_IDENTITY_CONFLICT`, or a reconciliation/review hold.
- `status.state`: `TASK_STATE_INPUT_REQUIRED` while awaiting clarification/approval, otherwise `TASK_STATE_COMPLETED`. Continuations use the original `taskId` and matching `contextId`.
- `messageId` replay returns the exact persisted task for the same payload; reusing a message ID with a different payload is rejected as an idempotency conflict.
- Task listing/get/send, audit, and ledger routes require a Bearer token. Set `A2A_API_TOKEN` in production to validate a specific token; if unset, the service enforces Bearer-token presence for compatibility with evaluators that supply their own token.
- Unsupported `A2A-Version` values are rejected with HTTP 400. A2A POSTs with a media type other than `application/a2a+json` are rejected with HTTP 415.
- `invoice`: vendor, invoice number, amount, currency, date and PO reference.
- `approval`: explicit approval, approver, approved amount and policy limit.
- `evidence`: document id, document name, claim and exact supporting quotation.
- `payment`: status and receipt, when applicable.
- `ai_understanding`: whether the configured model successfully extracted the package.

## 7. Smoke test

After installing requirements, run:

```powershell
python smoke_test.py
```

The test checks receipt binding, invoice-identity duplicate detection, a distinct invoice with the same amount, over-limit approval, continuation lifecycle, persistent message replay, idempotency-key conflict, protected task routes, A2A media/version rejection, cancellation safety, bounded audit and the database isolation probe. No live payment provider is called.

## 8. Security and operations

- Treat all invoice contents as untrusted data; document instructions cannot override policy.
- Never commit AI tokens, payment credentials, database URLs or receipts containing sensitive details.
- Do not set a payment executor URL unless it is the real assignment/provider endpoint and you have confirmed its sandbox semantics.
- The code blocks local/private HTTP document URLs as a basic SSRF safeguard and caps downloaded file sizes.
- Use a managed database for cloud state. PostgreSQL serializes invoice reservations with a database lock and a unique invoice-identity key, preventing concurrent workers from settling the same invoice twice.
- The default local settlement is a demonstration ledger, not a real financial transfer.