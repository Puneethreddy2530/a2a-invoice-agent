# GA3 A2A Invoice Action Agent

This service implements the GA3 invoice **claim batch → action proposals → accepted/rejected results → receipts** workflow. It does not make bank transfers. It proposes an action for each package and only records an action as executed when the caller returns a valid result with a receipt nonce.

## A2A contract

- Public Agent Card: `GET /.well-known/agent-card.json`
- Public health: `GET /health`
- Protected message send: `POST /message:send`
- Protected task listing/get: `GET /tasks`, `GET /tasks/{task_id}`
- Protected cancellation: `POST /tasks/{task_id}:cancel`
- Protected audit: `GET /audit/actions`, `GET /audit/receipts`, `GET /audit`
- Protected isolation diagnostic: `GET /isolation-probe`

All protected requests require a non-empty `Authorization: Bearer <token>` and `A2A-Version: 1.0`. All POST requests require `Content-Type: application/a2a+json`.

The Agent Card advertises:

```text
Input:
  application/vnd.ga5.invoice-claim-batch+json
  application/vnd.ga5.invoice-action-results+json

Output:
  application/vnd.ga5.invoice-action-proposals+json
  application/vnd.ga5.invoice-action-receipts+json

Skill id: invoice_action_agent
Protocol: HTTP+JSON, version 1.0
```

An initial A2A message carries one `application/vnd.ga5.invoice-claim-batch+json` data part. Its data contains `batchId` and `packages`. The response is `{"task": ...}` and the task remains `TASK_STATE_INPUT_REQUIRED`; its proposal artifact has one action per package.

A continuation message includes the original `taskId` and `contextId` and one `application/vnd.ga5.invoice-action-results+json` data part. The data contains the same `batchId` and one result for every proposal. Each result must match the exact `packageId`, `actionId`, and `action`, and contain `outcome` (`ACCEPTED` or `REJECTED`) plus a non-empty `receiptNonce`. Only after all results validate does the task become `TASK_STATE_COMPLETED` and receive an `application/vnd.ga5.invoice-action-receipts+json` artifact.

## Business and safety rules

Allowed actions are `settle_invoice`, `request_approval`, `hold_invoice`, `reject_duplicate`, and `open_exception`.

The AI reads the full package and proposes one action with typed invoice facts, exactly three source-grounded evidence references, and a rationale citing at least two references. The validator rejects invented or missing references and malformed output. If the model is unavailable or returns invalid output, the service falls back to conservative rules that hold ambiguous cases rather than settle them.

Duplicate identity is normalized vendor name + normalized invoice number. Amount is not part of identity; different invoice numbers with the same amount are separate invoices. An accepted `settle_invoice` result is stored in the paid ledger; a later proposal for the same identity is converted to `reject_duplicate`. A payment is never marked settled when merely proposed.

## Persistence and isolation

PostgreSQL is used when `DATABASE_URL` is set; SQLite is available for local development. Task records, message replay keys, semantic proposal cache, accepted invoice identities, and bounded audit events are stored durably. Every record is scoped to a SHA-256 hash of the caller's Bearer token. The raw token is never stored. Another Bearer principal cannot list or retrieve a task belonging to a different principal.

Message replay is keyed by `(principal, messageId)`. Replaying the same message and body returns the stored task. Reusing the same message ID with a different body returns HTTP 409. Result submission and cancellation lock the same task row/transaction so the task cannot become both canceled and completed. No model call occurs for a stored message replay, task read, task list, cancellation, or receipt continuation.

Audit retention is configurable with `AUDIT_ACTION_CAP` and `AUDIT_RECEIPT_CAP` (defaults 500 and 200 per principal).

## Render environment

Set these environment variables in the Render Web Service:

```env
DATABASE_URL=<Render PostgreSQL Internal Database URL>
LLM_BASE_URL=https://aipipe.org/openrouter/v1
LLM_API_KEY=<private AI Pipe token>
LLM_MODEL=openai/gpt-4.1-nano
```

`PUBLIC_BASE_URL` is optional; leave it unset when Render's forwarded host/protocol headers correctly identify the public origin. Do not put credentials in the public A2A URL or commit them to GitHub.

The included Dockerfile uses Render's injected `PORT`. The health check is `/health`.

## Local tests

```powershell
pip install -r requirements.txt
python smoke_test.py
```

The smoke tests cover the custom Agent Card and media types, authentication, version rejection, per-Bearer task isolation, source-grounded evidence, input-required/complete/canceled lifecycle, receipt nonce binding, message replay/conflicts, different invoice numbers with the same amount, repeated invoice identity, audit retention, and concurrent identical submissions.