# GA3 A2A Invoice Action Agent

This service implements the GA3 invoice **claim batch → action proposals → accepted/rejected results → receipts** workflow. It does not make bank transfers. It proposes an action for each package and only records an action as executed when the caller returns a valid result with a receipt nonce.

## A2A contract

- Public Agent Card: `GET /.well-known/agent-card.json`
- Public health: `GET /health`
- A2A interface base URL: `https://<host>/a2a/`
- Protected message send: `POST /a2a/message:send`
- Protected task listing/get: `GET /a2a/tasks`, `GET /a2a/tasks/{task_id}`
- Protected cancellation: `POST /a2a/tasks/{task_id}:cancel`
- Protected audit: `GET /a2a/audit/actions`, `GET /a2a/audit/receipts`
- Protected isolation diagnostic: `GET /a2a/isolation-probe`
- Root aliases are also provided for compatibility.

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

The AI reads the full package and proposes one action with typed invoice facts, exactly three canonical source-grounded evidence IDs (without surrounding display brackets), and a rationale quoting the supporting source text. The validator rejects invented or missing references and malformed output. A package-specific safety layer then applies its own controlling facts: exact paid-invoice identity, void/dispute flags, bank-detail changes, PO mismatches, approval state, amount-vs-approval/delegated/settlement caps, goods receipt or service acceptance, and vendor/bank verification. A proposed settlement is downgraded unless the evidence establishes all mandatory clearances. One invoice's warning does not impose a blanket action on unrelated packages. If the model is unavailable or returns invalid output, the service falls back to conservative per-package rules that hold ambiguous cases rather than settle them.

Duplicate identity is normalized vendor name + normalized invoice number. Amount is not part of identity; different invoice numbers with the same amount are separate invoices. An accepted `settle_invoice` result is stored in the paid ledger; a later proposal for the same identity is converted to `reject_duplicate`. A payment is never marked settled when merely proposed.

## Persistence and isolation

PostgreSQL is used when `DATABASE_URL` is set; SQLite is available for local development. Task records, message replay keys, semantic proposal cache, accepted invoice identities, and bounded audit events are stored durably. Every record is scoped to a SHA-256 hash of the caller's Bearer token. The raw token is never stored. Another Bearer principal cannot list or retrieve a task belonging to a different principal.

Message replay is keyed by `(principal, messageId)`. Replaying the same message and body returns the stored task; after completion or cancellation, every message associated with the task is updated to replay the same immutable terminal Task. Reusing the same message ID with a different body returns HTTP 409. Result submission and cancellation lock the same task row/transaction so the task cannot become both canceled and completed. No model call occurs for a stored message replay, task read, task list, cancellation, or receipt continuation.

Audit retention is configurable with `AUDIT_ACTION_CAP` and `AUDIT_RECEIPT_CAP` (defaults 100 each per principal). API list limits are clamped to the configured retention cap. A claim batch is limited to 100 packages (`MAX_PACKAGES`, configurable downward; values above 100 are clamped).

## Render environment

Set these environment variables in the Render Web Service:

```env
DATABASE_URL=<Render PostgreSQL Internal Database URL>
LLM_BASE_URL=https://aipipe.org/openrouter/v1
LLM_API_KEY=<private AI Pipe token>
LLM_MODEL=openai/gpt-4.1-mini
```

`PUBLIC_BASE_URL` is optional; leave it unset when Render's forwarded host/protocol headers correctly identify the public origin. The `/health` endpoint reports whether AI is configured, the selected model, and a safe last-call status (never the token). Do not put credentials in the public A2A URL or commit them to GitHub.

The included Dockerfile uses Render's injected `PORT`. The health check is `/health`.

## Local tests

```powershell
pip install -r requirements.txt
python smoke_test.py
```

The smoke tests cover the custom Agent Card and media types, authentication, version rejection, per-Bearer task isolation, source-grounded evidence, package-specific business dispositions, approval/settlement caps, input-required/complete/canceled lifecycle, receipt nonce binding, message replay/conflicts, different invoice numbers with the same amount, repeated invoice identity, audit retention/API caps, concurrent identical submissions, and cancel-vs-receipt race arbitration.