# AutoLead AI V4 — Gemini 3 Flash
This is the V4 implementation baseline built from the V3 real-estate UI/features, with fabricated/demo lead generation removed.

## Setup
1. Node.js 20+
2. PostgreSQL
3. Run `database/schema.sql`
4. Copy `.env.example` to `.env`
5. Put your Gemini API key in `.env` as `GEMINI_API_KEY` (never in frontend or chat)
6. Keep `GEMINI_MODEL=gemini-3-flash-preview`
7. Set `JWT_SECRET` to a long random secret
8. `npm install`
9. `npm start`
10. Serve `frontend/` using a local/static web server and set `FRONTEND_ORIGIN`.

## What is included
- Agent signup/login
- Agent-level lead isolation
- Authorized CSV import
- Server-enforced 7-day / 10-lead trial
- No hard-coded/fake leads
- Gemini 3 Flash backend analysis
- Structured AI output
- Lead status updates
- Rate limiting, Helmet, validation and upload limits

## Still required before public launch
HTTPS/deployment, database backups, monitoring, stronger production session/security controls, payments/subscriptions, privacy/consent/legal review, real CRM integrations, and end-to-end security/load testing.
