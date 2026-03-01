<div align="center">

# 🛡️ PhishGuard

### AI-Powered Phishing Detection Platform

*Heuristics · Threat Intel · Machine Learning · LLM Analysis · Full Auth*

---

**Author : [Anas TAGUI](https://github.com/taguianas)**

### 🌐 [Live Demo](https://phishguard-frontend-7ir8.onrender.com)

</div>

---

A full-stack cybersecurity platform that analyzes URLs and emails for phishing threats,
combining heuristic rules, typosquatting detection, threat intelligence APIs, a
trained XGBoost classifier, and LLM-based email analysis, all behind a complete
user authentication system with per-user data isolation.

---

## Architecture

```
phish-guard/
 ├── frontend/       Next.js 16.1.6 (App Router) + TailwindCSS + NextAuth.js v5
 ├── backend/        Node.js + Express API (JWT-protected)
 ├── ml-service/     Python FastAPI + XGBoost (trained model included)
 ├── browser-extension/  Chrome Manifest V3 extension
 └── tests/          End-to-end test suite (Python)
```

**Data storage:**
- `backend/data/phishguard.db` : SQLite scan history (url_scans, email_scans), filtered by user
- `frontend/data/auth.db` : SQLite user accounts (email/password via bcrypt, Google OAuth)

---

## Current Status

| Service | Port | State |
|---------|------|-------|
| Frontend (Next.js 16) | 3000 | Ready : auth enabled |
| Backend (Express) | 4000 | Ready : JWT-protected |
| ML Service (FastAPI) | 8000 | Ready : model trained |

---

## Quick Start

### 1. Backend

```bash
cd backend
cp .env.example .env          # fill in API keys + NEXTAUTH_SECRET
npm install
npm run dev                   # http://localhost:4000
```

### 2. ML Service

```bash
cd ml-service
pip install -r requirements.txt

# Build the dataset (downloads ~789k phishing URLs automatically)
python build_dataset.py       # creates data/urls.csv (100k rows)

# Train the model
python train_model.py         # creates model.pkl

# Start the API
python -m uvicorn main:app --port 8000
```

### 3. Frontend

```bash
cd frontend
cp .env.local.example .env.local   # fill in NEXTAUTH_SECRET (same as backend)
npm install
npm run dev                        # http://localhost:3000
```

> **First run:** visit `http://localhost:3000` : you will be redirected to `/register` to create your account.

---

## User Authentication

PhishGuard requires a user account to access any page or API endpoint.

- **Email + password** registration and login (bcrypt-hashed, stored in `frontend/data/auth.db`)
- **Google OAuth** : enable by setting `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `frontend/.env.local`
- **Session strategy:** JWT (NextAuth v5, `authjs.session-token` cookie)
- **Route protection:** Next.js middleware redirects unauthenticated requests to `/login`, preserving `?callbackUrl`
- **Backend protection:** Every Express route verifies the JWT from `Authorization: Bearer <token>` using the shared `NEXTAUTH_SECRET`
- **Data isolation:** Each user sees only their own scan history : all queries filter by `user_id`

### Auth flow

```
Browser                 Next.js (3000)              Express (4000)
  |-- POST /api/auth/register -->|                        |
  |<-- 201 {"ok":true} ----------|                        |
  |-- POST /api/auth/callback -->|                        |
  |<-- authjs.session-token ckv--|                        |
  |-- POST /api/analyze/url ---->|                        |
  |                   getToken() |-- Bearer <JWT> ------->|
  |                              |<-- analysis JSON -------|
  |<-- analysis JSON ------------|                        |
```

The frontend proxy routes (`/api/analyze/*`) extract the session token server-side using `getToken()` and re-sign a backend-compatible JWT using `jose`. The raw token never reaches the browser.

---

## API Endpoints

### Frontend Proxy (port 3000) : requires session cookie

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/analyze/url` | Analyze a URL (proxies to backend, adds auth header) |
| POST | `/api/analyze/email` | Analyze email content (proxies to backend) |
| GET | `/api/analyze/history` | Fetch user's scan history |
| GET | `/api/analyze/history?type=stats` | Fetch user's scan stats |
| POST | `/api/auth/register` | Register a new account |
| GET/POST | `/api/auth/[...nextauth]` | NextAuth.js handlers (login, session, signout, CSRF) |

### Backend (port 4000) : requires `Authorization: Bearer <JWT>`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/url/analyze` | Analyze a URL for phishing risk |
| POST | `/api/email/analyze` | Analyze email content |
| GET | `/api/history` | User's scan history |
| GET | `/api/history/stats` | User's aggregate stats |
| GET | `/health` | Health check (public) |

### ML Service (port 8000) : public (internal use)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/predict` | Classify a URL (returns prediction + probability + features) |
| GET | `/health` | Health check + model load status |

#### URL Analyze : Response Example
```json
{
  "url": "http://paypa1.com/login",
  "risk_score": 65,
  "classification": "Medium Risk",
  "reasons": [
    "Suspicious keyword(s): login",
    "Not using HTTPS",
    "Possible typosquatting of \"paypal\" (distance: 1)",
    "Blacklisted by VirusTotal (9 engines)"
  ],
  "threat_intel": { "malicious": 9, "suspicious": 1, "harmless": 58, "blacklisted": true },
  "ml_prediction": { "prediction": "Phishing", "probability": 1.0 }
}
```

#### ML Predict : Response Example
```json
{
  "url": "http://paypa1-security-update.com/login",
  "prediction": "Phishing",
  "probability": 1.0,
  "features": { "is_https": 0, "has_suspicious_tld": 0, "suspicious_keyword_count": 2, "brand_impersonation": 1 }
}
```

---

## ML Service : Dataset & Model

### Dataset (`data/urls.csv`)

Built by `build_dataset.py` using two sources:

| Source | Count | Label |
|--------|-------|-------|
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (active phishing URLs) | 50,000 | 1 (Phishing) |
| Generated from 100 known-trusted domains (Google, GitHub, PayPal, etc.) | 50,000 | 0 (Legitimate) |
| **Total** | **100,000** | balanced |

### Model (`model.pkl`)

| Property | Value |
|----------|-------|
| Algorithm | XGBoost (200 estimators, depth 6) |
| Features | 20 URL structural features |
| Test accuracy | 100% (20,000 held-out samples) |
| Train/test split | 80/20, stratified |

### Features Extracted

`url_length`, `hostname_length`, `path_length`, `num_dots`, `num_hyphens`,
`num_underscores`, `num_slashes`, `num_question_marks`, `num_equals`, `num_at`,
`num_percent`, `num_ampersand`, `has_ip`, `is_https`, `has_www`,
`has_encoded_chars`, `suspicious_keyword_count`, `has_suspicious_tld`,
`subdomain_count`, `brand_impersonation`

---

## Environment Variables

### Backend `.env`
| Variable | Description |
|----------|-------------|
| `PORT` | Backend port (default 4000) |
| `NEXTAUTH_SECRET` | **Required** : shared JWT secret (same value as frontend) |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing API key (free, 10k req/day) |
| `ML_SERVICE_URL` | ML microservice URL (default `http://localhost:8000`) |
| `ALLOWED_ORIGINS` | Comma-separated allowed CORS origins |
| `GROQ_API_KEY` | Groq API key for LLM email classification (free at console.groq.com) |

### Frontend `.env.local`
| Variable | Description |
|----------|-------------|
| `NEXTAUTH_SECRET` | **Required** : shared JWT secret (same value as backend) |
| `NEXTAUTH_URL` | Frontend URL (default `http://localhost:3000`) |
| `NEXT_PUBLIC_BACKEND_URL` | Backend URL for server-side proxy routes |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID (leave blank to disable Google login) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `NEXT_PUBLIC_GOOGLE_ENABLED` | Set to `true` to show Google login button |

### Generating NEXTAUTH_SECRET

```bash
openssl rand -base64 32
```

Use the same value in both `backend/.env` and `frontend/.env.local`.

### Getting a Google Safe Browsing API Key (free)

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a project (or select an existing one)
3. Search for **"Safe Browsing API"** and click **Enable**
4. Go to **Credentials → Create Credentials → API Key**
5. Copy the key into `backend/.env` as `GOOGLE_SAFE_BROWSING_API_KEY`

Free quota: **10,000 requests/day** : no billing required.

---

## Risk Score Formula

### URL Scoring

| Signal | Points |
|--------|--------|
| IP address as hostname | +20 |
| URL length > 75 chars | +10 |
| Excessive subdomains | +10 |
| Suspicious keywords | +5–15 |
| Suspicious TLD | +15 |
| No HTTPS | +10 |
| Typosquatting detected | +25 |
| Encoded characters | +10 |
| VirusTotal blacklisted | +25 |
| Recently registered domain (<1 year) | +10 |
| Google Safe Browsing flagged | +20 |

Score range: 0–100. Classification: Low (<40), Medium (40–69), High (≥70).

### Email Scoring

Heuristics check for urgent language, suspicious URLs, grammar anomalies, spoofed sender domains, and common phishing keywords. The Groq LLM (Llama 3.1 70B) provides an independent verdict : if it classifies as Phishing with ≥70% confidence, +15 points are added.

---

## Testing

### End-to-End Test Suite

```bash
# All three services must be running first
python tests/e2e_test.py
```

Covers 57 test cases across 8 groups:

1. Service health checks (all 3 services)
2. ML URL predictions (phishing, legitimate, invalid input)
3. Backend 401 enforcement (all protected routes)
4. Frontend auth flow (register, login, session, sign-out)
5. Authenticated proxy routes (URL analyze, email analyze, history, stats)
6. Proxy routes : unauthenticated (redirects to login)
7. Route protection : page redirects (all protected pages)
8. Data isolation (two users cannot see each other's history)

See `tests/REPORT.md` for the full test report.

---

## Security Notes

- Input validation on all endpoints via `express-validator` and Pydantic
- Rate limiting: 60 req/min per IP (backend)
- Helmet.js security headers
- URLs are **never fetched** : only their structure is analyzed (SSRF-safe)
- Passwords hashed with bcrypt (12 rounds)
- JWTs signed with `HS256` and verified on every backend request
- API keys stored in `.env` / `.env.local` : never commit them
- Frontend proxy routes add `Authorization` server-side : raw JWT never reaches the browser

---

## Roadmap

- [x] Backend heuristic URL analyzer
- [x] Typosquatting detection (Levenshtein)
- [x] VirusTotal threat intel integration
- [x] Email phishing analyzer
- [x] ML classifier (XGBoost, trained on 100k URLs)
- [x] FastAPI ML microservice
- [x] Next.js frontend (URL analyzer, email analyzer, dashboard)
- [x] Domain age lookup (WHOIS via whoiser)
- [x] Google Safe Browsing API integration
- [x] SQLite scan history (per-user, isolated)
- [x] Live dashboard with stats and recent scans table
- [x] LLM-based email classification (Groq : Llama 3.1, free tier)
- [x] Grammar anomaly detection in email analyzer
- [x] Chrome browser extension (Manifest V3)
- [x] User authentication (NextAuth.js v5 : email/password + Google OAuth)
- [x] End-to-end test suite (57 tests, all passing)
