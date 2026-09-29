# SecureMailScope — Email Cryptographic Posture & Traffic Forensics

AI-assisted cryptographic security posture assessment and passive traffic forensics for email communications (SMTP, IMAP, POP3). Passively analyzes PCAP/PCAPNG packet captures, reconstructs transport sessions, audits TLS handshakes, inspects X.509 certificate trust chains, applies deterministic RFC/NIST compliance rules, and delivers grounded AI security reasoning.

---

## 1. Architectural Highlights

- **Passive PCAP Ingestion**: Offline traffic parsing without modifying or intercepting live transmissions, backed by verifiable SHA-256 evidence integrity hashing.
- **Protocol State Machine Dissection**: Full TCP reassembly for SMTP (ports 25, 587, 465), IMAP (ports 143, 993), and POP3 (ports 110, 995), tracking cleartext-to-TLS STARTTLS state transitions.
- **Deterministic Cryptographic Rules**: Enforces RFC 8996 (TLS 1.0/1.1 deprecation), RFC 9325 (BCP 195 TLS recommendations), RFC 8314 (cleartext email obsolescence), and CVE-2016-2183 (Sweet32 3DES prohibition).
- **Grounded AI Security Reasoning**: Contextual risk correlation and remediation triage without hallucinating raw cryptographic facts.
- **Interactive What-If Simulator**: Live policy simulation projecting posture improvements and risk reduction prior to MTA configuration changes.
- **Master-Detail Forensic Inspector**: Seamless stream inspection across handshakes, cipher suites, certificate trees, protocol events, and raw packet frame hex dumps.

---

## 2. Prerequisites & Environment Setup

Ensure the Google Cloud CLI (`gcloud`) and Node.js (v20+) are installed.

```bash
# Set your active Google Cloud project
gcloud config set project YOUR_PROJECT_ID

# Enable required Google Cloud APIs
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  firestore.googleapis.com \
  cloudbuild.googleapis.com
```

---

## 3. Secret Management Setup

SecureMailScope uses Google Cloud Secret Manager for sensitive credentials (such as `GEMINI_API_KEY`), strictly avoiding hardcoded API keys.

```bash
# 1. Create and populate the secret
gcloud secrets create GEMINI_API_KEY --replication-policy="automatic"
echo -n "YOUR_GEMINI_API_KEY" | gcloud secrets versions add GEMINI_API_KEY --data-file=-

# 2. Retrieve your project number
PROJECT_NUMBER=$(gcloud projects describe YOUR_PROJECT_ID --format="value(projectNumber)")

# 3. Grant the Cloud Run runtime service account access to read the secret
gcloud secrets add-iam-policy-binding GEMINI_API_KEY \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

---

## 4. Firestore Security Rules Configuration

For persistent session storage and user audit tracking, configure owner-bound security rules to ensure strict user data isolation:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/interactions/{interactionId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

Deploy the rules via the Firebase CLI or Google Cloud console:

```bash
firebase deploy --only firestore:rules
```

---

## 5. Google Cloud Run Deployment

Deploy SecureMailScope directly to Google Cloud Run:

```bash
# Build and deploy container to Cloud Run
gcloud run deploy securemailscope \
  --source . \
  --region asia-southeast1 \
  --platform managed \
  --allow-unauthenticated \
  --set-secrets="GEMINI_API_KEY=GEMINI_API_KEY:latest" \
  --memory 1Gi \
  --cpu 1
```

---

## 6. Required Campaign Verification Binding

To register the service for automated challenge verification:

```bash
gcloud run services update securemailscope \
  --update-labels=dev-tutorial=cloud-run-ai-challenge \
  --region=asia-southeast1
```

---

## 7. Local Development

```bash
# Install dependencies
npm install

# Start local development server on port 3000
npm run dev

# Run TypeScript type check
npm run lint

# Build production bundle
npm run build
```
