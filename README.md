AWS IAM Security RAG System

# AWS IAM Security RAG Auditor
> AI-powered IAM policy analysis using LangChain, FAISS, and Claude

A Retrieval-Augmented Generation (RAG) system that ingests AWS IAM documentation
and audits IAM policies for security misconfigurations, privilege escalation paths, and CIS benchmark violations — in plain English.

Built by - cybersecbella - code explanation and testing at https://www.cybersecbella.com/articles/iam-auditor/

---

## What it does

Paste any IAM policy and get back:
- **Severity rating** — CRITICAL / HIGH / MEDIUM / LOW
- **Specific findings** — what is wrong and exactly where in the policy
- **ATT&CK mapping** — which MITRE technique the misconfiguration enables
- **Remediation** — the fixed policy JSON

---

## Quickstart

### 1. Clone and install
```bash
git clone https://github.com/cybersecbella/aws-iam-rag-auditor
cd aws-iam-rag-auditor
pip install -r requirements.txt
```

### 2. Set your API key
```bash
# Create .env file
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

### 3. Build the vector store (run once)
```bash
python src/ingest.py
```
Downloads 7 AWS IAM doc pages, chunks and embeds them, saves a local FAISS index.

### 4. Run the auditor
```bash
python src/app.py
```

---

## Architecture
AWS IAM Docs (HTML)
↓
LangChain WebLoader → Text Splitter → HuggingFace Embeddings
↓
FAISS Vector Store  ←  10 hardcoded IAM security rules
↓
MMR Retriever (semantic search)
↓
Claude (claude-sonnet-4-6) → Structured security verdict

---

## Sample policies included

| File | Description | Expected result |
|------|-------------|-----------------|
| `policies/admin_wildcard.json` | `Action:* Resource:*` | 🔴 CRITICAL |
| `policies/least_privilege.json` | Scoped S3 read-only | 🟢 SECURE |
| `policies/privilege_escalation.json` | `iam:PassRole` + `iam:CreatePolicyVersion` | 🔴 CRITICAL |

---

## ATT&CK techniques covered

| Technique | ID | Detected by |
|---|---|---|
| Account Manipulation | T1098 | Wildcard action check |
| Additional Cloud Credentials | T1098.003 | CreatePolicyVersion, CreateAccessKey |
| Valid Accounts — Cloud | T1078.004 | Overpermissive role detection |
| Steal Application Token | T1528 | PassRole to EC2/Lambda |

---

## Requirements

- Python 3.9+
- Anthropic API key ([get one here](https://console.anthropic.com))
- No AWS account needed to run the auditor

---

## Project structure

aws-iam-rag-auditor/
├── src/
│   ├── ingest.py          # load + chunk + embed AWS docs into FAISS
│   ├── retriever.py       # semantic search over vector store
│   ├── iam_auditor.py     # RAG chain + static checks + LLM verdict
│   └── app.py             # interactive CLI
├── policies/              # sample IAM policies for testing
├── PLAN.md                # full build plan and architecture notes
├── requirements.txt
└── .env                   # API key (gitignored)

---

## Blog writeup

Full walkthrough at [cybersecbella.com](https://cybersecbella.com)
