# AWS IAM Security RAG System
## Plan: LangChain + FAISS + AWS Docs → "Is this IAM policy secure?"

> **AWS Cloud Security  
> **Goal:** Build a RAG (Retrieval-Augmented Generation) system that ingests AWS
IAM documentation and lets you query it with natural language, specifically to
> audit IAM policies for security misconfigurations.

---

## Building

```
AWS Docs (HTML/PDF)
       ↓
  Document Loader        ← LangChain loaders
       ↓
  Text Splitter          ← chunk into ~500 token pieces
       ↓
  Embeddings             ← OpenAI or HuggingFace
       ↓
  FAISS Vector Store     ← local vector database (no cloud needed)
       ↓
  Retriever              ← semantic search over your docs
       ↓
  LLM (Claude/GPT)       ← answers grounded in retrieved context
       ↓
  "Is this IAM policy secure?" → structured security verdict
```

---

## File structure

```
aws-iam-rag/
├── PLAN.md                   ← this file
├── requirements.txt
├── .env                      ← API keys (gitignored)
├── .gitignore
│
├── data/
│   ├── raw/                  ← downloaded AWS docs (HTML, PDF)
│   └── processed/            ← cleaned text chunks
│
├── vectorstore/              ← FAISS index (gitignored — rebuild locally)
│
├── src/
│   ├── ingest.py             ← Step 1: load + chunk + embed + store
│   ├── retriever.py          ← Step 2: query the vector store
│   ├── iam_auditor.py        ← Step 3: IAM policy security checker
│   └── app.py               ← Step 4: interactive CLI / REPL
│
└── policies/                 ← sample IAM policies to test against
    ├── admin_wildcard.json   ← insecure: Action:* Resource:*
    ├── least_privilege.json  ← secure: scoped S3 read-only
    └── kms_overpermissive.json
```

---

### Install dependencies

```bash
pip install \
  langchain>=0.2.0 \
  langchain-anthropic>=0.1.0 \
  langchain-community>=0.2.0 \
  langchain-huggingface>=0.0.3 \
  faiss-cpu>=1.7.4 \
  sentence-transformers>=2.2.2 \
  beautifulsoup4>=4.12.0 \
  requests>=2.31.0 \
  python-dotenv>=1.0.0 \
  tiktoken>=0.5.0 \
  anthropic>=0.25.0
```

### `.env` file

```env
# .env — DO NOT COMMIT
ANTHROPIC_API_KEY=sk-ant-...
# Optional: if you want OpenAI embeddings instead of HuggingFace
OPENAI_API_KEY=sk-...
```

### `.gitignore` additions

```
vectorstore/
data/raw/
data/processed/
.env
```

---

## Phase 2 — Data ingestion (`src/ingest.py`)

### What docs to download

These are the most relevant AWS IAM docs for security auditing:

| Doc | URL | Why |
|-----|-----|-----|
| IAM User Guide | docs.aws.amazon.com/IAM/latest/UserGuide | Core IAM concepts |
| IAM Best Practices | docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html | Security rules |
| IAM JSON Policy Reference | docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html | Policy syntax |
| AWS Security Hub Controls | docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html | Audit checks |
| IAM Access Analyzer | docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html | Overpermission detection |
| CIS AWS Benchmark | Available as PDF from cisecurity.org | Hardening checklist |

### Step 1 

```powershell
# From project root
python src/ingest.py
```

Output:
```
[ingest] Loading 7 AWS doc pages...
[ingest] Loaded 7 documents
[ingest] Split into 312 chunks
[ingest] Embedding chunks and building FAISS index...
[ingest] Vector store saved to: vectorstore/aws_iam
[ingest] Added 10 hardcoded IAM security rules
[ingest] Done. Run src/app.py to start querying.
```

### Step 2 — Run the auditor

```powershell
python src/app.py
```

### Step 3 — Test it

```
>> audit policies/admin_wildcard.json
>> audit policies/privilege_escalation.json
>> query What IAM actions enable privilege escalation?
>> query How do I enforce MFA on sensitive actions?
>> paste
[paste your own policy]
END
```

---

## ATT&CK mappings covered by this project

| Technique | ID | Detected by |
|---|---|---|
| Account Manipulation | T1098 | Action:* wildcard check |
| Additional Cloud Credentials | T1098.003 | CreateAccessKey, CreatePolicyVersion |
| Valid Accounts — Cloud | T1078.004 | Overpermissive role detection |
| Steal Application Token | T1528 | PassRole to EC2/Lambda |
| Modify Cloud Compute Infrastructure | T1578 | Unscoped EC2/Lambda permissions |

---

## Additional Addons to be built on top of auditor 

- Add **AWS Config** integration — pull live policies from your account
- Add **STRIDE threat modeling** layer on top of the RAG analysis
