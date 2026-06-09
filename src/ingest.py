"""
ingest.py — Load AWS docs, chunk, embed, store in FAISS
Run once: python src/ingest.py
"""
import os
import json
from pathlib import Path
from dotenv import load_dotenv

from langchain_community.document_loaders import (
    WebBaseLoader,
    PyPDFLoader,
    DirectoryLoader,
)
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings

load_dotenv()

# ── AWS doc URLs to ingest ────────────────────────────────────────────────────
AWS_DOC_URLS = [
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation-reference.html",
    "https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html",
]

VECTORSTORE_PATH = "vectorstore/aws_iam"
CHUNK_SIZE       = 500    # tokens per chunk
CHUNK_OVERLAP    = 50     # overlap between chunks


def load_web_docs(urls: list[str]):
    """Load HTML pages from AWS documentation."""
    print(f"[ingest] Loading {len(urls)} AWS doc pages...")
    loader = WebBaseLoader(
        web_paths=urls,
        bs_kwargs={"features": "html.parser"},
    )
    docs = loader.load()
    print(f"[ingest] Loaded {len(docs)} documents")
    return docs


def load_pdf_docs(pdf_dir: str = "data/raw"):
    """Load any PDF files from the data/raw directory."""
    pdf_path = Path(pdf_dir)
    if not pdf_path.exists():
        return []
    pdfs = list(pdf_path.glob("*.pdf"))
    if not pdfs:
        return []
    print(f"[ingest] Loading {len(pdfs)} PDF files...")
    docs = []
    for pdf in pdfs:
        loader = PyPDFLoader(str(pdf))
        docs.extend(loader.load())
    return docs


def chunk_documents(docs):
    """Split documents into overlapping chunks for embedding."""
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunks = splitter.split_documents(docs)
    print(f"[ingest] Split into {len(chunks)} chunks")
    return chunks


def build_vectorstore(chunks):
    """
    Embed chunks using HuggingFace sentence-transformers (free, local).
    Swap to OpenAIEmbeddings() if you prefer.
    """
    print("[ingest] Loading embedding model (first run downloads ~90MB)...")
    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
    )
    print("[ingest] Embedding chunks and building FAISS index...")
    vectorstore = FAISS.from_documents(chunks, embeddings)
    Path(VECTORSTORE_PATH).parent.mkdir(parents=True, exist_ok=True)
    vectorstore.save_local(VECTORSTORE_PATH)
    print(f"[ingest] Vector store saved to: {VECTORSTORE_PATH}")
    return vectorstore


def add_hardcoded_iam_rules(vectorstore, embeddings):
    """
    Inject known IAM security rules directly into the vector store.
    These supplement the AWS docs with explicit security guidance.
    """
    from langchain.schema import Document

    iam_rules = [
        Document(
            page_content=(
                "IAM Security Rule: Never use Action: '*' with Resource: '*'. "
                "This grants full admin access and violates least-privilege. "
                "CRITICAL misconfiguration. ATT&CK: T1098 — Account Manipulation."
            ),
            metadata={"source": "iam_rules", "severity": "CRITICAL"},
        ),
        Document(
            page_content=(
                "IAM Security Rule: Root account should have no access keys. "
                "Root access keys cannot be scoped and represent full account compromise "
                "if leaked. Delete all root access keys immediately. "
                "CIS AWS Benchmark 1.4."
            ),
            metadata={"source": "iam_rules", "severity": "CRITICAL"},
        ),
        Document(
            page_content=(
                "IAM Security Rule: Policies with NotAction are dangerous. "
                "NotAction: ['iam:*'] with Resource: '*' grants everything EXCEPT IAM — "
                "still extremely overpermissive. Prefer explicit Allow with specific actions."
            ),
            metadata={"source": "iam_rules", "severity": "HIGH"},
        ),
        Document(
            page_content=(
                "IAM Security Rule: Inline policies are harder to audit than managed policies. "
                "Use AWS managed policies or customer managed policies attached to roles. "
                "Inline policies bypass SCPs and are invisible to IAM Access Analyzer."
            ),
            metadata={"source": "iam_rules", "severity": "MEDIUM"},
        ),
        Document(
            page_content=(
                "IAM Security Rule: IAM roles should use Condition keys to restrict usage. "
                "Add conditions like aws:RequestedRegion, aws:SourceVpc, aws:MultiFactorAuthPresent "
                "to prevent privilege escalation from unexpected contexts."
            ),
            metadata={"source": "iam_rules", "severity": "MEDIUM"},
        ),
        Document(
            page_content=(
                "IAM Security Rule: sts:AssumeRole without Condition is dangerous. "
                "Anyone matching the Principal can assume the role from any IP, region, or context. "
                "Add aws:PrincipalOrgID or aws:SourceIp conditions to restrict."
            ),
            metadata={"source": "iam_rules", "severity": "HIGH"},
        ),
        Document(
            page_content=(
                "IAM Security Rule: PassRole permission (iam:PassRole) should be tightly scoped. "
                "iam:PassRole on Resource:* lets users pass any role to any service, "
                "enabling privilege escalation to admin. Scope to specific role ARNs."
            ),
            metadata={"source": "iam_rules", "severity": "CRITICAL"},
        ),
        Document(
            page_content=(
                "IAM Security Rule: iam:CreatePolicyVersion allows privilege escalation. "
                "A user with iam:CreatePolicyVersion can create a new version of any policy "
                "granting themselves admin. This is a critical privilege escalation path. "
                "ATT&CK: T1098.003."
            ),
            metadata={"source": "iam_rules", "severity": "CRITICAL"},
        ),
        Document(
            page_content=(
                "IAM Best Practice: Enable MFA for all IAM users with console access. "
                "Use aws:MultiFactorAuthPresent condition in policies to enforce MFA. "
                "CIS AWS Benchmark 1.10. Without MFA, stolen credentials = full access."
            ),
            metadata={"source": "iam_rules", "severity": "HIGH"},
        ),
        Document(
            page_content=(
                "IAM Best Practice: Use IAM roles for EC2 instances, not access keys. "
                "Access keys in EC2 user data or environment variables are frequently leaked. "
                "Instance profiles rotate credentials automatically and cannot be exfiltrated "
                "without access to the instance metadata service."
            ),
            metadata={"source": "iam_rules", "severity": "HIGH"},
        ),
    ]

    vectorstore.add_documents(iam_rules)
    vectorstore.save_local(VECTORSTORE_PATH)
    print(f"[ingest] Added {len(iam_rules)} hardcoded IAM security rules")
    return vectorstore


if __name__ == "__main__":
    # 1. Load docs
    docs = load_web_docs(AWS_DOC_URLS)
    docs += load_pdf_docs()

    # 2. Chunk
    chunks = chunk_documents(docs)

    # 3. Embed + store
    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
    )
    vs = build_vectorstore(chunks)

    # 4. Inject hardcoded rules
    vs = add_hardcoded_iam_rules(vs, embeddings)
    print("[ingest] Done. Run src/app.py to start querying.")