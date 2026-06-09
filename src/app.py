"""
app.py — Interactive IAM policy auditor REPL
"""
import json
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.iam_auditor import audit_policy
from src.retriever import retrieve

BANNER = """
╔══════════════════════════════════════════════════╗
║   AWS IAM Security RAG Auditor                  ║
║   LangChain + FAISS + Claude                    ║
╚══════════════════════════════════════════════════╝

Commands:
  audit <path>     Audit an IAM policy JSON file
  query <text>     Ask a free-form AWS security question
  paste            Paste a policy JSON directly
  examples         Show example queries
  exit             Quit
"""

EXAMPLE_QUERIES = [
    "Is Action:* with Resource:* ever acceptable?",
    "What conditions should I add to sts:AssumeRole?",
    "How do I prevent privilege escalation via iam:PassRole?",
    "What is the principle of least privilege for S3 access?",
    "How do I audit IAM policies for CIS AWS Benchmark compliance?",
    "What IAM actions allow privilege escalation?",
    "How should I scope KMS permissions for EC2 instances?",
]


def handle_audit(args: str):
    """Audit a policy from a file path."""
    path = args.strip()
    if not path:
        print("[error] Provide a file path: audit policies/my_policy.json")
        return
    try:
        with open(path) as f:
            policy_json = f.read()
        json.loads(policy_json)  # validate
        audit_policy(policy_json)
    except FileNotFoundError:
        print(f"[error] File not found: {path}")
    except json.JSONDecodeError as e:
        print(f"[error] Invalid JSON: {e}")


def handle_paste():
    """Accept multi-line policy JSON from stdin."""
    print("Paste your IAM policy JSON below.")
    print("Enter a blank line followed by END to finish:\n")
    lines = []
    while True:
        try:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        except EOFError:
            break
    policy_json = "\n".join(lines)
    try:
        json.loads(policy_json)
        audit_policy(policy_json)
    except json.JSONDecodeError as e:
        print(f"[error] Invalid JSON: {e}")


def handle_query(query: str):
    """Answer a free-form AWS security question using RAG."""
    if not query.strip():
        print("[error] Provide a question: query What is least privilege?")
        return

    from langchain_anthropic import ChatAnthropic
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_core.output_parsers import StrOutputParser

    print(f"\n[query] Retrieving relevant AWS docs for: {query}\n")
    docs = retrieve(query, k=5)

    context = "\n\n---\n\n".join(
        f"[{d.metadata.get('source', 'docs')}]\n{d.page_content}"
        for d in docs
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", (
            "You are an AWS IAM security expert. Answer questions about IAM "
            "security, best practices, and misconfigurations. Ground your answers "
            "in the provided AWS documentation context. Be specific and actionable."
        )),
        ("human", "Context:\n{context}\n\nQuestion: {question}"),
    ])

    llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0, max_tokens=1024)
    chain = prompt | llm | StrOutputParser()

    print("[answer]\n")
    answer = chain.invoke({"context": context, "question": query})
    print(answer)


def main():
    print(BANNER)

    while True:
        try:
            raw = input("\n>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not raw:
            continue

        parts = raw.split(maxsplit=1)
        cmd   = parts[0].lower()
        args  = parts[1] if len(parts) > 1 else ""

        if cmd in ("exit", "quit"):
            print("Goodbye.")
            break
        elif cmd == "audit":
            handle_audit(args)
        elif cmd == "query":
            handle_query(args)
        elif cmd == "paste":
            handle_paste()
        elif cmd == "examples":
            print("\nExample queries:")
            for q in EXAMPLE_QUERIES:
                print(f"  query {q}")
        else:
            print(f"[unknown command] '{cmd}' — type 'exit' to quit")


if __name__ == "__main__":
    main()