"""
iam_auditor.py — RAG-powered IAM policy security auditor
"""
import json
import os
from dotenv import load_dotenv

from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

from src.retriever import load_retriever

load_dotenv()

# ── Prompts ───────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an AWS IAM security expert and cloud security auditor with 10 years
of experience. You review IAM policies and identify security misconfigurations.

You have access to relevant AWS documentation and IAM security rules retrieved
for this specific policy. Use that context to ground your analysis.

For each finding, provide:
1. SEVERITY: CRITICAL / HIGH / MEDIUM / LOW / INFO
2. FINDING: What the specific issue is
3. EVIDENCE: The exact policy element that caused it (quote it)
4. RISK: What an attacker could do if they exploited this
5. REMEDIATION: The specific fix with example JSON
6. ATT&CK: The MITRE ATT&CK technique if applicable

End with an overall verdict: SECURE / INSECURE / NEEDS_REVIEW
and a one-sentence summary a non-technical manager can understand.
"""

AUDIT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", """\
Audit this IAM policy for security issues.

=== RETRIEVED AWS SECURITY CONTEXT ===
{context}

=== IAM POLICY TO AUDIT ===
{policy}

=== QUERY ===
Is this IAM policy secure? Identify all misconfigurations, excessive permissions,
and privilege escalation paths. Be specific and actionable.
"""),
])


# ── RAG chain builder ─────────────────────────────────────────────────────────

def build_iam_audit_chain():
    """Build the RAG chain for IAM policy auditing."""
    retriever = load_retriever(k=8)
    llm = ChatAnthropic(
        model="claude-sonnet-4-6",
        temperature=0,
        max_tokens=2048,
    )

    def format_docs(docs):
        return "\n\n---\n\n".join(
            f"[Source: {d.metadata.get('source', 'aws_docs')}]\n{d.page_content}"
            for d in docs
        )

    # Build retrieval query from policy content
    def policy_to_query(policy_json: str) -> str:
        """Generate a semantic search query from the policy."""
        try:
            policy = json.loads(policy_json)
            statements = policy.get("Statement", [])
            actions = []
            for stmt in statements:
                action = stmt.get("Action", [])
                if isinstance(action, str):
                    actions.append(action)
                elif isinstance(action, list):
                    actions.extend(action[:5])
            action_str = ", ".join(actions[:10])
            return f"IAM policy security {action_str} least privilege best practices"
        except Exception:
            return "IAM policy security best practices misconfigurations"

    chain = (
        {
            "context": lambda x: format_docs(
                retriever.invoke(policy_to_query(x["policy"]))
            ),
            "policy": lambda x: x["policy"],
        }
        | AUDIT_PROMPT
        | llm
        | StrOutputParser()
    )
    return chain


# ── Static checks (run before LLM for speed) ─────────────────────────────────

def static_policy_checks(policy_json: str) -> list[dict]:
    """
    Run fast pattern-based checks before sending to the LLM.
    These catch the most obvious misconfigurations instantly.
    """
    findings = []
    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as e:
        return [{"severity": "ERROR", "finding": f"Invalid JSON: {e}"}]

    statements = policy.get("Statement", [])

    for i, stmt in enumerate(statements):
        effect   = stmt.get("Effect", "")
        action   = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        condition = stmt.get("Condition", {})

        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        # Check 1: Admin wildcard
        if (effect == "Allow"
                and ("*" in action or "iam:*" in action)
                and "*" in resource):
            findings.append({
                "severity": "CRITICAL",
                "finding":  "Admin wildcard — Action:* Resource:* grants full AWS access",
                "attck":    "T1098 — Account Manipulation",
                "fix":      "Replace with specific actions scoped to specific resources",
            })

        # Check 2: Dangerous IAM actions without condition
        dangerous_actions = {
            "iam:CreatePolicyVersion": "Privilege escalation via policy version",
            "iam:SetDefaultPolicyVersion": "Privilege escalation via policy rollback",
            "iam:PassRole": "Can pass privileged roles to services",
            "iam:AttachUserPolicy": "Can attach admin policies to any user",
            "iam:CreateAccessKey": "Can create persistent credentials for any user",
            "sts:AssumeRole": "Can assume any role without restriction",
        }
        for action_name, risk in dangerous_actions.items():
            if (effect == "Allow"
                    and any(a in (action_name, "*", "iam:*", "sts:*")
                            for a in action)
                    and "*" in resource
                    and not condition):
                findings.append({
                    "severity": "CRITICAL",
                    "finding":  f"Dangerous action without condition: {action_name}",
                    "risk":     risk,
                    "attck":    "T1098.003 — Additional Cloud Credentials",
                    "fix":      f"Add Condition to scope {action_name} or restrict Resource",
                })

        # Check 3: NotAction pattern
        if "NotAction" in stmt and effect == "Allow" and "*" in resource:
            findings.append({
                "severity": "HIGH",
                "finding":  "NotAction with Resource:* — grants everything except listed actions",
                "fix":      "Replace NotAction with explicit Allow of specific needed actions",
            })

        # Check 4: Allow with no condition on sensitive services
        sensitive_prefixes = ["s3:", "kms:", "secretsmanager:", "ssm:"]
        if (effect == "Allow"
                and "*" in resource
                and not condition
                and any(any(a.startswith(p) for p in sensitive_prefixes)
                        for a in action)):
            findings.append({
                "severity": "HIGH",
                "finding":  f"Sensitive service actions on Resource:* without conditions",
                "actions":  [a for a in action
                             if any(a.startswith(p) for p in sensitive_prefixes)],
                "fix":      "Scope Resource to specific ARNs and add Condition constraints",
            })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding":  "No critical static patterns detected — proceeding to deep AI analysis",
        })

    return findings


# ── Main audit function ───────────────────────────────────────────────────────

def audit_policy(policy_json: str, verbose: bool = True) -> dict:
    """
    Full IAM policy audit:
    1. Parse and validate JSON
    2. Run static pattern checks
    3. Run RAG-powered LLM analysis
    4. Return structured result
    """
    if verbose:
        print("\n" + "=" * 60)
        print("AWS IAM POLICY SECURITY AUDIT")
        print("=" * 60)

    # Step 1: static checks
    if verbose:
        print("\n[1/3] Running static pattern checks...")
    static_findings = static_policy_checks(policy_json)
    if verbose:
        for f in static_findings:
            sev = f.get("severity", "INFO")
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                    "LOW": "🟢", "INFO": "ℹ️", "ERROR": "❌"}.get(sev, "")
            print(f"  {icon} [{sev}] {f.get('finding', '')}")

    # Step 2: AI analysis
    if verbose:
        print("\n[2/3] Running RAG + AI deep analysis...")
        print("      (retrieving relevant AWS docs and security rules...)\n")

    chain = build_iam_audit_chain()
    ai_analysis = chain.invoke({"policy": policy_json})

    if verbose:
        print("\n[3/3] AI Analysis:\n")
        print(ai_analysis)

    return {
        "static_findings":   static_findings,
        "ai_analysis":       ai_analysis,
        "policy_audited":    policy_json,
        "static_flag_count": sum(
            1 for f in static_findings
            if f.get("severity") in ("CRITICAL", "HIGH")
        ),
    }


if __name__ == "__main__":
    # Quick test with a deliberately insecure policy
    test_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }, indent=2)

    result = audit_policy(test_policy)