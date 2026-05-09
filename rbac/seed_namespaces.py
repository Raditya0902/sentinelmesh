"""
Seed ChromaDB with sample documents per namespace.
Idempotent: uses stable IDs — safe to re-run without creating duplicates.
Usage: PYTHONPATH=. python rbac/seed_namespaces.py
"""

from dotenv import load_dotenv

load_dotenv()

from rbac.vector_store import NamespacedVectorStore

_SEEDER_ROLE = "admin"

_SEED_DATA: dict[str, list[dict]] = {
    "general": [
        {
            "id": "gen-001",
            "document": "Company remote work policy: all employees may work remotely up to 3 days per week with manager approval. Core hours are 10am–3pm local time.",
            "metadata": {"doc_type": "policy", "sensitivity": "low"},
        },
        {
            "id": "gen-002",
            "document": "Q2 2026 all-hands summary: product roadmap reviewed, three new features shipped. Team headcount at 142. Next all-hands scheduled for July.",
            "metadata": {"doc_type": "meeting_summary", "sensitivity": "low"},
        },
        {
            "id": "gen-003",
            "document": "SentinelMesh project overview: multi-agent orchestration platform with real-time policy enforcement via Lobster Trap proxy. Stack: Python, LangGraph, FastAPI, ChromaDB.",
            "metadata": {"doc_type": "project_summary", "sensitivity": "low"},
        },
        {
            "id": "gen-004",
            "document": "IT security guidelines: all laptops must use full-disk encryption. VPN required for internal systems. MFA enforced on all accounts.",
            "metadata": {"doc_type": "policy", "sensitivity": "low"},
        },
    ],
    "hr": [
        {
            "id": "hr-001",
            "document": "Engineering salary bands 2026: Junior L3 $95k–$115k, Mid L4 $120k–$145k, Senior L5 $155k–$195k, Staff L6 $200k–$250k. Reviewed annually.",
            "metadata": {"doc_type": "salary_band", "sensitivity": "high"},
        },
        {
            "id": "hr-002",
            "document": "Employee record — Jane Smith (EMP-0042): Role: Senior Engineer L5, Dept: Platform, Start date: 2022-03-14, Manager: Bob Chen. Status: Active.",
            "metadata": {"doc_type": "employee_record", "sensitivity": "high"},
        },
        {
            "id": "hr-003",
            "document": "Performance review cycle Q1 2026: 12 employees rated Exceeds Expectations, 87 Meets, 3 Below. PIPs initiated for 3 employees in sales.",
            "metadata": {"doc_type": "performance_report", "sensitivity": "high"},
        },
        {
            "id": "hr-004",
            "document": "Org chart update April 2026: Engineering now reports to CTO. Two new VP-level hires joining Q3. Design team merging with Product.",
            "metadata": {"doc_type": "org_chart", "sensitivity": "medium"},
        },
    ],
    "finance": [
        {
            "id": "fin-001",
            "document": "Q1 2026 budget report: total spend $4.2M vs $4.0M budget (+5%). Infrastructure overspent by $180k due to unexpected GPU provisioning. Marketing underspent by $220k.",
            "metadata": {"doc_type": "budget_report", "sensitivity": "high"},
        },
        {
            "id": "fin-002",
            "document": "Invoice INV-2026-0391: Vendor AWS, amount $142,800, period March 2026, status Paid. Primary cost centers: EC2 68%, S3 18%, RDS 14%.",
            "metadata": {"doc_type": "invoice", "sensitivity": "high"},
        },
        {
            "id": "fin-003",
            "document": "Annual revenue forecast 2026: base case $28.4M ARR, bull case $33.1M, bear case $22.9M. Enterprise tier growing 34% YoY.",
            "metadata": {"doc_type": "forecast", "sensitivity": "high"},
        },
    ],
    "legal": [
        {
            "id": "leg-001",
            "document": "Standard NDA template v3.2: mutual non-disclosure, 3-year term, excludes publicly available information and independently developed IP. Governing law: Delaware.",
            "metadata": {"doc_type": "nda_template", "sensitivity": "medium"},
        },
        {
            "id": "leg-002",
            "document": "Vendor contract MSA-2026-007 with DataCo Inc: 12-month term, $240k annual, SLA 99.9% uptime, 30-day termination notice. Signed 2026-01-15.",
            "metadata": {"doc_type": "contract", "sensitivity": "medium"},
        },
        {
            "id": "leg-003",
            "document": "GDPR compliance review April 2026: data processing agreements in place for all EU vendors. Consent mechanisms audited. No violations found.",
            "metadata": {"doc_type": "compliance_review", "sensitivity": "medium"},
        },
    ],
    "audit": [
        {
            "id": "aud-001",
            "document": "Access log 2026-05-08: analyst role queried general namespace 47 times, 0 violations. admin role performed 3 upserts to hr namespace.",
            "metadata": {"doc_type": "access_log", "sensitivity": "medium"},
        },
        {
            "id": "aud-002",
            "document": "Blocked event 2026-05-08T14:32:11Z: agent extraction-agent-v1, rule block_pii_request, action DENY. Input contained SSN pattern. Risk score 0.91.",
            "metadata": {"doc_type": "blocked_event", "sensitivity": "medium"},
        },
        {
            "id": "aud-003",
            "document": "SOC 2 Type II audit summary 2025: all 5 trust service criteria met. 2 minor findings resolved. Next audit window Q4 2026.",
            "metadata": {"doc_type": "audit_report", "sensitivity": "medium"},
        },
    ],
}


def seed() -> None:
    store = NamespacedVectorStore()

    for namespace, entries in _SEED_DATA.items():
        documents = [e["document"] for e in entries]
        ids = [e["id"] for e in entries]
        metadatas = [{"namespace": namespace, **e["metadata"]} for e in entries]

        store.upsert(_SEEDER_ROLE, namespace, documents, ids, metadatas)
        print(f"  {namespace}: {len(entries)} document(s) seeded")

    print("Seed complete.")


if __name__ == "__main__":
    print("Seeding ChromaDB namespaces...")
    seed()
