"""
SentinelMesh Governance Dashboard (Streamlit).

Reads the Lobster Trap JSONL audit log and renders:
  - Live blocked-event feed
  - Risk score heatmap
  - Blocked-by-rule breakdown
  - RBAC violation log
  - Human-review queue management
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

# Configuration
AUDIT_LOG_PATH = Path(os.getenv("AUDIT_LOG_PATH", "logs/audit.jsonl"))
API_URL = os.getenv("API_URL", "http://localhost:8000")
REFRESH_INTERVAL_SEC = 3

# UI Constants
COLOR_MAP = {
    "ALLOW": "#66bb6a",
    "DENY": "#ef5350",
    "QUARANTINE": "#ffa726",
    "HUMAN_REVIEW": "#42a5f5",
    "LOG": "#9e9e9e",
}

ACTION_BG = {
    "ALLOW":        "background-color: #1a3a1a; color: #66bb6a",
    "DENY":         "background-color: #3a1a1a; color: #ef5350",
    "QUARANTINE":   "background-color: #3a2a1a; color: #ffa726",
    "HUMAN_REVIEW": "background-color: #1a2a3a; color: #42a5f5",
    "LOG":          "background-color: #2a2a2a; color: #9e9e9e",
}


def load_audit_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().strip().splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def get_review_queue() -> list[dict]:
    try:
        resp = requests.get(f"{API_URL}/review/queue?status=pending", timeout=2)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


def submit_decision(request_id: str, decision: str, note: str) -> bool:
    try:
        resp = requests.post(
            f"{API_URL}/review/{request_id}/decide",
            json={"decision": decision, "note": note},
            timeout=5,
        )
        return resp.status_code == 200
    except Exception as e:
        st.error(f"Failed to submit decision: {e}")
        return False


def render_sidebar(df: pd.DataFrame) -> dict:
    st.sidebar.title("🛡️ Controls")
    
    if df.empty:
        return {"agents": [], "actions": [], "rules": []}

    st.sidebar.subheader("Filters")
    
    # Agent filter
    agents = sorted(df["agent_id"].dropna().astype(str).unique().tolist()) if "agent_id" in df.columns else []
    selected_agents = st.sidebar.multiselect("Agents", agents, default=agents)

    # Action filter
    actions = sorted(df["action"].dropna().astype(str).unique().tolist()) if "action" in df.columns else []
    selected_actions = st.sidebar.multiselect("Actions", actions, default=actions)

    # Rule filter
    rules = sorted(df["rule_name"].dropna().astype(str).unique().tolist()) if "rule_name" in df.columns else []
    selected_rules = st.sidebar.multiselect("Rules", rules, default=rules)

    st.sidebar.divider()
    if st.sidebar.button("Clear Audit Log (Danger Zone)", type="secondary"):
        if AUDIT_LOG_PATH.exists():
            AUDIT_LOG_PATH.write_text("")
            st.rerun()

    return {
        "agents": selected_agents,
        "actions": selected_actions,
        "rules": selected_rules,
    }


def render_metrics(df: pd.DataFrame, pending_count: int) -> None:
    if df.empty:
        cols = st.columns(4)
        cols[0].metric("Total Calls", 0)
        cols[1].metric("Blocked", 0)
        cols[2].metric("Pending Review", pending_count)
        cols[3].metric("Avg Risk", "0.00")
        return

    total = len(df)
    blocked = len(df[df["action"].isin(["DENY", "QUARANTINE"])])
    avg_risk = df["risk_score"].mean() if "risk_score" in df.columns else 0.0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Calls", total)
    col2.metric("Blocked", blocked, delta=f"{blocked/total*100:.1f}%", delta_color="inverse")
    col3.metric("Pending Review", pending_count, delta=f"{pending_count}" if pending_count > 0 else None, delta_color="normal")
    col4.metric("Avg Risk", f"{avg_risk:.2f}")


def render_audit_table(df: pd.DataFrame) -> None:
    st.subheader("Real-Time Audit Trail")
    if df.empty:
        st.info("Waiting for data...")
        return

    display_df = df.copy()
    if "timestamp" in display_df.columns:
        display_df["timestamp"] = pd.to_datetime(display_df["timestamp"])

    cols = ["timestamp", "agent_id", "action", "rule_name", "risk_score"]
    cols = [c for c in cols if c in display_df.columns]
    display_df = display_df[cols].sort_values("timestamp", ascending=False)

    styled = display_df.style.map(
        lambda val: ACTION_BG.get(val, ""),
        subset=["action"],
    )
    st.dataframe(styled, use_container_width=True, hide_index=True)


def render_visuals(df: pd.DataFrame) -> None:
    if df.empty:
        return

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Events by Agent & Action")
        if "agent_id" in df.columns and "action" in df.columns:
            heat_df = (
                df.groupby(["agent_id", "action"])
                .size()
                .reset_index(name="count")
            )
            heat_df.columns = ["Agent", "Action", "Count"]
            fig = px.bar(
                heat_df,
                x="Agent",
                y="Count",
                color="Action",
                color_discrete_map=COLOR_MAP,
                barmode="group",
                labels={"Count": "Event Count"},
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="white",
            )
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Attack Breakdown")
        blocks = df[df["action"].isin(["DENY", "QUARANTINE"])]
        if not blocks.empty:
            rule_counts = blocks["rule_name"].value_counts().reset_index()
            rule_counts.columns = ["Rule", "Count"]
            fig = px.pie(rule_counts, values="Count", names="Rule", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No blocked events detected yet.")


def render_human_review() -> None:
    st.subheader("Human Review Queue")
    queue = get_review_queue()
    
    if not queue:
        st.success("Queue is empty. All clear!")
        return

    for item in queue:
        with st.expander(f"REQ: {item['request_id']} | Agent: {item['agent_id']} | Risk: {item['risk_score']}", expanded=True):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**Rule Violated:** `{item['rule_name']}`")
                st.write(f"**Timestamp:** `{item['timestamp']}`")
                st.json(item['raw'])
            
            with col2:
                note = st.text_area("Review Note", key=f"note_{item['request_id']}")
                if st.button("Approve", key=f"app_{item['request_id']}", type="primary", use_container_width=True):
                    if submit_decision(item['request_id'], "approve", note):
                        st.success("Approved")
                        st.rerun()
                
                if st.button("Reject", key=f"rej_{item['request_id']}", type="secondary", use_container_width=True):
                    if submit_decision(item['request_id'], "reject", note):
                        st.warning("Rejected")
                        st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="SentinelMesh Governance Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom CSS for the badge
    st.markdown("""
        <style>
        .badge {
            background-color: #ff4b4b;
            color: white;
            padding: 4px 8px;
            text-align: center;
            border-radius: 10px;
            font-size: 12px;
            font-weight: bold;
        }
        </style>
    """, unsafe_allow_html=True)

    st.title("🛡️ SentinelMesh — AI Governance Dashboard")
    
    # Load data
    entries = load_audit_entries(AUDIT_LOG_PATH)
    df = pd.DataFrame(entries)
    
    # Get review queue
    review_queue = get_review_queue()
    pending_count = len(review_queue)

    # Sidebar
    filters = render_sidebar(df)
    
    # Apply filters
    if not df.empty:
        if filters["agents"]:
            df = df[df["agent_id"].isin(filters["agents"])]
        if filters["actions"]:
            df = df[df["action"].isin(filters["actions"])]
        if filters["rules"]:
            df = df[df["rule_name"].isin(filters["rules"])]

    # Tabs
    tab_audit, tab_review, tab_analytics = st.tabs([
        "📊 Governance Audit", 
        f"👤 Human Review ({pending_count})", 
        "📈 Risk Analytics"
    ])

    with tab_audit:
        render_metrics(df, pending_count)
        st.divider()
        render_audit_table(df)
        
        if not df.empty:
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "Export Audit Log (CSV)",
                csv,
                "sentinel_audit_log.csv",
                "text/csv",
                key='download-csv'
            )

    with tab_review:
        render_human_review()

    with tab_analytics:
        render_visuals(df)
        
        if not df.empty:
            st.subheader("Agent Activity Timeline")
            timeline_df = df.copy()
            timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"])
            fig = px.scatter(
                timeline_df,
                x="timestamp",
                y="agent_id",
                color="action",
                color_discrete_map=COLOR_MAP,
                labels={"agent_id": "Agent", "timestamp": "Time"},
                title="Requests per minute",
            )
            fig.update_traces(marker=dict(size=14))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="white",
            )
            st.plotly_chart(fig, use_container_width=True)

    # Auto-refresh logic (only if not in a middle of a review)
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.time()
    
    if time.time() - st.session_state.last_refresh > REFRESH_INTERVAL_SEC:
        st.session_state.last_refresh = time.time()
        st.rerun()


if __name__ == "__main__":
    main()
