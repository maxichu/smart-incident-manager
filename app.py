import re
import json
import html
import streamlit as st
from io import BytesIO
import pdfplumber
import db
import llm
st.set_page_config(page_title="Smart Incident Manager", layout="centered")
db.init_db()
# F8: conversation history in session state
if "qa_messages" not in st.session_state:
    st.session_state.qa_messages = []
def summarize(text):
    """Return the first 3 non-trivial sentences from text (Lead-3)."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    meaningful = [s.strip() for s in sentences if len(s.strip()) > 5]
    return " ".join(meaningful[:3])
# F5: keyword lists for incident classification.
KEYWORDS = {
    "Network": [
        "vpn", "firewall", "dns", "router", "network", "connectivity",
        "bandwidth", "latency", "gateway", "switch", "lan", "wan", "isp",
    ],
    "Database": [
        "database", "mysql", "postgres", "query", "timeout", "connection",
        "oracle", "sql", "deadlock", "replication", "tns", "listener",
    ],
    "Security": [
        "attack", "malware", "phishing", "unauthorized", "breach",
        "vulnerability", "ddos", "intrusion", "ransomware", "hack",
        "compromise", "exploit", "brute force",
    ],
    "Infrastructure": [
        "cpu", "memory", "disk", "server", "vm", "storage", "kubernetes",
        "container", "hardware", "node", "cluster", "load balancer",
    ],
    "Application": [
        "application", "api", "deployment", "service", "frontend",
        "backend", "crash", "bug", "error 500", "exception", "restart",
        "rollback", "web", "mobile",
    ],
}
def classify(text):
    """
    Classify an incident into one of five categories via keyword scoring.
    Falls back to Others when no keyword matches.
    """
    lower = text.lower()
    scores = {cat: 0 for cat in KEYWORDS}
    for cat, words in KEYWORDS.items():
        for w in words:
            if w in lower:
                scores[cat] += 1
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "Others"
# F6: severity keyword weights.
SEVERITY_KEYWORDS = {
    4: ["outage", "down", "breach", "data loss", "ransomware", "critical"],
    3: ["unavailable", "timeout", "crash", "failure", "attack", "95%"],
    2: ["slow", "degraded", "error", "issue", "warning"],
    1: ["notice", "minor", "informational"],
}
def score_severity(text):
    """
    Score severity via weighted keyword matching.
    Uses max-keyword-weight mapping per F6 test cases.
    """
    lower = text.lower()
    max_weight = 0
    for weight, words in SEVERITY_KEYWORDS.items():
        for w in words:
            if w in lower:
                if weight > max_weight:
                    max_weight = weight
    if max_weight >= 4:
        return ("Critical", max_weight)
    elif max_weight == 3:
        return ("High", max_weight)
    elif max_weight == 2:
        return ("Medium", max_weight)
    else:
        return ("Low", max_weight)
# F7: category-keyword playbook for action recommendations.
# Structure: category -> keyword -> list of recommended actions.
PLAYBOOK = {
    "Network": {
        "vpn": ["Verify VPN gateway", "Check firewall rules", "Restart VPN service"],
        "dns": ["Verify DNS records", "Check DNS server health", "Flush DNS cache"],
        "firewall": ["Verify firewall policy", "Check blocked connections", "Review security rules"],
        "connectivity": ["Check network connectivity", "Verify ISP status", "Inspect network hardware"],
        "latency": ["Measure network latency", "Check bandwidth usage", "Review routing tables"],
        "gateway": ["Verify gateway status", "Check gateway configuration", "Restart gateway service"],
    },
    "Database": {
        "timeout": ["Check slow query logs", "Inspect connection pool", "Escalate to DBA"],
        "replication": ["Verify replication status", "Check database synchronization", "Escalate to DBA"],
        "connection": ["Verify database connectivity", "Review connection limits", "Restart connection pool"],
        "query": ["Analyze query performance", "Check query execution plan", "Consider indexing"],
        "deadlock": ["Identify deadlock source", "Review transaction isolation", "Escalate to DBA"],
    },
    "Security": {
        "breach": ["Escalate to security team", "Review access logs", "Isolate affected systems"],
        "attack": ["Review attack indicators", "Verify firewall protection", "Escalate immediately"],
        "unauthorized": ["Review user permissions", "Check authentication logs", "Reset compromised credentials"],
        "malware": ["Run malware scan", "Isolate infected systems", "Escalate to security team"],
        "phishing": ["Investigate phishing source", "Notify affected users", "Block malicious domains"],
    },
    "Infrastructure": {
        "cpu": ["Identify top processes", "Check resource utilization", "Consider scaling resources"],
        "memory": ["Review memory consumption", "Check for memory leaks", "Restart affected service"],
        "disk": ["Check disk usage", "Remove unnecessary files", "Expand storage if required"],
        "server": ["Verify server health", "Check system logs", "Restart server if needed"],
        "storage": ["Check storage capacity", "Verify storage performance", "Consider expanding storage"],
    },
    "Application": {
        "deployment": ["Roll back deployment", "Review deployment logs", "Verify service health"],
        "api": ["Check API logs", "Verify upstream dependencies", "Restart affected service"],
        "error": ["Inspect application logs", "Review recent changes", "Escalate to application team"],
        "crash": ["Check crash logs", "Identify root cause", "Restart application"],
        "bug": ["Review bug report", "Verify fix deployment", "Escalate to development team"],
    },
}
# F7: category-level fallback actions when no keyword matches.
CATEGORY_FALLBACKS = {
    "Network": ["Verify connectivity", "Review logs", "Escalate to network team"],
    "Database": ["Review database logs", "Verify service status", "Escalate to DBA"],
    "Infrastructure": ["Review system metrics", "Verify resource health", "Escalate to infrastructure team"],
    "Application": ["Review application logs", "Verify service health", "Escalate to application team"],
    "Security": ["Review security logs", "Investigate suspicious activity", "Escalate to security team"],
    "Others": ["Investigate issue", "Review logs", "Escalate to appropriate team"],
}
# F7: generic fallback when category is unavailable.
GENERIC_FALLBACK = ["Investigate issue", "Review logs", "Escalate to appropriate team"]
def recommend(content, category):
    """
    Generate action recommendations based on category and keyword matching.
    Input:  incident content string, category string
    Output: list of action strings
    Falls back to category-level actions, then generic fallback.
    """
    lower = content.lower()
    playbook = PLAYBOOK.get(category, {})
    for keyword, actions in playbook.items():
        if keyword in lower:
            return actions
    return CATEGORY_FALLBACKS.get(category, GENERIC_FALLBACK)
# F8: extract keywords from questions for FTS5 search with OR semantics.
# Natural-language questions contain stop words and verb modifiers that
# will never match incident content under AND semantics.
def _build_incident_card(detail):
    """Format a single incident as a structured context block."""
    cat = detail.get("category") or "?"
    sev = detail.get("severity") or "?"
    summary = detail.get("summary") or detail["content"][:150]
    recs = detail.get("recommendations", [])
    ts = str(detail.get("created_at", ""))[:19]
    lines = [
        f"--- Incident #{detail['id']} ---",
        f"Time: {ts}",
        f"Category: {cat}",
        f"Severity: {sev}",
        f"Summary: {summary}",
    ]
    if recs:
        lines.append("Recommendations:")
        for r in recs[:3]:
            lines.append(f"  - {r}")
    lines.append(f"Content: {detail['content'][:400]}")
    return "\n".join(lines)
# F11: orchestrates a sequential multi-agent workflow.
def run_workflow(content):
    """Execute Summary -> Classification -> Severity -> Recommendation agents."""
    steps = []
    # Step 1: Summary Agent
    steps.append({"agent": "Summary Agent", "output": summarize(content)})
    # Step 2: Classification Agent
    cat = classify(content)
    steps.append({"agent": "Classification Agent", "output": cat})
    # Step 3: Severity Agent
    sev, score = score_severity(content)
    steps.append({"agent": "Severity Agent", "output": f"{sev} (score: {score})"})
    # Step 4: Recommendation Agent
    steps.append({"agent": "Recommendation Agent", "output": recommend(content, cat)})
    return steps
def answer_question(question, history):
    """Generate an answer from retrieved incidents and conversation history."""
    results = find_citations(question)
    contexts = []
    for r in results[:5]:
        detail = db.get_incident_by_id(r["id"])
        if not detail:
            continue
        cat = detail.get("category") or "?"
        sev = detail.get("severity") or "?"
        content = detail["content"][:300]
        contexts.append(
            f"[Incident #{detail['id']}] Category: {cat}, Severity: {sev}\n{content}"
        )
    if not contexts:
        # Fallback: use 5 most recent incidents when FTS5 finds nothing
        recent = db.get_all_incidents()[:5]
        for inc in recent:
            detail = db.get_incident_by_id(inc["id"])
            if detail:
                cat = detail.get("category") or "?"
                sev = detail.get("severity") or "?"
                content = detail["content"][:300]
                contexts.append(
                    f"[Incident #{detail['id']}] Category: {cat}, Severity: {sev}\n{content}"
                )
    context_text = "\n\n".join(contexts)
    recent = "\n".join(
        f"{m['role'].capitalize()}: {m['content']}"
        for m in history[-6:]
    )
    system_prompt = (
        "You are an IT incident analyst. Answer questions based ONLY on "
        "the provided incident reports. If the answer cannot be determined, "
        "say 'Not enough information available.' Be concise. No explanations."
    )
    user_prompt = (
        f"Conversation history:\n{recent}\n\n"
        f"Incident reports:\n{context_text}\n\n"
        f"Question: {question}\n\nAnswer:"
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    return llm.chat(messages)
# F9: two-stage citation retrieval - broad candidate fetch + LLM reranking.
def find_citations(question):
    """Return up to 5 most relevant incidents for a question via LLM reranking."""
    candidates = db.get_recent_summaries(50)
    if not candidates:
        return []
    lines = []
    for inc in candidates:
        cat = inc.get("category") or "?"
        sev = inc.get("severity") or "?"
        summary = (inc.get("summary") or "")[:120]
        lines.append(f"#{inc['id']} ({cat}, {sev}): {summary}")
    system_prompt = (
        "You are a citation finder. Given a question and a list of incidents, "
        "select up to 5 incident IDs most relevant to the question. "
        "Return ONLY a JSON array of IDs: [id1, id2, id3]. "
        "If no incidents are relevant, return []."
    )
    user_prompt = (
        f"Question: {question}\n\n"
        f"Incidents:\n" + "\n".join(lines) + "\n\n"
        "Relevant IDs (JSON array, max 5):"
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    response = llm.chat(messages)
    import re
    ids = []
    try:
        parsed = json.loads(response)
        if isinstance(parsed, list):
            ids = [int(i) for i in parsed[:5]]
    except (json.JSONDecodeError, ValueError, TypeError):
        ids = [int(m) for m in re.findall(r"\b\d+\b", response)][:5]
    results = []
    for cid in ids:
        inc = db.get_incident_by_id(cid)
        if inc:
            results.append(inc)
    return results
st.title("Smart Incident Manager")
st.caption("Submit an IT incident report.")
manual_text = st.text_area(
    "Incident Description",
    placeholder="Example: Server CPU usage reaches 95% on production node...",
    height=200,
)
pdf_file = st.file_uploader("Or upload a PDF report", type=["pdf"])
if st.button("Submit Incident"):
    text = manual_text.strip()
    if pdf_file is not None:
        pdf_bytes = pdf_file.read()
        if pdf_bytes:
            try:
                with pdfplumber.open(BytesIO(pdf_bytes)) as pdf:
                    all_text = []
                    for page in pdf.pages:
                        page_text = page.extract_text()
                        if page_text:
                            all_text.append(page_text)
                    text = "\n".join(all_text).strip()
                    if manual_text.strip():
                        text = manual_text.strip() + "\n\n" + text
                if not text:
                    st.error(
                        "Could not extract text from this PDF. "
                        "It may contain only scanned images."
                    )
                    st.stop()
            except Exception:
                st.error(
                    "Failed to parse this file as a PDF. "
                    "Please ensure it is a valid, text-based PDF."
                )
                st.stop()
        else:
            st.error("The uploaded PDF appears to be empty.")
            st.stop()
    if not text:
        st.warning(
            "Please enter incident text or upload a PDF before submitting."
        )
        st.stop()
    incident_id = db.insert_incident(text)
    # F10: persist all analysis at once via centralized layer
    sev, score = score_severity(text)
    recs = recommend(text, classify(text))
    db.save_analysis(
        incident_id,
        summary=summarize(text),
        category=classify(text),
        severity=sev,
        severity_score=score,
        recommendations=recs,
        analysis_version="1.0",
    )
    st.success(
        f"Incident #{incident_id} saved. "
        f"Text length: {len(text)} characters."
    )
def highlight_content(content, query):
    """Wrap all occurrences of query in content with <mark> tags (case-insensitive)."""
    if not query or not content:
        return content
    safe_content = html.escape(content)
    pattern = "(" + "|".join(__import__("re").escape(w) for w in query.split() if len(w) >= 3) + ")"
    return re.sub(pattern, lambda m: "<mark>" + m.group(1) + "</mark>", safe_content, flags=re.IGNORECASE)
st.divider()
st.subheader("Search Incidents")
search_query = st.text_input("Search", placeholder="e.g. database timeout...")
if search_query.strip():
    results = db.search_incidents(search_query)
    if not results:
        st.info("No matching incidents found.")
    else:
        st.caption(f"{len(results)} result(s)")
        for res in results:
            cat = res.get("category") or "?"
            sev = res.get("severity") or "?"
            header = f"#{res['id']} | [{cat}] [{sev}] | {res['created_at'][:19]}"
            with st.expander(header):
                safe_snippet = html.escape(res.get("snippet", ""))
                safe_snippet = safe_snippet.replace("&lt;mark&gt;", "<mark>").replace("&lt;/mark&gt;", "</mark>")
                st.markdown(safe_snippet, unsafe_allow_html=True)
                detail = db.get_incident_by_id(res["id"])
                if detail:
                    summary = detail.get("summary")
                    if not summary:
                        import re
                        sentences = re.split(r"(?<=[.!?])\s+", detail["content"].strip())
                        meaningful = [s.strip() for s in sentences if len(s.strip()) > 5]
                        summary = " ".join(meaningful[:3])
                        db.save_analysis(detail["id"], summary=summary)
                    st.info(f"**Summary**: {summary}")
                    st.markdown(highlight_content(detail["content"], search_query), unsafe_allow_html=True)
st.divider()
st.subheader("QA Assistant")
# F8: conversation history display
for msg in st.session_state.qa_messages:
    if msg["role"] == "user":
        st.markdown(f"**You:** {msg['content']}")
    else:
        st.markdown(f"**Assistant:** {msg['content']}")
# F8: question input
question = st.text_input("Ask a question about incidents", key="qa_question")
if st.button("Ask", key="qa_ask"):
    if question.strip():
        st.session_state.qa_messages.append(
            {"role": "user", "content": question}
        )
        with st.spinner("Analyzing..."):
            answer = answer_question(
                question, st.session_state.qa_messages[:-1]
            )
        st.session_state.qa_messages.append(
            {"role": "assistant", "content": answer}
        )
        st.rerun()
st.divider()
st.subheader("Citation Finder")
# F9: question input for citation retrieval
cite_q = st.text_input("Question to find relevant incidents", key="cite_q")
if st.button("Find Citations", key="cite_btn"):
    if cite_q.strip():
        with st.spinner("Searching with LLM reranking..."):
            cites = find_citations(cite_q)
        if cites:
            st.markdown("**Sources**")
            for inc in cites:
                cat = inc.get("category") or "?"
                sev = inc.get("severity") or "?"
                summary = inc.get("summary") or inc["content"][:100]
                st.markdown(
                    f"- **Incident #{inc['id']}** [{cat}] [{sev}]: {summary}"
                )
                with st.expander("View"):
                    st.text(inc["content"])
        else:
            st.info("No relevant incidents found.")
    else:
        st.warning("Please enter a question.")
st.divider()
st.subheader("Incident History")
incidents = db.get_all_incidents()
if not incidents:
    st.info("No incidents found.")
else:
    options = {}
    for inc in incidents:
        cat = inc.get("category") or "?"
        sev = inc.get("severity") or "?"
        label = f"#{inc['id']} | [{cat}] [{sev}] | {inc['created_at'][:19]} | {inc['preview']}..."
        options[label] = inc['id']
    selected = st.selectbox(
        "Select an incident to view details",
        list(options.keys()),
    )
    selected_id = options[selected]
    incident = db.get_incident_by_id(selected_id)
    if incident:
        cat = incident.get("category") or "?"
        sev = incident.get("severity") or "?"
        st.caption(
            f"Incident #{incident['id']} | [{cat}] [{sev}] | {incident['created_at']}"
        )
        # F4: display summary (generate for legacy incidents)
        summary = incident.get("summary")
        if not summary:
            sentences = re.split(r"(?<=[.!?])\s+", incident["content"].strip())
            meaningful = [s.strip() for s in sentences if len(s.strip()) > 5]
            summary = " ".join(meaningful[:3])
            db.save_analysis(incident["id"], summary=summary)
        st.info(f"**Summary**: {summary}")
        # F7: display recommendations in a green box
        recs = incident.get("recommendations", [])
        if recs:
            body = "**Recommended Actions**\n" + "\n".join(f"- {a}" for a in recs)
            st.success(body)
        st.text(incident["content"])
# F12: generate sample trend data on first run
db.load_sample_trends()
st.divider()
st.subheader("Trend Analysis")
stats = db.get_trend_stats()
# F12: overview metrics and distribution charts
c1, c2 = st.columns(2)
c1.metric("Total Incidents", stats["total"])
c2.metric("Categories", len(stats["by_category"]))
col1, col2 = st.columns(2)
with col1:
    st.caption("Category Distribution")
    if stats["by_category"]:
        st.bar_chart({r["category"]: r["cnt"] for r in stats["by_category"]})
with col2:
    st.caption("Severity Distribution")
    if stats["by_severity"]:
        st.bar_chart({r["severity"]: r["cnt"] for r in stats["by_severity"]})
st.caption("Weekly Incident Trend")
if stats["by_week"]:
    st.line_chart({r["week"]: r["cnt"] for r in stats["by_week"]})
st.divider()
st.subheader("Agent Workflow")
# F11: select incident and run multi-agent workflow
incidents = db.get_all_incidents()
if not incidents:
    st.info("No incidents available for workflow analysis.")
else:
    wf_options = {}
    for inc in incidents:
        label = f"#{inc['id']} | {inc['created_at'][:19]} | {inc['preview']}..."
        wf_options[label] = inc['id']
    sel = st.selectbox(
        "Select an incident for analysis",
        list(wf_options.keys()),
        key="f11_select",
    )
    if st.button("Run Workflow", key="f11_run"):
        incident = db.get_incident_by_id(wf_options[sel])
        if incident:
            steps = run_workflow(incident["content"])
            for i, step in enumerate(steps, 1):
                st.markdown(f"**Step {i}: {step['agent']}**")
                output = step["output"]
                if isinstance(output, list):
                    for item in output:
                        st.markdown(f"- {item}")
                else:
                    st.write(output)
                st.success("Completed")
            st.divider()
            st.subheader("Final Workflow Report")
            st.markdown(f"**Summary:** {steps[0]['output']}")
            st.markdown(f"**Category:** {steps[1]['output']}")
            st.markdown(f"**Severity:** {steps[2]['output']}")
            st.markdown("**Recommendations:**")
            for r in steps[3]["output"]:
                st.markdown(f"- {r}")
