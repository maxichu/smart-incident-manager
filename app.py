import re
import streamlit as st
from io import BytesIO
import pdfplumber
import db

st.set_page_config(page_title="Smart Incident Manager", layout="centered")

db.init_db()


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

    # F4: generate and store summary
    db.update_summary(incident_id, summarize(text))

    # F5: classify and store category
    db.update_category(incident_id, classify(text))

    # F6: score severity and store level + score
    sev, score = score_severity(text)
    db.update_severity(incident_id, sev, score)

    st.success(
        f"Incident #{incident_id} saved. "
        f"Text length: {len(text)} characters."
    )



def highlight_content(content, query):
    """Wrap all occurrences of query in content with <mark> tags (case-insensitive)."""
    if not query or not content:
        return content
    pattern = "(" + "|".join(__import__("re").escape(w) for w in query.split() if len(w) >= 3) + ")"
    return re.sub(pattern, lambda m: "<mark>" + m.group(1) + "</mark>", content, flags=re.IGNORECASE)


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
                st.markdown(res["snippet"], unsafe_allow_html=True)
                detail = db.get_incident_by_id(res["id"])
                if detail:
                    summary = detail.get("summary")
                    if not summary:
                        import re
                        sentences = re.split(r"(?<=[.!?])\s+", detail["content"].strip())
                        meaningful = [s.strip() for s in sentences if len(s.strip()) > 5]
                        summary = " ".join(meaningful[:3])
                        db.update_summary(detail["id"], summary)
                    st.info(f"**Summary**: {summary}")
                    st.markdown(highlight_content(detail["content"], search_query), unsafe_allow_html=True)

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
            db.update_summary(incident["id"], summary)
        st.info(f"**Summary**: {summary}")

        st.text(incident["content"])
