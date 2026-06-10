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

    st.success(
        f"Incident #{incident_id} saved. "
        f"Text length: {len(text)} characters."
    )


st.divider()
st.subheader("Incident History")

incidents = db.get_all_incidents()

if not incidents:
    st.info("No incidents found.")
else:
    options = {}
    for inc in incidents:
        label = f"#{inc['id']} | {inc['created_at'][:19]} | {inc['preview']}..."
        options[label] = inc['id']

    selected = st.selectbox(
        "Select an incident to view details",
        list(options.keys()),
    )

    selected_id = options[selected]
    incident = db.get_incident_by_id(selected_id)

    if incident:
        st.caption(
            f"Incident #{incident['id']} | {incident['created_at']}"
        )

        # F4: display summary (generate for legacy incidents)
        summary = incident.get("summary")
        if not summary:
            import re
            sentences = re.split(r"(?<=[.!?])\s+", incident["content"].strip())
            meaningful = [s.strip() for s in sentences if len(s.strip()) > 5]
            summary = " ".join(meaningful[:3])
            db.update_summary(incident["id"], summary)
        st.info(f"**Summary**: {summary}")

        st.text(incident["content"])
