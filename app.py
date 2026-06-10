import streamlit as st
from io import BytesIO
import pdfplumber
import db

st.set_page_config(page_title="Smart Incident Manager", layout="centered")

db.init_db()

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
    st.success(
        f"Incident #{incident_id} saved. "
        f"Text length: {len(text)} characters."
    )
