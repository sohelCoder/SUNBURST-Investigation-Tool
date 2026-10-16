import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

APP_NAME = "SUNBURST Investigation Workbench"
MAX_BYTES = 15 * 1024 * 1024
KEYWORDS = [
    "solarwinds", "sunburst", "orion", "teardrop", "raindrop",
    "avsvmcloud", "globalcdn", "webshell", "powershell", "encodedcommand",
    "mimikatz", "credential", "lateral movement", "c2", "command and control",
]

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp {background: #0b1020; color: #e8edf8;}
[data-testid="stSidebar"] {background: #111a2d;}
.block-container {padding-top: 1.6rem; max-width: 1250px;}
.hero {padding: 1.35rem 1.5rem; border: 1px solid #283754; border-radius: 18px; background: linear-gradient(120deg,#142541,#111827 70%); margin-bottom: 1rem;}
.hero h1 {margin:0; color:#f4f7ff; font-size:2rem;}
.hero p {color:#b8c7e4; margin:.4rem 0 0 0;}
.note {border-left: 4px solid #e0a84b; padding:.75rem 1rem; background:#211d17; border-radius:8px; color:#f5dfb5;}
.small {color:#a8b5ce; font-size:.88rem;}
</style>
<div class="hero"><h1>🛡️ SUNBURST Investigation Workbench</h1><p>Static file triage • security-log review • exportable findings</p></div>
""", unsafe_allow_html=True)

st.warning("Educational triage prototype — not a validated SUNBURST detector. Findings are heuristic indicators, not proof of compromise. No findings does not mean a file or system is safe.")

with st.sidebar:
    st.title("Workbench")
    page = st.radio("Choose a workspace", ["File Analyzer", "Log Analyzer", "About & Safety"])
    st.divider()
    st.caption("Local-first analysis recommended")
    st.caption("Maximum file size: 15 MB")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def strings_from_bytes(data: bytes, minimum: int = 5):
    found = re.findall(rb"[\x20-\x7e]{" + str(minimum).encode() + rb",}", data)
    return [x.decode("ascii", errors="ignore") for x in found]


def keyword_findings(text: str):
    lower = text.lower()
    return [{"indicator": word, "count": lower.count(word), "severity": "Review"} for word in KEYWORDS if lower.count(word) > 0]


def report_download(report: dict, filename: str):
    payload = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    st.download_button("⬇️ Download JSON report", payload, file_name=filename, mime="application/json", use_container_width=False)

if page == "File Analyzer":
    st.subheader("Static file triage")
    st.write("Upload a file to calculate hashes, estimate entropy, extract printable strings, and check for selected investigation terms. The file is read as data and is never executed by this app.")
    uploaded = st.file_uploader("Choose a file (maximum 15 MB)", help="For sensitive evidence, run the tool locally and avoid public hosting.")
    if uploaded:
        raw = uploaded.getvalue()
        if len(raw) > MAX_BYTES:
            st.error("This file exceeds the 15 MB limit. Choose a smaller file.")
        else:
            decoded = raw.decode("utf-8", errors="replace")
            strings = strings_from_bytes(raw)
            searchable = decoded + "\n" + "\n".join(strings)
            findings = keyword_findings(searchable)
            file_report = {
                "tool": APP_NAME,
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "filename": Path(uploaded.name).name,
                "size_bytes": len(raw),
                "hashes": {
                    "md5": hashlib.md5(raw).hexdigest(),
                    "sha1": hashlib.sha1(raw).hexdigest(),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                },
                "entropy_bits_per_byte": round(entropy(raw), 4),
                "keyword_indicators": findings,
                "strings_count": len(strings),
                "strings_preview": strings[:200],
                "limitations": "Heuristic educational triage only; not a validated SUNBURST detector.",
            }
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("File size", f"{len(raw):,} bytes")
            c2.metric("SHA-256", hashlib.sha256(raw).hexdigest()[:12] + "…")
            c3.metric("Entropy", f"{entropy(raw):.3f} / 8")
            c4.metric("Keyword hits", len(findings))
            with st.expander("File hashes", expanded=True):
                st.code(f"MD5    {file_report['hashes']['md5']}\nSHA-1  {file_report['hashes']['sha1']}\nSHA-256 {file_report['hashes']['sha256']}")
            st.subheader("Keyword indicators")
            if findings:
                st.dataframe(findings, use_container_width=True, hide_index=True)
            else:
                st.info("No configured keywords were found in the extracted text. This is not proof that the file is benign.")
            with st.expander("Printable strings preview"):
                st.text_area("Extracted strings (first 200)", "\n".join(strings[:200]) or "No printable strings found.", height=260)
            report_download(file_report, "sunburst_file_triage_report.json")

elif page == "Log Analyzer":
    st.subheader("Security log review")
    st.write("Paste text logs or load the included fictional training sample. Matching is keyword-based and intended to help an analyst decide what to review next.")
    sample_path = Path(__file__).parent / "samples" / "sample_security_log.txt"
    if st.button("Load fictional sample log"):
        st.session_state["log_text"] = sample_path.read_text(encoding="utf-8") if sample_path.exists() else "Sample file not found."
    log_text = st.text_area("Paste log lines", value=st.session_state.get("log_text", ""), height=280, placeholder="Paste authorized log text here…")
    if st.button("Analyze log", type="primary"):
        if not log_text.strip():
            st.error("Paste log text or load the fictional sample first.")
        else:
            lines = log_text.splitlines()
            matched = []
            for idx, line in enumerate(lines, start=1):
                hits = [k for k in KEYWORDS if k in line.lower()]
                if hits:
                    matched.append({"line": idx, "indicators": ", ".join(hits), "log_entry": line[:1000]})
            report = {
                "tool": APP_NAME,
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "input_type": "pasted_text_log",
                "line_count": len(lines),
                "matched_line_count": len(matched),
                "matches": matched,
                "limitations": "Keyword matching only. Context and false positives require human review.",
            }
            a, b, c = st.columns(3)
            a.metric("Lines reviewed", len(lines))
            b.metric("Matching lines", len(matched))
            c.metric("Configured terms", len(KEYWORDS))
            if matched:
                st.dataframe(matched, use_container_width=True, hide_index=True)
            else:
                st.info("No configured keyword matches. This does not establish that the logs are clean.")
            report_download(report, "sunburst_log_review_report.json")

else:
    st.subheader("About this tool")
    st.markdown("""
**Purpose**
- Calculate file hashes (MD5, SHA-1, SHA-256) and byte entropy.
- Extract printable ASCII strings from a small file.
- Search extracted text and pasted logs for a short list of investigation keywords.
- Export a JSON report for documentation.

**Important limitations**
- This is a learning/demo tool, not a forensic suite and not a signature-accurate SUNBURST detector.
- Keyword hits can be false positives; missing hits do not prove safety.
- It does not execute files, repair systems, contact external indicators, or alter evidence.
- Keep original evidence unchanged and record chain-of-custody details separately.

**Privacy**
- Local use keeps processing on your computer.
- If you deploy this app publicly, uploaded files and pasted logs are processed by the hosted app. Do not upload confidential, personal, or client evidence to a public deployment.

**Official references**
- [CISA: Active Exploitation of SolarWinds Software](https://www.cisa.gov/news-events/alerts/2020/12/13/active-exploitation-solarwinds-software)
- [CISA Analysis Report AR21-039A](https://www.cisa.gov/news-events/analysis-reports/ar21-039a)
- [MITRE ATT&CK: SUNBURST (S0559)](https://attack.mitre.org/software/S0559/)
""")

st.divider()
st.markdown('<p class="small">SUNBURST Investigation Workbench • Static analysis only • Use only with files and logs you are authorized to examine.</p>', unsafe_allow_html=True)
