import ast
import csv
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

APP_NAME = "BugHunter AI"
MAX_FILES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
ALLOWED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rb", ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".txt"}

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

RULES = [
    ("Hardcoded secret or API key", "High", re.compile(r"(?i)(api[_-]?key|secret[_-]?key|password|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]"), "Move secrets to environment variables or a secrets manager. Rotate any exposed credential."),
    ("Private key material", "Critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Remove the private key from source control and rotate/revoke it immediately."),
    ("SQL built with string formatting", "High", re.compile(r"(?i)(execute|executemany)\s*\(\s*f['\"]"), "Use parameterized SQL queries instead of interpolating untrusted values."),
    ("TLS certificate verification disabled", "High", re.compile(r"(?i)(verify\s*=\s*False|CERT_NONE)"), "Enable certificate verification. Do not disable TLS validation in production."),
    ("Dangerous eval/exec usage", "High", re.compile(r"\b(eval|exec)\s*\("), "Avoid evaluating dynamic input. Use a safe parser or an explicit allowlist."),
    ("Unsafe pickle deserialization", "High", re.compile(r"\bpickle\.(loads|load)\s*\("), "Never unpickle untrusted data. Prefer JSON or another non-executable data format."),
    ("Shell command execution", "Medium", re.compile(r"(?i)(os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\([^\n]*shell\s*=\s*True)"), "Avoid shell=True and os.system with untrusted input. Pass an argument list and validate inputs."),
    ("Weak hash algorithm", "Medium", re.compile(r"(?i)(md5|sha1)\s*\("), "Use SHA-256 or a modern password-hashing algorithm such as Argon2/bcrypt for passwords."),
    ("Debug mode enabled", "Low", re.compile(r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True)"), "Disable debug mode in production to avoid exposing diagnostics and sensitive data."),
    ("Wildcard CORS origin", "Medium", re.compile(r"(?i)(allow_origins\s*=\s*\[\s*['\"]\*['\"]|Access-Control-Allow-Origin\s*:\s*\*)"), "Restrict CORS to the exact trusted origins required by the application."),
]

def safe_extract(uploaded_file):
    entries = []
    total = 0
    with zipfile.ZipFile(uploaded_file) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError(f"Archive contains more than {MAX_FILES} entries.")
        for info in infos:
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            path = Path(name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError(f"Unsafe archive path rejected: {name}")
            if info.file_size > MAX_FILE_BYTES:
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("Archive exceeds the 20 MB uncompressed scan limit.")
            if Path(name).suffix.lower() not in ALLOWED_SUFFIXES:
                continue
            if info.flag_bits & 0x1:
                continue
            try:
                raw = archive.read(info)
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            entries.append((name, text))
    return entries

def scan_text(path, text):
    findings = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        for title, severity, pattern, recommendation in RULES:
            if pattern.search(line):
                findings.append({
                    "file": path, "line": number, "severity": severity,
                    "finding": title, "evidence": line.strip()[:240],
                    "recommendation": recommendation, "tool": "Built-in rules"
                })
    if path.endswith(".py"):
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml" and node.func.attr in {"load", "unsafe_load"}:
                        findings.append({"file": path, "line": getattr(node, "lineno", 1), "severity": "High", "finding": "Potential unsafe YAML loading", "evidence": "yaml.load/unsafe_load call", "recommendation": "Use yaml.safe_load for untrusted YAML input.", "tool": "Python AST"})
        except SyntaxError:
            pass
    return findings

def run_bandit(files):
    results = []
    if shutil.which("bandit") is None:
        return results, "Bandit is not installed in this environment."
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, content in files:
            if Path(name).suffix.lower() == ".py":
                dest = root / Path(name).name
                dest.write_text(content, encoding="utf-8")
        py_files = list(root.glob("*.py"))
        if not py_files:
            return results, "No Python files found for Bandit."
        proc = subprocess.run(["bandit", "-r", str(root), "-f", "json", "-q"], capture_output=True, text=True, timeout=60)
        try:
            payload = json.loads(proc.stdout or "{}")
            for item in payload.get("results", []):
                results.append({
                    "file": item.get("filename", "").replace(str(root), "").lstrip("/\\"),
                    "line": item.get("line_number", 0),
                    "severity": {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get(item.get("issue_severity", "LOW"), "Low"),
                    "finding": item.get("test_name", "Bandit finding"),
                    "evidence": item.get("code", "").strip()[:240],
                    "recommendation": item.get("issue_text", "Review this finding and apply secure coding practices."),
                    "tool": "Bandit"
                })
        except (ValueError, TypeError):
            return results, "Bandit ran but its JSON output could not be parsed."
    return results, "Bandit scan completed."

def severity_counts(findings):
    return {level: sum(1 for item in findings if item["severity"] == level) for level in ["Critical", "High", "Medium", "Low"]}

def make_pdf(findings, project_name):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        return None
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=32, leftMargin=32, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [Paragraph("BugHunter AI Security Report", styles["Title"]), Paragraph(f"Project: {project_name}", styles["Normal"]), Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]), Spacer(1, 14)]
    counts = severity_counts(findings)
    story.append(Paragraph("Severity summary: " + " | ".join(f"{k}: {v}" for k, v in counts.items()), styles["Heading2"]))
    data = [["Severity", "File", "Line", "Finding", "Recommendation"]]
    for f in findings[:250]:
        data.append([f["severity"], f["file"][:35], str(f["line"]), f["finding"][:42], f["recommendation"][:110]])
    if len(data) == 1:
        data.append(["—", "—", "—", "No findings", "No issues detected by enabled checks."])
    table = Table(data, colWidths=[52, 90, 28, 110, 220], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#172554")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), 0.35, colors.grey), ("VALIGN", (0,0), (-1,-1), "TOP"), ("FONTSIZE", (0,0), (-1,-1), 7), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F1F5F9")])]))
    story.append(table)
    doc.build(story)
    return buffer.getvalue()

st.title("🛡️ BugHunter AI")
st.caption("Static source-code security analysis • Upload a ZIP you own or are authorized to assess.")
with st.sidebar:
    st.header("Scan settings")
    use_bandit = st.checkbox("Run Bandit for Python", value=True, help="Runs Bandit only against extracted Python source files. Uploaded code is never executed.")
    st.markdown("---")
    st.caption("Safety limits: 500 archive entries, 2 MB per file, 20 MB total uncompressed content.")
    st.caption("This tool performs static checks; results require manual validation.")

left, right = st.columns([1.5, 1])
with left:
    project_name = st.text_input("Project name", value="My source code")
    archive = st.file_uploader("Upload project ZIP", type=["zip"], help="ZIP source files for static analysis.")
with right:
    st.markdown("### Checks included")
    st.markdown("- Hardcoded secrets and private keys\n- SQL string interpolation\n- Dangerous eval/exec and pickle\n- TLS verification disabled\n- Shell execution patterns\n- Weak hashes, debug mode, CORS\n- Optional Bandit analysis")

if "history" not in st.session_state:
    st.session_state.history = []
if archive is not None:
    if st.button("🔍 Scan project", type="primary", use_container_width=True):
        try:
            with st.spinner("Inspecting source files safely…"):
                source_files = safe_extract(archive)
                findings = []
                for file_path, content in source_files:
                    findings.extend(scan_text(file_path, content))
                bandit_note = "Bandit disabled."
                if use_bandit:
                    extra, bandit_note = run_bandit(source_files)
                    findings.extend(extra)
                st.session_state.scan = {"project": project_name, "findings": findings, "files": len(source_files), "bandit_note": bandit_note, "created": datetime.now(timezone.utc).isoformat()}
                st.session_state.history.insert(0, {"project": project_name, "findings": len(findings), "files": len(source_files), "created": st.session_state.scan["created"]})
                st.session_state.history = st.session_state.history[:10]
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            st.error(f"Could not scan archive: {exc}")

scan = st.session_state.get("scan")
if scan:
    findings = scan["findings"]
    st.divider()
    st.subheader("Scan overview")
    counts = severity_counts(findings)
    metric_cols = st.columns(5)
    metric_cols[0].metric("Files scanned", scan["files"])
    metric_cols[1].metric("Total findings", len(findings))
    for col, level in zip(metric_cols[2:], ["Critical", "High", "Medium"]):
        col.metric(level, counts[level])
    st.caption(scan["bandit_note"])
    if not findings:
        st.success("No findings were detected by the enabled checks. This does not guarantee that the project is vulnerability-free.")
    else:
        st.markdown("#### Findings by severity")
        st.bar_chart(pd.DataFrame({"Findings": [counts[x] for x in ["Critical", "High", "Medium", "Low"]]}, index=["Critical", "High", "Medium", "Low"]))
        frame = pd.DataFrame(findings)
        selected = st.multiselect("Filter severity", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
        filtered = frame[frame["severity"].isin(selected)]
        st.dataframe(filtered, use_container_width=True, hide_index=True)
        csv_bytes = filtered.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Download CSV report", csv_bytes, file_name="bughunter-findings.csv", mime="text/csv")
        pdf_bytes = make_pdf(findings, scan["project"])
        if pdf_bytes:
            st.download_button("⬇️ Download PDF report", pdf_bytes, file_name="bughunter-report.pdf", mime="application/pdf")
        else:
            st.info("Install reportlab to enable PDF export.")
    with st.expander("Scan metadata"):
        st.write({"project": scan["project"], "files_scanned": scan["files"], "created_utc": scan["created"]})
        st.write("Uploaded source is inspected as text; the application does not run project code.")

with st.expander("Recent scans (this session)"):
    if st.session_state.history:
        st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True, hide_index=True)
    else:
        st.caption("No scans in this session yet.")

st.divider()
st.caption("BugHunter AI is a defensive static-analysis aid, not a substitute for code review, testing, or a professional security assessment.")
