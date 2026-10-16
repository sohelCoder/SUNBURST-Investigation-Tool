## 🚀 Live Demo

Try the SUNBURST Investigation Workbench online:

[Open Live Application](https://sunburst-investigation-tool-sohelcoder.streamlit.app)

This is an educational prototype for static file analysis and security-log review.

# SUNBURST Investigation Workbench

A small Streamlit learning tool for static file triage and keyword-based security-log review. It calculates file hashes and entropy, extracts printable ASCII strings, checks selected investigation keywords, and exports JSON reports.

## Important limitations

This is an educational prototype, **not a validated SUNBURST detector** or a replacement for an incident-response/forensic workflow. A keyword match is not proof of compromise, and no matches do not prove safety. The app does not execute uploaded files or modify systems.

## Run locally on Windows

Open PowerShell in this project folder (the folder containing `app.py`) and run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open `http://localhost:8501` in your browser. Stop the server with `Ctrl+C` in PowerShell.

If you already have a virtual environment in the parent folder, run its Python executable using the correct relative path from this project folder, for example `..\.venv\Scripts\python.exe`.

## Publish online and get a shareable link

1. Create/sign in to a GitHub account and create a repository, for example `sunburst-investigation-workbench`.
2. Upload `app.py`, `requirements.txt`, `README.md`, and the `samples` folder. **Do not upload `.venv`, evidence files, private logs, or secrets.**
3. Open [Streamlit Community Cloud](https://share.streamlit.io/) and sign in with GitHub.
4. Choose **Create app**, select your repository and branch, and set the main file path to `app.py`.
5. Deploy. When deployment completes, copy the Streamlit app URL and share it.

The shareable URL is created by Streamlit after deployment; it cannot be generated in advance. Public hosting means the server receives uploaded files and pasted logs, so use only fictional or non-sensitive test data online. Use the local version for confidential evidence.

## Included files

- `app.py` — Streamlit application
- `requirements.txt` — Python dependency
- `samples/sample_security_log.txt` — fictional training log
- `README.md` — setup and deployment instructions
