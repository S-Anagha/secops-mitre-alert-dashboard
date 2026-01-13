SecOps MITRE Alert Dashboard

This project is a lightweight security analytics dashboard that normalizes heterogeneous security alerts, enriches events with MITRE ATT&CK mappings, and provides filterable operational visibility with exportable outputs.

It demonstrates a simple SecOps pipeline for handling alerts from multiple sources such as WAFs, IDS, cloud audit logs, and endpoint systems. Alerts are normalized into a unified schema, assigned severity buckets using explicit rules, and enriched with MITRE ATT&CK tactics and techniques for better triage and visibility.

The dashboard supports filtering by source, severity, and MITRE tactic, visualizes alert trends over time, and allows exporting filtered results to CSV. MITRE enrichment is intentionally rule-based to remain transparent and auditable.

Screenshot:

<img width="1448" height="832" alt="image" src="https://github.com/user-attachments/assets/a69c29a5-ae51-40a2-acda-e7a02cc00f9e" />

Tech stack: Python, Streamlit, Pandas, Altair.

Run locally with:
pip install -r requirements.txt
python -m streamlit run app.py
