# Running the connected LANTERN app

This version connects rule detections and optional ML flow predictions to the
FastAPI alert API, SQLite database, WebSocket, and existing dashboard.
The dashboard and API now share one server and origin.

## 1. Install (Windows PowerShell)

Open this folder in VS Code, then run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For Linux/WSL, activate with `source .venv/bin/activate` instead.
The saved models were trained with scikit-learn 1.9.1, already pinned in
requirements.txt. Keep that version. ML is explicitly enabled with `--ml`;
without it, the sensor runs rule detections only.

## 2. Start the server (terminal 1)

From the repository root with the environment active:

```powershell
python -m uvicorn server.app:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/ in a browser. Do not double-click index.html or
start Live Server: the dashboard uses its own page origin for API and WebSocket
connections. API documentation is at http://127.0.0.1:8000/docs.

## 3. Verify the display first (terminal 2)

Activate the same environment in a second terminal and run:

```powershell
python tools/send_fake_alerts.py --count 10 --interval 1
```

These are synthetic demo alerts, not detected attacks. They exercise the real
API, database and WebSocket. The dashboard should show LIVE, incoming alerts,
zone/severity counts, charts, and clickable alert details. They remain in SQLite
across restarts. For a clean database, stop the server and start it with a new
LANTERN_DB filename.

## 4. Send actual rule detections from a capture

```powershell
python tools/make_captures.py
python -m sensor replay captures/arp_spoof.pcap --gateway-ip 192.168.1.1 --server http://127.0.0.1:8000 --jsonl alerts.jsonl
python -m sensor replay captures/port_scan.pcap --server http://127.0.0.1:8000 --jsonl alerts.jsonl
python -m sensor replay captures/rogue_dhcp.pcap --server http://127.0.0.1:8000 --jsonl alerts.jsonl
```

## 5. Enable ML predictions too

```powershell
python -m sensor replay sensor/test_data/test.pcap --server http://127.0.0.1:8000 --ml --zone inside --jsonl alerts.jsonl
```

For every completed flow, the existing extractor calculates the model features.
All predictions, including benign traffic, are appended to
`ml_module/output/predictions.jsonl`. Attack predictions and benign-classified
anomalies also become dashboard alerts. Click one to see classification
confidence, anomaly score, and flow metadata under detector evidence.
A predicted attack class is a model assessment; it is not an explanation of
which individual feature caused the decision. Feature attribution is not
implemented. Existing rule alerts retain their concrete detection reasons.

The `--zone` option labels ML alerts according to where the sensor is deployed;
it does not infer traffic direction automatically. Existing rule detectors
continue to label their LAN detections as inside. Flows emit at FIN/RST, a packet
limit, timeout evaluated when another IP packet arrives, or shutdown/replay end.

## 6. Live capture (Linux/WSL with a suitable capture interface)

On a network you own or are authorized to monitor:

```bash
sudo .venv/bin/python -m sensor live -i eth0 --gateway-ip 192.168.1.1 --server http://127.0.0.1:8000 --ml --zone inside --jsonl alerts.jsonl
```

Replace eth0 and the gateway address with the actual values. The sensor must
be placed where it can see the relevant traffic. Starting it on an ordinary
laptop does not automatically expose all other devices' traffic. Windows live
capture also requires a Scapy-compatible capture driver; the fake-alert demo
requires no packet capture support.

## Separate machines

Bind the server to `--host 0.0.0.0`, open its port on your trusted LAN, and open
`http://SERVER_LAN_IP:8000/`. Pass that same address to the sensor's `--server`.
The dashboard automatically uses that host for HTTP and WebSocket traffic.
If LANTERN_API_KEY is set, set the same environment variable on the sensor.
The fake-alert tool uses `--api-key` instead. This key protects ingestion;
dashboard reads are not authenticated. Keep this prototype on a trusted LAN.

## Delivery and current limits

HTTP delivery is synchronous with a three-second timeout. Connection/HTTP
failures are logged without stopping capture; failed alerts are not queued or
automatically retried. Use --jsonl for a local backup. The HTTP sink connects
directly rather than using proxy environment variables. This design is for a
small prototype, not high-rate production capture.

GeoIP remains unimplemented, so country stays unknown. This integration does
not implement the README's planned response, isolation, or new attack detectors.
The dashboard history loads the latest 100 alerts, including on reconnect;
aggregate stats cover the whole database.

## Validation performed

- 13 server/integration tests passed (including sensor HTTP payload delivery,
  storage, WebSocket push, dashboard files, API key checks and ML alert mapping).
- Saved models loaded with scikit-learn 1.9.1 and predicted successfully on a
  synthetic 68-feature smoke input. This checks execution, not model accuracy.
- Packet replay/detector tests could not run in the build environment because
  Scapy network-interface initialization is blocked. Run `python -m pytest -q`
  locally to complete those checks.
- Browser rendering and live network capture still require local verification.

## Changed files

- server/app.py: serve the dashboard after the API routes.
- dashboard/js/api.js: derive the API/WebSocket host from the page origin.
- dashboard/js/app.js: reload recent alerts after a reconnect.
- sensor/output.py: HTTP alert sink with optional API key.
- sensor/__main__.py: --server, --ml and --zone; forward flagged ML flows.
- ml_module/inference.py: handle NumPy integer and encoder class mappings.
- tests/test_integration.py: integration coverage.

The GitHub repository has not been modified remotely. This is a local snapshot
with integration changes.
