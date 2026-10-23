# 🏮 LANTERN Dashboard

The operator console for LANTERN, a three-zone network intrusion detection system. Built with plain HTML, CSS, and vanilla ES modules — zero build step, zero npm, zero React.

---

## 🚀 Running the Dashboard

### 1. With the Live Backend (Default)

1. **Start the LANTERN server** from the repository root:
   ```bash
   python -m uvicorn server.app:app --reload
   ```
   (Verify backend is reachable at `http://127.0.0.1:8000/docs`).

2. **Serve the dashboard** from the `dashboard/` directory:
   ```bash
   cd dashboard
   python -m http.server 5500
   ```

3. Open your browser at:
   ```
   http://127.0.0.1:5500
   ```

4. **Send simulated alerts** to see the live feed and gauges update in real time:
   ```bash
   # In a separate terminal from repository root:
   python tools/send_fake_alerts.py --count 20 --interval 1.0
   ```

---

### 2. Standalone Mock Mode (`?mock=1`)

For quick demos, offline presentations, or when the backend server is not running:

1. Serve `dashboard/`:
   ```bash
   python -m http.server 5500
   ```

2. Open:
   ```
   http://127.0.0.1:5500/?mock=1
   ```

- Automatically generates 30 historical seed alerts across all 3 zones and 7 attack types.
- Streams a new realistic alert every 2.5 seconds.
- Displays the `DEMO DATA` badge in the header.
- Fully functional without any backend running.

---

### 3. Drag-and-Drop Capture Replay (`alerts.jsonl`)

To inspect real sensor replay output offline:

1. Generate an `alerts.jsonl` file using the sensor replay mode:
   ```bash
   python -m sensor replay captures/arp_spoof.pcap --gateway-ip 192.168.1.1 --jsonl alerts.jsonl
   ```

2. Open the dashboard in your browser.
3. Simply **drag and drop** the `alerts.jsonl` file anywhere onto the dashboard page.
4. Alerts will be ingested, de-duplicated by ID, and rendered into the live signal stream, counters, and telemetry charts.

---

## 🎨 Key Features & Design System

- **Corps Watch**: Three sector cards (`Inside`, `Inbound`, `Outbound`) with animated circular ring gauges, alert counters, and latest threat summary.
- **Sensor Mesh Readout**: Dynamic health indicator showing the percentage of zones reporting active telemetry.
- **Live Alert Feed**: Filter chips for Severity (`ALL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and Sector (`ALL`, `INSIDE`, `INBOUND`, `OUTBOUND`).
- **Telemetry Charts**: Powered by pinned Chart.js (v4.4.7). Alerts-over-time per minute (Inside, Inbound, Outbound) plus an attack breakdown doughnut chart. Collapsible via chevron.
- **Threat Inspection Drawer**: Slide-over drawer on alert click with generic key/value formatting for detector evidence.
- **Resilient Connectivity**: Automatic exponential backoff (1s to 30s) on WebSocket disconnect, with LIVE / RECONNECTING / OFFLINE pill status and backend warning banner.
- **Motion & Accessibility**: Strictly respects `prefers-reduced-motion` and ensures pure textContent rendering for security against XSS.
