/**
 * Detail Drawer component.
 * Slides in from the right when an alert is clicked.
 * Fetches GET /alerts/{id} or uses cached alert, rendering details generically as key/value rows.
 * Uses textContent exclusively for untrusted content.
 */

import { fetchAlertById } from "./api.js";
import { formatAttackLabel, formatCountry, formatEndpoint, formatLocalTime } from "./labels.js";


let drawerEl = null;
let backdropEl = null;
let closeBtnEl = null;
let drawerContentEl = null;

export function initDrawer() {
  drawerEl = document.getElementById("detail-drawer");
  backdropEl = document.getElementById("drawer-backdrop");
  closeBtnEl = document.getElementById("drawer-close-btn");
  drawerContentEl = document.getElementById("drawer-content");

  if (closeBtnEl) {
    closeBtnEl.addEventListener("click", closeAlertDrawer);
  }
  if (backdropEl) {
    backdropEl.addEventListener("click", closeAlertDrawer);
  }

  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && isDrawerOpen()) {
      closeAlertDrawer();
    }
  });
}

export function isDrawerOpen() {
  return drawerEl && drawerEl.classList.contains("open");
}

export async function openAlertDrawer(initialAlert) {
  if (!drawerEl || !drawerContentEl) return;

  // Show drawer immediately with initial cached alert data
  renderDrawerContent(initialAlert, true);
  drawerEl.classList.add("open");
  if (backdropEl) backdropEl.classList.add("open");

  // Attempt to fetch fresh alert details from backend
  try {
    const fullAlert = await fetchAlertById(initialAlert.id);
    renderDrawerContent(fullAlert, false);
  } catch (err) {
    // Backend might be offline or in mock mode; cached alert is already shown
    renderDrawerContent(initialAlert, false);
  }
}

export function closeAlertDrawer() {
  if (drawerEl) drawerEl.classList.remove("open");
  if (backdropEl) backdropEl.classList.remove("open");
}

/**
 * Builds the drawer DOM safely with textContent.
 */
function renderDrawerContent(alert, isLoading = false) {
  if (!drawerContentEl) return;

  while (drawerContentEl.firstChild) {
    drawerContentEl.removeChild(drawerContentEl.firstChild);
  }

  // Header section
  const header = document.createElement("div");
  header.className = "drawer-header-info";

  const topBadges = document.createElement("div");
  topBadges.className = "drawer-badges";

  const sev = document.createElement("span");
  sev.className = `severity-badge ${alert.severity || "low"}`;
  sev.textContent = (alert.severity || "info").toUpperCase();
  topBadges.appendChild(sev);

  const zone = document.createElement("span");
  zone.className = "zone-tag";
  zone.textContent = (alert.zone || "unknown").toUpperCase();
  topBadges.appendChild(zone);

  if (isLoading) {
    const loadingBadge = document.createElement("span");
    loadingBadge.className = "drawer-loading-badge";
    loadingBadge.textContent = "SYNCING...";
    topBadges.appendChild(loadingBadge);
  }

  header.appendChild(topBadges);

  const title = document.createElement("h3");
  title.className = "drawer-title";
  title.textContent = formatAttackLabel(alert.attack);
  header.appendChild(title);

  const attackCode = document.createElement("div");
  attackCode.className = "drawer-attack-code";
  attackCode.textContent = `Attack Signature: ${alert.attack || "unknown"}`;
  header.appendChild(attackCode);

  drawerContentEl.appendChild(header);

  // Plain-English Reason Box
  const reasonBox = document.createElement("div");
  reasonBox.className = "drawer-reason-box";

  const reasonLabel = document.createElement("div");
  reasonLabel.className = "drawer-section-kicker";
  reasonLabel.textContent = "// PLAIN ENGLISH EXPLANATION";
  reasonBox.appendChild(reasonLabel);

  const reasonText = document.createElement("p");
  reasonText.textContent = alert.reason || "No explanation provided.";
  reasonBox.appendChild(reasonText);

  drawerContentEl.appendChild(reasonBox);

  // Core Metadata Table
  const metaSection = document.createElement("div");
  metaSection.className = "drawer-section";

  const metaKicker = document.createElement("div");
  metaKicker.className = "drawer-section-kicker";
  metaKicker.textContent = "// CORE TELEMETRY";
  metaSection.appendChild(metaKicker);

  const metaTable = document.createElement("table");
  metaTable.className = "drawer-table";

  const rows = [
    ["Alert ID", alert.id || "-"],
    ["Captured Sensor", alert.sensor || "sensor"],
    ["Local Time", formatLocalTime(alert.timestamp)],
    ["UTC Timestamp", alert.timestamp || "-"],
    ["Source Endpoint", formatEndpoint(alert.source)],
    ["Target Endpoint", alert.target ? formatEndpoint(alert.target) : "None (Broadcast / Ambient)"],
    ["Country", getOriginDisplay(alert)],
  ];

  for (const [key, val] of rows) {
    metaTable.appendChild(createTableRow(key, val));
  }
  metaSection.appendChild(metaTable);
  drawerContentEl.appendChild(metaSection);

  // Generic Details Table (Data Rule 9: Never assume a details key exists)
  const detailsSection = document.createElement("div");
  detailsSection.className = "drawer-section";

  const detailsKicker = document.createElement("div");
  detailsKicker.className = "drawer-section-kicker";
  detailsKicker.textContent = "// DETECTOR EVIDENCE (DETAILS)";
  detailsSection.appendChild(detailsKicker);

  const detailsTable = document.createElement("table");
  detailsTable.className = "drawer-table";

  const detailsObj = alert.details && typeof alert.details === "object" ? alert.details : {};
  const detailKeys = Object.keys(detailsObj);

  if (detailKeys.length === 0) {
    const emptyRow = document.createElement("tr");
    const td = document.createElement("td");
    td.setAttribute("colspan", "2");
    td.className = "drawer-no-details";
    td.textContent = "No detector-specific evidence attached.";
    emptyRow.appendChild(td);
    detailsTable.appendChild(emptyRow);
  } else {
    for (const key of detailKeys) {
      const formattedVal = formatDetailValue(detailsObj[key]);
      detailsTable.appendChild(createTableRow(key, formattedVal));
    }
  }

  detailsSection.appendChild(detailsTable);
  drawerContentEl.appendChild(detailsSection);
}

function createTableRow(key, value) {
  const tr = document.createElement("tr");

  const th = document.createElement("th");
  th.textContent = key;
  tr.appendChild(th);

  const td = document.createElement("td");
  td.textContent = value;
  tr.appendChild(td);

  return tr;
}

function formatDetailValue(val) {
  if (val === null || val === undefined) return "-";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (Array.isArray(val)) {
    return val.length === 0 ? "[]" : val.join(", ");
  }
  if (typeof val === "object") {
    try {
      return JSON.stringify(val);
    } catch {
      return String(val);
    }
  }
  return String(val);
}

function getOriginDisplay(alert) {
  return formatCountry(alert.country, alert.zone);
}
