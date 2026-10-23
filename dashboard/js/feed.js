/**
 * Signal Stream / Live Alert Feed component.
 * Renders filter chips, list of alerts (max 50, newest first),
 * prominent plain-English reasons, and connection lines.
 * Strictly adheres to textContent for security (no innerHTML with untrusted data).
 */

import { state } from "./state.js";
import { formatAttackLabel, formatConnection, formatLocalTime, SEVERITY_META } from "./labels.js";
import { openAlertDrawer } from "./drawer.js";

let feedListEl = null;
let feedCountEl = null;

export function initFeed() {
  feedListEl = document.getElementById("alert-feed-list");
  feedCountEl = document.getElementById("feed-count");

  // Setup filter buttons
  const severityFilters = document.querySelectorAll("[data-filter-severity]");
  severityFilters.forEach((btn) => {
    btn.addEventListener("click", () => {
      severityFilters.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.setFilters({ severity: btn.getAttribute("data-filter-severity") });
    });
  });

  const sectorFilters = document.querySelectorAll("[data-filter-zone]");
  sectorFilters.forEach((btn) => {
    btn.addEventListener("click", () => {
      sectorFilters.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.setFilters({ zone: btn.getAttribute("data-filter-zone") });
    });
  });

  // Listen to state changes
  state.on("alerts_loaded", () => renderFeed());
  state.on("filters_changed", () => renderFeed());
  state.on("alert_added", ({ alert, isHistorical }) => {
    if (isHistorical) {
      renderFeed();
    } else {
      handleLiveAlert(alert);
    }
  });

  renderFeed();
}

/**
 * Full re-render of feed list based on current filters.
 */
export function renderFeed() {
  if (!feedListEl) return;

  const filtered = state.getFilteredAlerts();
  const displayed = filtered.slice(0, 50);

  // Update counter display: "XX / YY"
  if (feedCountEl) {
    const totalCount = state.alerts.size;
    const filterCountStr = String(displayed.length).padStart(2, "0");
    const totalCountStr = String(Math.min(totalCount, 50)).padStart(2, "0");
    feedCountEl.textContent = `${filterCountStr} / ${totalCountStr}`;
  }

  // Clear current list safely
  while (feedListEl.firstChild) {
    feedListEl.removeChild(feedListEl.firstChild);
  }

  if (displayed.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-feed";
    empty.textContent = state.alerts.size === 0
      ? "Awaiting incoming telemetry. No alerts recorded yet."
      : "No alerts match the current filter selection.";
    feedListEl.appendChild(empty);
    return;
  }

  for (const alert of displayed) {
    const row = createAlertRow(alert, false);
    feedListEl.appendChild(row);
  }
}

/**
 * Handles a single live alert arriving via WebSocket or mock generator.
 * Prepend with animated glow and cap list at 50 items.
 */
function handleLiveAlert(alert) {
  if (!feedListEl) return;

  // Check if matches active filters
  const { severity, zone } = state.filters;
  if (severity !== "all" && alert.severity !== severity) return;
  if (zone !== "all" && alert.zone !== zone) return;

  // Remove empty message if present
  const empty = feedListEl.querySelector(".empty-feed");
  if (empty) {
    feedListEl.removeChild(empty);
  }

  const row = createAlertRow(alert, true);
  feedListEl.insertBefore(row, feedListEl.firstChild);

  // Keep max 50 items in DOM
  while (feedListEl.children.length > 50) {
    feedListEl.removeChild(feedListEl.lastChild);
  }

  // Update count
  if (feedCountEl) {
    const displayedCount = feedListEl.children.length;
    const totalCount = state.alerts.size;
    feedCountEl.textContent = `${String(displayedCount).padStart(2, "0")} / ${String(Math.min(totalCount, 50)).padStart(2, "0")}`;
  }
}

/**
 * Creates DOM elements for an alert row.
 * Safely sets all textContent (zero innerHTML).
 */
function createAlertRow(alert, isLive = false) {
  const row = document.createElement("article");
  row.className = `alert-row sev-${alert.severity || "low"}`;
  row.setAttribute("role", "button");
  row.setAttribute("tabindex", "0");
  row.setAttribute("aria-label", `View alert details for ${alert.attack || "threat"}`);

  if (isLive) {
    row.classList.add("alert-slide-in");
  }

  // Top header line
  const head = document.createElement("div");
  head.className = "alert-head";

  const sevBadge = document.createElement("span");
  sevBadge.className = `severity-badge ${alert.severity || "low"}`;
  sevBadge.textContent = alert.severity ? alert.severity.toUpperCase() : "INFO";
  head.appendChild(sevBadge);

  const zoneTag = document.createElement("span");
  zoneTag.className = "zone-tag";
  zoneTag.textContent = alert.zone ? alert.zone.toUpperCase() : "UNKNOWN";
  head.appendChild(zoneTag);

  const attackName = document.createElement("span");
  attackName.className = "attack-tag";
  attackName.textContent = formatAttackLabel(alert.attack);
  head.appendChild(attackName);

  if (alert.severity === "critical") {
    const critDot = document.createElement("span");
    critDot.className = "critical-dot";
    critDot.setAttribute("title", "Critical priority alert");
    head.appendChild(critDot);
  }

  const timeEl = document.createElement("time");
  timeEl.className = "alert-time";
  timeEl.textContent = formatLocalTime(alert.timestamp);
  head.appendChild(timeEl);

  row.appendChild(head);

  // Plain-English reason (main selling point, prominent)
  const reasonP = document.createElement("p");
  reasonP.className = "alert-reason";
  reasonP.textContent = alert.reason || "Suspicious network behavior detected.";
  row.appendChild(reasonP);

  // Bottom meta: source -> target & sensor
  const metaDiv = document.createElement("div");
  metaDiv.className = "alert-meta";

  const connSpan = document.createElement("span");
  connSpan.className = "alert-connection";
  connSpan.textContent = formatConnection(alert.source, alert.target);
  metaDiv.appendChild(connSpan);

  const sensorSpan = document.createElement("span");
  sensorSpan.className = "alert-sensor";
  sensorSpan.textContent = alert.sensor || "sensor";
  metaDiv.appendChild(sensorSpan);

  row.appendChild(metaDiv);

  // Interactive drawer opening
  const handleOpen = () => openAlertDrawer(alert);
  row.addEventListener("click", handleOpen);
  row.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleOpen();
    }
  });

  return row;
}
