/**
 * Main application entry point for LANTERN dashboard.
 * Coordinates WebSocket connection, initial API loads, mock mode,
 * drag-and-drop JSONL ingestion, and critical alert visual flares.
 */

import { fetchAlerts, fetchStats, getWsUrl, API_BASE } from "./api.js";
import { state } from "./state.js";
import { initFeed } from "./feed.js";
import { initStats } from "./stats.js";
import { initCharts } from "./charts.js";
import { initDrawer } from "./drawer.js";
import { startMockMode } from "./mock.js";

let ws = null;
let reconnectDelay = 1000;
let reconnectTimer = null;
let statsSyncTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  initUIComponents();
  setupDragAndDrop();
  setupConnectionListeners();
  setupLogoFlare();

  const urlParams = new URLSearchParams(window.location.search);
  const isMockRequested = urlParams.get("mock") === "1";

  if (isMockRequested) {
    console.log("[LANTERN] Starting in mock mode (?mock=1)");
    startMockMode();
    const demoBadge = document.getElementById("demo-data-badge");
    if (demoBadge) demoBadge.style.display = "inline-block";
  } else {
    bootLiveBackend();
  }
});

function initUIComponents() {
  initFeed();
  initStats();
  initCharts();
  initDrawer();
}

/**
 * Boots the connection with the live FastAPI backend:
 * 1. GET /alerts?limit=100
 * 2. GET /stats
 * 3. WS ws://127.0.0.1:8000/ws
 */
async function bootLiveBackend() {
  state.setConnectionStatus("RECONNECTING");

  try {
    const [alertsData, statsData] = await Promise.all([
      fetchAlerts({ limit: 100 }),
      fetchStats(),
    ]);

    hideBackendDownBanner();
    state.setStats(statsData);
    state.addAlerts(alertsData);

    // Open live WebSocket
    connectWebSocket();

    // Periodic stats re-sync every 30s
    if (statsSyncTimer) clearInterval(statsSyncTimer);
    statsSyncTimer = setInterval(async () => {
      try {
        const freshStats = await fetchStats();
        state.setStats(freshStats);
      } catch (err) {
        console.warn("[LANTERN] Periodic stats re-sync failed:", err);
      }
    }, 30000);

  } catch (err) {
    console.warn("[LANTERN] Initial backend connection failed:", err);
    state.setConnectionStatus("OFFLINE");
    showBackendDownBanner();
    scheduleReconnect();
  }
}

/**
 * WebSocket manager with exponential backoff (1s up to 30s).
 */
function connectWebSocket() {
  if (ws) {
    try {
      ws.close();
    } catch {
      // ignore
    }
    ws = null;
  }

  const wsUrl = getWsUrl();
  console.log(`[LANTERN] Connecting WebSocket: ${wsUrl}`);

  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    console.error("[LANTERN] Failed to construct WebSocket:", err);
    state.setConnectionStatus("OFFLINE");
    showBackendDownBanner();
    scheduleReconnect();
    return;
  }

  ws.onopen = () => {
    console.log("[LANTERN] WebSocket connected (LIVE)");
    state.setConnectionStatus("LIVE");
    hideBackendDownBanner();
    reconnectDelay = 1000; // Reset backoff
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data && typeof data === "object") {
        state.addAlert(data, false);
      }
    } catch (err) {
      console.error("[LANTERN] Error parsing WebSocket message:", err);
    }
  };

  ws.onerror = (err) => {
    console.warn("[LANTERN] WebSocket error encountered");
    state.setConnectionStatus("RECONNECTING");
  };

  ws.onclose = () => {
    console.warn("[LANTERN] WebSocket closed. Scheduling reconnect.");
    state.setConnectionStatus("RECONNECTING");
    scheduleReconnect();
  };
}

function scheduleReconnect() {
  if (reconnectTimer) return;

  console.log(`[LANTERN] Will attempt reconnect in ${reconnectDelay / 1000}s`);
  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null;
    reconnectDelay = Math.min(30000, reconnectDelay * 2);

    try {
      const stats = await fetchStats();
      state.setStats(stats);
      connectWebSocket();
    } catch {
      state.setConnectionStatus("OFFLINE");
      showBackendDownBanner();
      scheduleReconnect();
    }
  }, reconnectDelay);
}

function setupConnectionListeners() {
  const pillEl = document.getElementById("connection-status-pill");
  const pillDot = pillEl ? pillEl.querySelector(".pulse-dot") : null;
  const pillText = document.getElementById("connection-status-text");

  state.on("connection_changed", (status) => {
    if (!pillEl) return;

    pillEl.className = `status-pill pill-${status.toLowerCase()}`;
    if (pillText) {
      pillText.textContent = status;
    }

    if (status === "LIVE") {
      hideBackendDownBanner();
    } else if (status === "OFFLINE") {
      showBackendDownBanner();
    }
  });
}

function showBackendDownBanner() {
  const banner = document.getElementById("backend-down-banner");
  const apiUrlSpan = document.getElementById("banner-api-url");
  if (banner) {
    if (apiUrlSpan) apiUrlSpan.textContent = API_BASE;
    banner.classList.add("visible");
  }
}

function hideBackendDownBanner() {
  const banner = document.getElementById("backend-down-banner");
  if (banner) {
    banner.classList.remove("visible");
  }
}

/**
 * Logo flare effect: when a critical alert arrives, the lantern flares bright emerald.
 */
function setupLogoFlare() {
  const lanternWrap = document.querySelector(".lantern-wrap");
  if (!lanternWrap) return;

  state.on("critical_alert", () => {
    // Check reduced motion preference
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    lanternWrap.classList.remove("lantern-flare");
    void lanternWrap.offsetWidth; // Force reflow
    lanternWrap.classList.add("lantern-flare");
    setTimeout(() => {
      lanternWrap.classList.remove("lantern-flare");
    }, 750);
  });
}

/**
 * Drag and drop support for alerts.jsonl files.
 */
function setupDragAndDrop() {
  const dropOverlay = document.getElementById("drop-overlay");

  window.addEventListener("dragenter", (e) => {
    e.preventDefault();
    if (dropOverlay) dropOverlay.classList.add("active");
  });

  window.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (dropOverlay) dropOverlay.classList.add("active");
  });

  window.addEventListener("dragleave", (e) => {
    if (e.relatedTarget === null && dropOverlay) {
      dropOverlay.classList.remove("active");
    }
  });

  window.addEventListener("drop", async (e) => {
    e.preventDefault();
    if (dropOverlay) dropOverlay.classList.remove("active");

    const files = e.dataTransfer?.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    console.log(`[LANTERN] Processing dropped file: ${file.name}`);

    try {
      const text = await file.text();
      const lines = text.split(/\r?\n/);
      const parsedAlerts = [];

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const alert = JSON.parse(trimmed);
          if (alert && alert.id) {
            parsedAlerts.push(alert);
          }
        } catch {
          // Skip malformed line
        }
      }

      if (parsedAlerts.length > 0) {
        state.addAlerts(parsedAlerts);
        console.log(`[LANTERN] Successfully ingested ${parsedAlerts.length} alerts from ${file.name}`);
      }
    } catch (err) {
      console.error("[LANTERN] Failed reading dropped file:", err);
    }
  });
}
