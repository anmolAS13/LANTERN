/**
 * Command Console / Corps Watch component.
 * Manages the three sector cards (Inside, Inbound, Outbound),
 * circular ring gauges with smooth counters, latest alerts per zone,
 * and sensor mesh health percentage.
 */

import { state } from "./state.js";
import { formatAttackLabel, formatLocalTime, ZONE_META } from "./labels.js";

const ZONES = ["inside", "inbound", "outbound"];

export function initStats() {
  state.on("stats_updated", () => updateSectorDisplays());
  state.on("alerts_loaded", () => updateSectorDisplays());
  state.on("alert_added", ({ alert, isHistorical }) => {
    updateSectorDisplays();
    if (!isHistorical && alert.zone) {
      flashSectorCard(alert.zone);
    }
  });

  updateSectorDisplays();
}

/**
 * Update all 3 sector cards and sensor mesh percentage.
 */
export function updateSectorDisplays() {
  for (const zone of ZONES) {
    const cardEl = document.getElementById(`sector-card-${zone}`);
    if (!cardEl) continue;

    const count = Number(state.stats.by_zone[zone] || 0);
    const meta = ZONE_META[zone];

    // Update gauge
    const countEl = cardEl.querySelector(".gauge-count");
    if (countEl) {
      countEl.textContent = String(count);
    }

    const gaugeEl = cardEl.querySelector(".gauge");
    if (gaugeEl) {
      // Progress calculation: scales from 0 to 360deg based on count
      const progressPercent = Math.min(100, count === 0 ? 0 : Math.max(12, count * 7));
      const deg = Math.round(progressPercent * 3.6);
      gaugeEl.style.setProperty("--progress", `${deg}deg`);
      gaugeEl.style.setProperty("--gauge-color", meta.gaugeColor);
    }

    // Update latest alert
    const latest = state.getLatestAlertForZone(zone);
    const titleEl = cardEl.querySelector(".latest-title");
    const reasonEl = cardEl.querySelector(".latest-reason");
    const metaEl = cardEl.querySelector(".latest-meta");

    if (latest) {
      if (titleEl) titleEl.textContent = formatAttackLabel(latest.attack);
      if (reasonEl) reasonEl.textContent = latest.reason || "";
      if (metaEl) {
        const timeStr = formatLocalTime(latest.timestamp);
        const ipStr = latest.source?.ip || "unknown IP";
        metaEl.textContent = `${timeStr} · ${ipStr}`;
      }
    } else {
      if (titleEl) titleEl.textContent = "No sensor reporting yet";
      if (reasonEl) {
        reasonEl.textContent = zone === "inside"
          ? "Awaiting Zone 1 detector telemetry."
          : `Sensor mesh awaiting ${zone} traffic feed.`;
      }
      if (metaEl) metaEl.textContent = "--:--:-- · Standby";
    }
  }

  // Update sensor mesh indicator
  const meshEl = document.getElementById("sensor-mesh-val");
  if (meshEl) {
    meshEl.textContent = state.getSensorMeshPercentage();
  }
}

/**
 * Flash sector card briefly when a new alert for that zone arrives.
 */
function flashSectorCard(zone) {
  const cardEl = document.getElementById(`sector-card-${zone}`);
  if (!cardEl) return;

  const glowClass = `glow-${zone}`;
  cardEl.classList.remove(glowClass);
  // Trigger reflow to restart animation
  void cardEl.offsetWidth;
  cardEl.classList.add(glowClass);

  setTimeout(() => {
    cardEl.classList.remove(glowClass);
  }, 1200);
}
