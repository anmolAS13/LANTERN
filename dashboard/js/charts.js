/**
 * Telemetry and Breakdown Charts using Chart.js (v4.4.7).
 * - "Alerts over time" multi-line chart (Inside, Inbound, Outbound) bucketed per minute.
 * - Attack breakdown doughnut chart.
 * - Collapsible telemetry section via chevron button.
 */

import { state } from "./state.js";
import { formatAttackLabel } from "./labels.js";

let timeChart = null;
let attackChart = null;
let isTelemetryCollapsed = false;

export function initCharts() {
  const lineCanvas = document.getElementById("time-chart");
  const doughnutCanvas = document.getElementById("breakdown-chart");
  const toggleBtn = document.getElementById("toggle-telemetry-btn");
  const telemetryBody = document.getElementById("telemetry-body");

  if (toggleBtn && telemetryBody) {
    toggleBtn.addEventListener("click", () => {
      isTelemetryCollapsed = !isTelemetryCollapsed;
      telemetryBody.classList.toggle("collapsed", isTelemetryCollapsed);
      toggleBtn.classList.toggle("rotated", isTelemetryCollapsed);
      toggleBtn.setAttribute("aria-expanded", String(!isTelemetryCollapsed));
    });
  }

  // Check if Chart.js is loaded
  if (typeof window.Chart === "undefined") {
    console.warn("Chart.js not loaded from CDN.");
    return;
  }

  // Common dark theme defaults for Chart.js
  Chart.defaults.color = "#888";
  Chart.defaults.font.family = "'Chakra Petch', sans-serif";
  Chart.defaults.font.size = 10;

  if (lineCanvas) {
    setupTimeChart(lineCanvas);
  }

  if (doughnutCanvas) {
    setupBreakdownChart(doughnutCanvas);
  }

  state.on("alerts_loaded", () => updateAllCharts());
  state.on("alert_added", () => updateAllCharts());
  state.on("stats_updated", () => updateAllCharts());

  updateAllCharts();
}

/**
 * Configure line chart for alerts over time.
 */
function setupTimeChart(canvas) {
  const ctx = canvas.getContext("2d");
  timeChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "Inside",
          data: [],
          borderColor: "#6fe3a0",
          backgroundColor: "rgba(111, 227, 160, 0.1)",
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 5,
          fill: false,
        },
        {
          label: "Inbound",
          data: [],
          borderColor: "#1fe36f",
          backgroundColor: "rgba(31, 227, 111, 0.1)",
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 5,
          fill: false,
        },
        {
          label: "Outbound",
          data: [],
          borderColor: "#b8923f",
          backgroundColor: "rgba(184, 146, 63, 0.1)",
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 2,
          pointHoverRadius: 5,
          fill: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }, // Custom legend used in HTML
        tooltip: {
          backgroundColor: "#111",
          borderColor: "#333",
          borderWidth: 1,
          titleFont: { family: "'Chakra Petch', sans-serif" },
          bodyFont: { family: "'IBM Plex Sans', sans-serif" },
        },
      },
      scales: {
        x: {
          grid: { color: "#1a1a1a" },
          ticks: { color: "#666", maxRotation: 0 },
        },
        y: {
          beginAtZero: true,
          suggestedMax: 5,
          grid: { color: "#1a1a1a" },
          ticks: { color: "#666", precision: 0 },
        },
      },
    },
  });
}

/**
 * Configure doughnut chart for attack breakdown.
 */
function setupBreakdownChart(canvas) {
  const ctx = canvas.getContext("2d");
  attackChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: [],
      datasets: [
        {
          data: [],
          backgroundColor: [
            "#1fe36f",
            "#b8923f",
            "#ff9a3c",
            "#ff4d5e",
            "#6fe3a0",
            "#e6d04a",
            "#0a7a3a",
          ],
          borderColor: "#080808",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "70%",
      plugins: {
        legend: {
          position: "right",
          labels: {
            color: "#aaa",
            font: { size: 9, family: "'Chakra Petch', sans-serif" },
            boxWidth: 8,
            padding: 8,
          },
        },
        tooltip: {
          backgroundColor: "#111",
          borderColor: "#333",
          borderWidth: 1,
        },
      },
    },
  });
}

/**
 * Update time chart buckets and attack breakdown data.
 */
export function updateAllCharts() {
  updateTimeChartData();
  updateBreakdownChartData();
}

function updateTimeChartData() {
  if (!timeChart) return;

  // Bucket alerts into 1-minute intervals over the last 15 minutes
  const now = Date.now();
  const minutes = 15;
  const bucketLabels = [];
  const insideCounts = new Array(minutes).fill(0);
  const inboundCounts = new Array(minutes).fill(0);
  const outboundCounts = new Array(minutes).fill(0);

  for (let i = minutes - 1; i >= 0; i--) {
    const t = new Date(now - i * 60 * 1000);
    bucketLabels.push(t.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit" }));
  }

  for (const alert of state.alerts.values()) {
    const alertTime = new Date(alert.timestamp || 0).getTime();
    const diffMs = now - alertTime;
    const diffMin = Math.floor(diffMs / 60000);

    if (diffMin >= 0 && diffMin < minutes) {
      const idx = minutes - 1 - diffMin;
      if (alert.zone === "inside") insideCounts[idx]++;
      else if (alert.zone === "inbound") inboundCounts[idx]++;
      else if (alert.zone === "outbound") outboundCounts[idx]++;
    }
  }

  timeChart.data.labels = bucketLabels;
  timeChart.data.datasets[0].data = insideCounts;
  timeChart.data.datasets[1].data = inboundCounts;
  timeChart.data.datasets[2].data = outboundCounts;
  timeChart.update("none"); // update without layout thrash
}

function updateBreakdownChartData() {
  if (!attackChart) return;

  const attackMap = state.stats.by_attack || {};
  const labels = [];
  const counts = [];

  for (const [key, count] of Object.entries(attackMap)) {
    if (count > 0) {
      labels.push(formatAttackLabel(key));
      counts.push(count);
    }
  }

  if (labels.length === 0) {
    labels.push("No Threats");
    counts.push(1);
    attackChart.data.datasets[0].backgroundColor = ["#222"];
  } else {
    attackChart.data.datasets[0].backgroundColor = [
      "#1fe36f",
      "#b8923f",
      "#ff9a3c",
      "#ff4d5e",
      "#6fe3a0",
      "#e6d04a",
      "#0a7a3a",
    ];
  }

  attackChart.data.labels = labels;
  attackChart.data.datasets[0].data = counts;
  attackChart.update("none");
}
