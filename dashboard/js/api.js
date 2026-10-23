/**
 * Central API module for LANTERN server.
 * All backend access lives here.
 */

export const API_BASE = "http://127.0.0.1:8000";

/**
 * Derives the WebSocket URL from API_BASE.
 * Handles http -> ws and https -> wss.
 */
export function getWsUrl() {
  const url = new URL(API_BASE);
  const protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${url.host}/ws`;
}

/**
 * Fetch alerts from the backend.
 * @param {Object} [params] - Query parameters
 * @param {string} [params.zone] - inside | inbound | outbound
 * @param {string} [params.severity] - low | medium | high | critical
 * @param {string} [params.attack] - attack name
 * @param {number} [params.limit=100] - default 100
 * @param {number} [params.offset=0]
 * @returns {Promise<Array>}
 */
export async function fetchAlerts(params = {}) {
  const query = new URLSearchParams();
  if (params.zone && params.zone !== "all") query.set("zone", params.zone);
  if (params.severity && params.severity !== "all") query.set("severity", params.severity);
  if (params.attack && params.attack !== "all") query.set("attack", params.attack);
  query.set("limit", String(params.limit || 100));
  if (params.offset) query.set("offset", String(params.offset));

  const res = await fetch(`${API_BASE}/alerts?${query.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts: ${res.status} ${res.statusText}`);
  }
  return await res.json();
}

/**
 * Fetch stats summary { total, by_zone, by_severity, by_attack }.
 * @returns {Promise<Object>}
 */
export async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) {
    throw new Error(`Failed to fetch stats: ${res.status} ${res.statusText}`);
  }
  return await res.json();
}

/**
 * Fetch single alert by ID for the detail drawer.
 * @param {string} id
 * @returns {Promise<Object>}
 */
export async function fetchAlertById(id) {
  const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(id)}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert ${id}: ${res.status} ${res.statusText}`);
  }
  return await res.json();
}

/**
 * Health check endpoint.
 */
export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    return res.ok;
  } catch {
    return false;
  }
}
