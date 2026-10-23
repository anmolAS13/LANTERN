/**
 * Central reactive state store for LANTERN dashboard.
 * Manages de-duplicated alerts, stats counters, active filters, and connection status.
 */

class AppState {
  constructor() {
    this.alerts = new Map(); // id -> alert
    this.stats = {
      total: 0,
      by_zone: { inside: 0, inbound: 0, outbound: 0 },
      by_severity: { low: 0, medium: 0, high: 0, critical: 0 },
      by_attack: {},
    };
    this.filters = {
      severity: "all",
      zone: "all",
    };
    this.connectionStatus = "OFFLINE"; // 'LIVE' | 'RECONNECTING' | 'OFFLINE'
    this.isMock = false;
    this.listeners = new Map(); // event -> Set<callback>
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    return () => this.listeners.get(event).delete(callback);
  }

  emit(event, data) {
    const handlers = this.listeners.get(event);
    if (handlers) {
      for (const cb of handlers) {
        try {
          cb(data);
        } catch (err) {
          console.error(`Error in state listener for ${event}:`, err);
        }
      }
    }
  }

  setConnectionStatus(status) {
    if (this.connectionStatus === status) return;
    this.connectionStatus = status;
    this.emit("connection_changed", status);
  }

  setMockMode(isMock) {
    this.isMock = Boolean(isMock);
    this.emit("mock_mode_changed", this.isMock);
  }

  setFilters(filters) {
    this.filters = { ...this.filters, ...filters };
    this.emit("filters_changed", this.filters);
  }

  setStats(newStats) {
    if (!newStats) return;
    this.stats = {
      total: Number(newStats.total || 0),
      by_zone: {
        inside: Number(newStats.by_zone?.inside || 0),
        inbound: Number(newStats.by_zone?.inbound || 0),
        outbound: Number(newStats.by_zone?.outbound || 0),
      },
      by_severity: {
        low: Number(newStats.by_severity?.low || 0),
        medium: Number(newStats.by_severity?.medium || 0),
        high: Number(newStats.by_severity?.high || 0),
        critical: Number(newStats.by_severity?.critical || 0),
      },
      by_attack: { ...(newStats.by_attack || {}) },
    };
    this.emit("stats_updated", this.stats);
  }

  /**
   * Add a single alert.
   * Handles de-duplication by id (string).
   * Increments local counters if unique and new.
   * @param {Object} alert
   * @param {boolean} [isHistorical=false]
   * @returns {boolean} true if alert was newly added, false if duplicate
   */
  addAlert(alert, isHistorical = false) {
    if (!alert || !alert.id) return false;
    const id = String(alert.id);
    if (this.alerts.has(id)) {
      return false; // Already present
    }

    this.alerts.set(id, alert);

    // If live incoming, increment local counters
    if (!isHistorical) {
      this.stats.total += 1;
      const z = alert.zone;
      if (z) {
        this.stats.by_zone[z] = (this.stats.by_zone[z] || 0) + 1;
      }
      const s = alert.severity;
      if (s) {
        this.stats.by_severity[s] = (this.stats.by_severity[s] || 0) + 1;
      }
      const a = alert.attack;
      if (a) {
        this.stats.by_attack[a] = (this.stats.by_attack[a] || 0) + 1;
      }
      this.emit("stats_updated", this.stats);
    }

    this.emit("alert_added", { alert, isHistorical });

    if (alert.severity === "critical") {
      this.emit("critical_alert", alert);
    }

    return true;
  }

  /**
   * Add multiple alerts (e.g. from history load or JSONL import).
   * @param {Array<Object>} alertList
   */
  addAlerts(alertList) {
    if (!Array.isArray(alertList)) return;
    let addedCount = 0;
    for (const alert of alertList) {
      if (this.addAlert(alert, true)) {
        addedCount++;
      }
    }
    // Re-sync local stats counts if we loaded without initial /stats
    if (this.stats.total === 0 && this.alerts.size > 0) {
      this.recalculateStatsFromAlerts();
    }
    this.emit("alerts_loaded", { count: addedCount, total: this.alerts.size });
  }

  recalculateStatsFromAlerts() {
    const total = this.alerts.size;
    const by_zone = { inside: 0, inbound: 0, outbound: 0 };
    const by_severity = { low: 0, medium: 0, high: 0, critical: 0 };
    const by_attack = {};

    for (const a of this.alerts.values()) {
      if (a.zone && by_zone[a.zone] !== undefined) by_zone[a.zone]++;
      if (a.severity && by_severity[a.severity] !== undefined) by_severity[a.severity]++;
      if (a.attack) by_attack[a.attack] = (by_attack[a.attack] || 0) + 1;
    }

    this.stats = { total, by_zone, by_severity, by_attack };
    this.emit("stats_updated", this.stats);
  }

  /**
   * Get sorted list of alerts matching current filters.
   * Newest first.
   */
  getFilteredAlerts() {
    const { severity, zone } = this.filters;
    const result = [];

    for (const alert of this.alerts.values()) {
      if (severity !== "all" && alert.severity !== severity) continue;
      if (zone !== "all" && alert.zone !== zone) continue;
      result.push(alert);
    }

    result.sort((a, b) => {
      const ta = new Date(a.timestamp || 0).getTime();
      const tb = new Date(b.timestamp || 0).getTime();
      return tb - ta;
    });

    return result;
  }

  /**
   * Get latest alert for a specific zone.
   * @param {'inside'|'inbound'|'outbound'} zone
   */
  getLatestAlertForZone(zone) {
    let latest = null;
    let latestTime = -Infinity;

    for (const alert of this.alerts.values()) {
      if (alert.zone === zone) {
        const t = new Date(alert.timestamp || 0).getTime();
        if (t > latestTime) {
          latestTime = t;
          latest = alert;
        }
      }
    }
    return latest;
  }

  /**
   * Sensor mesh health percentage: percentage of the 3 zones that have reported.
   */
  getSensorMeshPercentage() {
    const zones = ["inside", "inbound", "outbound"];
    let reported = 0;
    for (const z of zones) {
      if ((this.stats.by_zone[z] || 0) > 0) {
        reported++;
      }
    }
    if (reported === 0) return "0.0%";
    if (reported === 3) return "100%";
    return `${((reported / 3) * 100).toFixed(1)}%`;
  }
}

export const state = new AppState();
