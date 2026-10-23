/**
 * Lookup table and formatting utilities for LANTERN attack signatures.
 * Never hard-codes severity from attack.
 */

export const ATTACK_LABELS = {
  arp_spoofing: "ARP Spoofing Detected",
  port_scan: "Port Scan Sweep",
  rogue_dhcp: "Rogue DHCP Server",
  ssh_brute_force: "SSH Brute Force",
  sql_injection: "SQL Injection Attempt",
  beaconing: "Malware Beaconing Signal",
  dns_tunneling: "DNS Tunneling Detected",
};

export const ZONE_META = {
  inside: {
    label: "Inside",
    subtitle: "LAN devices in conflict",
    sector: "SECTOR 01",
    color: "#6fe3a0",
    gaugeColor: "#6fe3a0",
  },
  inbound: {
    label: "Inbound",
    subtitle: "Internet → our perimeter",
    sector: "SECTOR 02",
    color: "#1fe36f",
    gaugeColor: "#1fe36f",
  },
  outbound: {
    label: "Outbound",
    subtitle: "Our devices → hostile net",
    sector: "SECTOR 03",
    color: "#b8923f",
    gaugeColor: "#b8923f",
  },
};

export const SEVERITY_META = {
  low: { label: "LOW", color: "#6fe3a0" },
  medium: { label: "MEDIUM", color: "#e6d04a" },
  high: { label: "HIGH", color: "#ff9a3c" },
  critical: { label: "CRITICAL", color: "#ff4d5e" },
};

/**
 * Returns a human-friendly name for an attack code.
 * Falls back to Title-Casing snake_case words so unknown detectors never break the UI.
 */
export function formatAttackLabel(attack) {
  if (!attack) return "Unknown Threat";
  if (ATTACK_LABELS[attack]) {
    return ATTACK_LABELS[attack];
  }
  return attack
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Format an endpoint object { ip, mac, port } cleanly, skipping nulls.
 * Example: "192.168.1.7 (aa:bb:cc:00:00:07):80" or "192.168.1.7"
 */
export function formatEndpoint(ep) {
  if (!ep || typeof ep !== "object") return "unknown";
  const parts = [];
  if (ep.ip) parts.push(ep.ip);
  if (ep.mac) parts.push(`(${ep.mac})`);
  let str = parts.join(" ");
  if (ep.port !== null && ep.port !== undefined) {
    str = str ? `${str}:${ep.port}` : `:${ep.port}`;
  }
  return str || "unknown";
}

/**
 * Format source -> target connection string.
 */
export function formatConnection(source, target) {
  const src = formatEndpoint(source);
  if (!target || (!target.ip && !target.mac && target.port === null)) {
    return src;
  }
  const tgt = formatEndpoint(target);
  return `${src} → ${tgt}`;
}

/**
 * Convert UTC ISO-8601 string to local time string (HH:MM:SS).
 * Falls back gracefully if invalid.
 */
export function formatLocalTime(isoString) {
  if (!isoString) return "--:--:--";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return String(isoString);
    return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return String(isoString);
  }
}

/**
 * Format country representation for an alert.
 * Returns country code (e.g. "US"), "Local" for inside alerts, or "Unknown".
 */
export function formatCountry(country, zone) {
  if (country) {
    return country.trim().toUpperCase();
  }
  if (zone === "inside") {
    return "Local";
  }
  return "Unknown";
}

