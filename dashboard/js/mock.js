/**
 * Mock data generator for offline demos and ?mock=1 testing.
 * Produces real alert shapes with 32-char hex IDs, varied severities,
 * all 7 attacks across all 3 zones, and sample country codes.
 */

import { state } from "./state.js";

function makeHexId() {
  return "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".replace(/[x]/g, () =>
    ((Math.random() * 16) | 0).toString(16)
  );
}

function randItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

const COUNTRY_CODES = ["US", "CN", "RU", "DE", "NL", "SG", "GB", "FR", "IN", "BR", "JP", "CA", "UA", "AU"];

const MOCK_SCENARIOS = [
  // Zone 1: Inside
  {
    zone: "inside",
    attack: "arp_spoofing",
    severities: ["critical", "high"],
    create: (sev) => {
      const isGateway = sev === "critical";
      const fakeMac = `aa:bb:cc:00:00:${randInt(10, 99)}`;
      const targetMac = "aa:bb:cc:00:00:01";
      const spoofedIp = isGateway ? "192.168.1.1" : `192.168.1.${randInt(20, 50)}`;
      const attackerIp = `192.168.1.${randInt(60, 99)}`;
      const reason = isGateway
        ? `Device ${attackerIp} (${fakeMac}) is pretending to be your router ${spoofedIp}. Someone may be reading your traffic.`
        : `Device ${attackerIp} (${fakeMac}) is claiming to be ${spoofedIp}, which belongs to ${targetMac}. Traffic may be intercepted.`;
      return {
        reason,
        source: { ip: attackerIp, mac: fakeMac, port: null },
        target: { ip: spoofedIp, mac: targetMac, port: null },
        details: {
          spoofed_ip: spoofedIp,
          expected_mac: targetMac,
          seen_mac: fakeMac,
          arp_reply: true,
          is_gateway: isGateway,
        },
        country: null,
      };
    },
  },
  {
    zone: "inside",
    attack: "port_scan",
    severities: ["medium", "high"],
    create: (sev) => {
      const src = `192.168.1.${randInt(10, 80)}`;
      const dst = `192.168.1.${randInt(2, 25)}`;
      const portsCount = sev === "high" ? randInt(70, 150) : randInt(25, 50);
      return {
        reason: `Device ${src} probed ${portsCount} different ports on ${dst} in 10 seconds. It is looking for weak spots to attack.`,
        source: { ip: src, mac: `02:00:00:00:00:${randInt(10, 99)}`, port: null },
        target: { ip: dst, mac: null, port: null },
        details: {
          ports_probed: portsCount,
          window_seconds: 10,
          sample_ports: [21, 22, 23, 80, 443, 8080, 3389, 5432, 27017].slice(0, randInt(4, 9)),
        },
        country: null,
      };
    },
  },
  {
    zone: "inside",
    attack: "rogue_dhcp",
    severities: ["high", "critical"],
    create: (sev) => {
      const server = `192.168.1.${randInt(150, 200)}`;
      const mac = `52:54:00:${randInt(10, 99)}:${randInt(10, 99)}:${randInt(10, 99)}`;
      const offeredDns = server;
      return {
        reason: `Device ${server} is handing out network addresses, but it isn't your real DHCP server (192.168.1.1). It is telling devices to use DNS server ${offeredDns}.`,
        source: { ip: server, mac, port: 67 },
        target: null,
        details: {
          message: "offer",
          trusted_servers: ["192.168.1.1"],
          offered_router: server,
          offered_dns: offeredDns,
        },
        country: null,
      };
    },
  },
  // Zone 2: Inbound
  {
    zone: "inbound",
    attack: "ssh_brute_force",
    severities: ["high", "critical"],
    create: (sev) => {
      const country = randItem(COUNTRY_CODES);
      const ip = `203.0.113.${randInt(2, 250)}`;
      const attempts = sev === "critical" ? randInt(120, 300) : randInt(30, 80);
      return {
        reason: `Remote attacker ${ip} tried ${attempts} passwords on your server's SSH login in under one minute.`,
        source: { ip, mac: null, port: randInt(40000, 65000) },
        target: { ip: "198.51.100.10", mac: null, port: 22 },
        details: { attempts },
        country,
      };
    },
  },
  {
    zone: "inbound",
    attack: "sql_injection",
    severities: ["medium", "high"],
    create: (sev) => {
      const country = randItem(COUNTRY_CODES);
      const ip = `198.51.100.${randInt(100, 250)}`;
      const path = randItem(["/api/v1/users", "/login", "/search", "/portal/auth"]);
      return {
        reason: `A malicious HTTP request to ${path} contained SQL injection statements meant to trick the backend database.`,
        source: { ip, mac: null, port: randInt(35000, 60000) },
        target: { ip: "198.51.100.10", mac: null, port: 443 },
        details: { path },
        country,
      };
    },
  },
  // Zone 3: Outbound
  {
    zone: "outbound",
    attack: "beaconing",
    severities: ["medium", "high"],
    create: (sev) => {
      const country = randItem(COUNTRY_CODES);
      const infected = `192.168.1.${randInt(10, 45)}`;
      const dest = `203.0.113.${randInt(50, 150)}`;
      const interval = randItem([5, 10, 15, 30]);
      return {
        reason: `Workstation ${infected} contacts command-and-control server ${dest} every ${interval} seconds, like malware phoning home.`,
        source: { ip: infected, mac: null, port: randInt(49152, 65535) },
        target: { ip: dest, mac: null, port: 443 },
        details: { interval_seconds: interval },
        country,
      };
    },
  },
  {
    zone: "outbound",
    attack: "dns_tunneling",
    severities: ["high", "critical"],
    create: (sev) => {
      const country = randItem(COUNTRY_CODES);
      const infected = `192.168.1.${randInt(12, 35)}`;
      const destDns = `192.0.2.${randInt(20, 80)}`;
      const avgLen = randInt(48, 64);
      return {
        reason: `Internal device ${infected} is sending unusually long encoded DNS requests (avg ${avgLen} bytes), which can hide exfiltrated data.`,
        source: { ip: infected, mac: null, port: randInt(50000, 60000) },
        target: { ip: destDns, mac: null, port: 53 },
        details: { avg_label_length: avgLen },
        country,
      };
    },
  },
];

export function generateMockAlert(offsetSeconds = 0) {
  const scenario = randItem(MOCK_SCENARIOS);
  const severity = randItem(scenario.severities);
  const data = scenario.create(severity);
  const date = new Date(Date.now() - offsetSeconds * 1000);

  return {
    id: makeHexId(),
    zone: scenario.zone,
    attack: scenario.attack,
    severity,
    reason: data.reason,
    source: data.source,
    target: data.target,
    details: data.details,
    timestamp: date.toISOString(),
    sensor: "fake-sensor",
    country: data.country,
  };
}

let mockInterval = null;

export function startMockMode() {
  state.setMockMode(true);
  state.setConnectionStatus("LIVE");

  // Generate 30 historical alerts spread over the last 30 minutes
  const historicalAlerts = [];
  for (let i = 29; i >= 0; i--) {
    const offset = i * 60 + randInt(0, 45);
    historicalAlerts.push(generateMockAlert(offset));
  }
  state.addAlerts(historicalAlerts);

  // Generate a live alert every 2.5 seconds
  if (mockInterval) clearInterval(mockInterval);
  mockInterval = setInterval(() => {
    const alert = generateMockAlert(0);
    state.addAlert(alert, false);
  }, 2500);
}

export function stopMockMode() {
  if (mockInterval) {
    clearInterval(mockInterval);
    mockInterval = null;
  }
  state.setMockMode(false);
}
