import express from "express";
import http from "http";
import path from "path";
import { WebSocket, WebSocketServer } from "ws";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const PORT = 3000;
const app = express();
app.use(express.json());

// Initialize Google GenAI on the server side
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Simple in-memory cache for IP scanned results to avoid redundant API queries
interface CacheEntry {
  data: any;
  timestamp: number;
}
const ipScanCache = new Map<string, CacheEntry>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes cache

// WebSocket client connections representation
const clients = new Set<WebSocket>();

// Ring buffer of last 50 traffic events to display in client charts on connect
interface TrafficEvent {
  id: string;
  timestamp: string;
  ip: string;
  country: string;
  countryCode: string;
  lat: number;
  lon: number;
  type: "human" | "good_bot" | "malicious";
  method: string;
  path: string;
  userAgent: string;
  threatScore: number;
  tags: string[];
}
const trafficHistory: TrafficEvent[] = [];
const MAX_HISTORY = 50;

// Geographic anchor points for traffic event simulator (representative IP-like data and regions)
const locations = [
  { country: "United States", code: "US", city: "San Francisco", lat: 37.7749, lon: -122.4194 },
  { country: "United States", code: "US", city: "New York", lat: 40.7128, lon: -74.0060 },
  { country: "Germany", code: "DE", city: "Frankfurt", lat: 50.1109, lon: 8.6821 },
  { country: "Brazil", code: "BR", city: "São Paulo", lat: -23.5505, lon: -46.6333 },
  { country: "China", code: "CN", city: "Shanghai", lat: 31.2304, lon: 121.4737 },
  { country: "Japan", code: "JP", city: "Tokyo", lat: 35.6762, lon: 139.6503 },
  { country: "Russia", code: "RU", city: "Moscow", lat: 55.7558, lon: 37.6173 },
  { country: "Netherlands", code: "NL", city: "Amsterdam", lat: 52.3676, lon: 4.9041 },
  { country: "Australia", code: "AU", city: "Sydney", lat: -33.8688, lon: 151.2093 },
  { country: "Singapore", code: "SG", city: "Singapore", lat: 1.3521, lon: 103.8198 },
  { country: "India", code: "IN", city: "Bangalore", lat: 12.9716, lon: 77.5946 },
  { country: "Ukraine", code: "UA", city: "Kyiv", lat: 50.4501, lon: 30.5234 },
];

const paths = {
  human: ["/index.html", "/api/v1/user/profile", "/assets/hero.png", "/blog/posts/cyber-hygiene", "/products/threatradar", "/api/v1/notifications"],
  good_bot: ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/feed.xml"],
  malicious: ["ssh://port-22/bruteforce", "c2://heartbeat/mirai", "ssh://auth/root", "/wp-login.php", "/.env", "/cgi-bin/php-cgi", "/.git/config", "/phpmyadmin/index.php", "/ws/terminal"],
};

const userAgents = {
  human: [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  ],
  good_bot: [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
    "AhrefsBot/7.0; (+http://ahrefs.com/robot/)",
  ],
  malicious: [
    "Hydra SSH Bruteforcer / SSH-2.0-Go",
    "Mirai Botnet Zombie Client/v2.1",
    "Nmap Scripting Engine; http://nmap.org/book/nse.html",
    "Go-http-client/1.1 (Security scanner test)",
    "Mozilla/5.0 (compatible; Masscan; http://github.com/robertdavidgraham/masscan)",
  ],
};

const threatDetails = {
  malicious: [
    { score: 95, tags: ["SSH Brute-Force", "Creds Stuffing"], comment: "Bulk authorization attempts detected targeting system SSH service on port 22." },
    { score: 98, tags: ["Mirai Botnet C2", "DDoS Zombie"], comment: "Outbound agent beacon targeting active Botnet command and control node." },
    { score: 90, tags: ["Cobalt Strike Beacon", "RCE Payload"], comment: "Beaconing pattern matching standard Cobalt Strike intrusion framework." },
    { score: 85, tags: ["SQL Injection Probe", "Brute Force Attack"], comment: "Exploitation attempt of authorization paths" },
    { score: 95, tags: ["CVE-2021-44228 Exploit Attempt", "RCE Shellshock Probe"], comment: "Zero-day payload inject signature matched" },
    { score: 80, tags: ["Dot-Env Inspection", "Credential Exhaustion Scan"], comment: "Crawler scanning root folders for leak files" },
    { score: 70, tags: ["Directory Traversal Probe"], comment: "Heuristic scan targeting /etc/passwd path traversal" },
  ],
  good_bot: [
    { score: 0, tags: ["Search Engine Indexer"], comment: "SEO Indexing session validation" },
    { score: 0, tags: ["SEO Sitemap Audit"], comment: "Robot checking page hierarchies" },
    { score: 0, tags: ["Link Checker Crawler"], comment: "Automatic verification of anchor tags" },
  ],
  human: [
    { score: 2, tags: ["Valid Session Request"], comment: "Normal telemetry navigation" },
    { score: 0, tags: ["Static Resource Fetch"], comment: "Normal static asset load" },
    { score: 5, tags: ["API Session Update"], comment: "Normal background state synchronizer" },
  ],
};

// Start generation of dynamic traffic mock data to broadcast
function generateTraffic() {
  const loc = locations[Math.floor(Math.random() * locations.length)];
  const roll = Math.random();
  let type: "human" | "good_bot" | "malicious" = "human";
  if (roll < 0.3) {
    type = "malicious";
  } else if (roll < 0.45) {
    type = "good_bot";
  }

  const selectedPaths = paths[type];
  const selectedUAs = userAgents[type];
  const threatInfoPool = threatDetails[type];

  const path = selectedPaths[Math.floor(Math.random() * selectedPaths.length)];
  const userAgent = selectedUAs[Math.floor(Math.random() * selectedUAs.length)];
  const threatInfo = threatInfoPool[Math.floor(Math.random() * threatInfoPool.length)];

  // Generate an IP
  let ip = "";
  if (type === "malicious") {
    ip = `${185 + Math.floor(Math.random() * 50)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`;
  } else if (type === "good_bot") {
    ip = `66.249.${Math.floor(Math.random() * 32 + 64)}.${Math.floor(Math.random() * 254 + 1)}`;
  } else {
    ip = `${73 + Math.floor(Math.random() * 110)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254 + 1)}`;
  }

  const methods = ["GET", "POST", "HEAD"];
  const method = methods[type === "malicious" && Math.random() > 0.5 ? 1 : 0];

  const now = new Date();
  const timestamp = now.toLocaleTimeString("en-US", { hour12: false });

  const event: TrafficEvent = {
    id: `ev_${Math.random().toString(36).substr(2, 9)}`,
    timestamp,
    ip,
    country: loc.country,
    countryCode: loc.code,
    lat: loc.lat + (Math.random() - 0.5) * 1.5, // slightly jitter coordinates around the hubs so they appear spread out nicely on mapping
    lon: loc.lon + (Math.random() - 0.5) * 1.5,
    type,
    method,
    path,
    userAgent,
    threatScore: threatInfo.score,
    tags: threatInfo.tags,
  };

  // Enqueue in history ring buffer
  trafficHistory.push(event);
  if (trafficHistory.length > MAX_HISTORY) {
    trafficHistory.shift();
  }

  // Broadcast to all active websocket clients
  const payload = JSON.stringify({ eventType: "traffic_event", event });
  for (const client of clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }

  // Schedule next event at adaptive randomized intervals
  const nextDelay = type === "malicious" ? Math.random() * 1500 + 400 : Math.random() * 1200 + 400;
  setTimeout(generateTraffic, nextDelay);
}

// Websocket logic
wss.on("connection", (ws) => {
  clients.add(ws);
  console.log(`[WebSocket] Client connected. Total active clients: ${clients.size}`);

  // Push full existing traffic history stream so charts load with historical entries instantly
  ws.send(JSON.stringify({ eventType: "initial_sync", history: trafficHistory }));

  ws.on("close", () => {
    clients.delete(ws);
    console.log(`[WebSocket] Client disconnected. Total active clients: ${clients.size}`);
  });

  ws.on("error", (err) => {
    console.error("[WebSocket] Error detected:", err);
  });
});

// Trigger the traffic simulator loop
setTimeout(generateTraffic, 1000);

// API Endpoints
app.get("/api/health", (req, res) => {
  res.json({ status: "online", clients: clients.size, cacheSize: ipScanCache.size });
});

// Search Engine Optimization (SEO) dynamic endpoints
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send(`User-agent: *
Allow: /
Disallow: /api/

Sitemap: https://threadradar.viajeinteligencia.com/sitemap.xml`);
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://threadradar.viajeinteligencia.com/</loc>
    <lastmod>2026-06-17</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`);
});

// AI-Generated Bespoke Premium Security Report
app.post("/api/premium-report", async (req, res) => {
  try {
    const { orgName, infrastructure } = req.body;
    if (!orgName || typeof orgName !== "string") {
      return res.status(400).json({ error: "Organization Name is required to generate a premium customized report." });
    }

    const cleanOrg = orgName.trim();
    const cleanInfra = (infrastructure || "General Linux & Cloud Servers").trim();

    console.log(`[Bespoke Report Generator] Invoking server-side Gemini to generate custom threat assessment for ${cleanOrg}`);

    const prompt = `Act as an expert Chief Information Security Officer (CISO) and threat intelligence strategist.
Produce an extremely detailed, highly professional, bespoke corporate security advisory and custom threat assessment report for the following target organization:
- Organization Name: ${cleanOrg}
- Stated Infrastructure Profile: ${cleanInfra}
- System Date: 2026-06-17

Your report must cover:
1. EXECUTIVE EXPOSURE SUMMARY: High-level risk evaluation tailored specifically to ${cleanOrg}'s infrastructure.
2. TAILORED ATTACK VECTORS: How an advanced persistent threat (APT) actor might target ${cleanOrg}'s system stack.
3. CONCRETE RECOMMENDED RECON (OSINT): Specific reconnaissance tools and audit queries (e.g., Shodan/LeakIX queries) relevant to their stated infrastructure.
4. THREAT SCENE FORECAST 2026: Modern threats (like AI-assisted credential stuffing, botnet proxies, API key leakage) they must prepare for.
5. STRATEGIC REMEDIATION & ACTION PLAN: A 3-step prioritized security hardening workflow.

Make the output feel organic, technical, authoritative and highly comprehensive. Use beautiful ASCII text headers and a formal professional advisory tone. Provide readable bullet points. Do not include random JSON brackets or formatting wrappers, just output the beautiful report text in Spanish or English depending on context.`;

    const modelName = "gemini-3.5-flash";
    const response = await ai.models.generateContent({
      model: modelName,
      contents: prompt,
    });

    const reportText = response.text;
    if (!reportText) {
      throw new Error("No response payload returned from the report generator engine.");
    }

    return res.json({ success: true, orgName: cleanOrg, report: reportText });
  } catch (error: any) {
    console.error("[Premium Report Generation Error]", error);
    return res.status(500).json({
      error: "Failed to generate premium customized security report.",
      details: error.message,
    });
  }
});

// Clear scanning cache endpoint (respecting sovereign cleanup requirements)
app.post("/api/scan/clear-cache", (req, res) => {
  ipScanCache.clear();
  res.json({ success: true, message: "扫描缓存清除成功 File-cache evicted completely." });
});

// Deep OSINT Target analysis endpoint using server-side Gemini API
app.post("/api/scan", async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip || typeof ip !== "string") {
      return res.status(400).json({ error: "An IP address or hostname is strictly required." });
    }

    const cleanIp = ip.trim();

    // Check Sovereign caching first (dictionary in memory to avoid repetitive external API quotas)
    const cachedEntry = ipScanCache.get(cleanIp);
    if (cachedEntry && Date.now() - cachedEntry.timestamp < CACHE_TTL) {
      console.log(`[OSINT Cache-Hit] Serving cached vulnerability profile for target: ${cleanIp}`);
      return res.json({ ...cachedEntry.data, cached: true });
    }

    console.log(`[OSINT Cache-Miss] Initiating AI-enriched Shodan & LeakIX database profile for target: ${cleanIp}`);

    // Trigger AI response generation matching standard schema
    const prompt = `Act as an advanced cybersecurity OSINT analyst representing Shodan and LeakIX data sources.
Analyze the target IP address or hostname: "${cleanIp}"

Provide a realistic security evaluation of this endpoint across 5 threat indicators/scores (0 to 100, where 100 represents severe critical threat risk, and 0 is safe). Identify any active malicious Botnets, botnet command & control (C2) heartbeat beaconeering, SSH password brute force dictionary attacks, and SSH credential stuffing:
1. 'vulnerabilities' (Known CVE software vulnerabilities)
2. 'configuration' (Configuration gaps like exposed .git, unprotected config files, leaked creds)
3. 'surface' (Surface service area size, number of active public ports, dangerous management protocols)
4. 'reputation' (Reputation feedback matching spam logs, brute force sensors, or malware vectors)
5. 'crypto' (Cryptographic protocol status: weak SSL standard versions, missing HTTP security keys, expired certs)

You must also formulate:
- ISP & Organization ASN metadata
- Primary GeoIP details (City, Country, and approximate coordinates: Latitude, Longitude)
- Active Port lists (usually 1 to 4 depending on scan depth)
- High-priority leak records resembling LeakIX logs
- High-priority CVEs resembling Shodan lists
- Actionable administrator recommendation (2 sentences)

Return your profile strictly in JSON format. Do not use markdown backticks or any introductory words. Just return raw JSON.
The structure must EXACTLY fit this JSON layout:
{
  "target": "${cleanIp}",
  "threatLevel": "Low" | "Medium" | "High" | "Critical",
  "org": "The ASN organization list",
  "isp": "The network service provider",
  "country": "Target country",
  "city": "Target city",
  "latitude": 37.7749,
  "longitude": -122.4194,
  "summary": "Administrative remediation recommendation...",
  "radarScores": {
    "vulnerabilities": 55,
    "configuration": 70,
    "surface": 40,
    "reputation": 20,
    "crypto": 30
  },
  "openPorts": [
    {"port": 80, "service": "http", "banner": "Apache/2.4.41"},
    {"port": 22, "service": "ssh", "banner": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"}
  ],
  "leaks": [
    {"title": "Open Directory Indexing", "severity": "medium", "description": "Index directory listing of core assets detected on port 80."},
    {"title": ".ENV exposure", "severity": "critical", "description": "LeakIX database found critical API environment keys exposed directly."}
  ],
  "vulnerabilities": [
    {"cve": "CVE-2021-41773", "severity": "high", "description": "Apache Path Traversal and File Disclosure vulnerability."}
  ]
}`;

    const modelName = "gemini-3.5-flash";
    const response = await ai.models.generateContent({
      model: modelName,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
      },
    });

    const textOutput = response.text;
    if (!textOutput) {
      throw new Error("No payload returned from the AI OSINT engine.");
    }

    // Try parsing the output
    const parsedData = JSON.parse(textOutput.trim());

    // Update Sovereign cache before return
    ipScanCache.set(cleanIp, {
      data: parsedData,
      timestamp: Date.now(),
    });

    return res.json({ ...parsedData, cached: false });
  } catch (error: any) {
    console.error("[OSINT Analysis Error]", error);
    return res.status(500).json({
      error: "Failed to generate security profiling. Please clarify your input or try again.",
      details: error.message,
    });
  }
});

// Configure Vite integration for both SPA development and production bundles
async function startAppServer() {
  if (process.env.NODE_ENV !== "production") {
    console.log("[Setup] Initializing Vite Dev Middleware...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("[Setup] Injecting production build file handlers...");
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`=============================================================`);
    console.log(`📡 ThreatRadar OSINT is listening on http://0.0.0.0:${PORT}`);
    console.log(`=============================================================`);
  });
}

startAppServer();
