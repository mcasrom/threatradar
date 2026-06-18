import "dotenv/config";
import express from "express";
import http from "http";
import path from "path";
import fs from "fs";
import { WebSocket, WebSocketServer } from "ws";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

if (!process.env.GEMINI_API_KEY) {
  console.warn("GEMINI_API_KEY not configured");
}

const PORT = Number(process.env.PORT) || 3015;
const app = express();
app.use(express.json());

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

// Simple in-memory cache for IP scanned results
interface CacheEntry {
  data: any;
  timestamp: number;
}
const ipScanCache = new Map<string, CacheEntry>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes cache

const clients = new Set<WebSocket>();

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
    lat: loc.lat + (Math.random() - 0.5) * 1.5,
    lon: loc.lon + (Math.random() - 0.5) * 1.5,
    type,
    method,
    path,
    userAgent,
    threatScore: threatInfo.score,
    tags: threatInfo.tags,
  };

  trafficHistory.push(event);
  if (trafficHistory.length > MAX_HISTORY) {
    trafficHistory.shift();
  }

  const payload = JSON.stringify({ eventType: "traffic_event", event });
  for (const client of clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }

  const nextDelay = type === "malicious" ? Math.random() * 1500 + 400 : Math.random() * 1200 + 400;
  setTimeout(generateTraffic, nextDelay);
}

wss.on("connection", (ws) => {
  clients.add(ws);
  console.log(`[WebSocket] Client connected. Total active clients: ${clients.size}`);

  ws.send(JSON.stringify({ eventType: "initial_sync", history: trafficHistory }));

  ws.on("close", () => {
    clients.delete(ws);
    console.log(`[WebSocket] Client disconnected. Total active clients: ${clients.size}`);
  });

  ws.on("error", (err) => {
    console.error("[WebSocket] Error detected:", err);
  });
});

setTimeout(generateTraffic, 1000);

// ===== STATIC PLATFORM ROUTES =====

app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send(`User-agent: *
Disallow: /api/
Sitemap: https://threadradar.viajeinteligencia.com/sitemap.xml`);
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://threadradar.viajeinteligencia.com</loc>
  </url>
</urlset>`);
});

// ===== REST API ENDPOINTS =====

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ThreatRadar OSINT",
    time: new Date().toISOString()
  });
});

app.post("/api/test", (req, res) => {
  res.json({ received: req.body || null });
});

// ===== WEEKLY JOB =====
import { startWeeklyReportsJob } from "./src/jobs/weeklyReportsJob";
startWeeklyReportsJob();

// ===== VITE & PRODUCTION FILE SERVING ENVIRONMENT (CRITICAL FIX) =====

async function startAppServer() {
  if (process.env.NODE_ENV !== "production") {
    console.log("[Setup] Launching Vite development server environment...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    
    // El middleware de Vite maneja los assets y scripts dinámicos en desarrollo
    app.use(vite.middlewares);
    
    // Capturador comodín para desarrollo: Transforma e inyecta el index.html raíz
    app.get("*", async (req, res, next) => {
      const url = req.originalUrl;
      try {
        let template = fs.readFileSync(path.resolve(".", "index.html"), "utf-8");
        template = await vite.transformIndexHtml(url, template);
        res.status(200).set({ "Content-Type": "text/html" }).end(template);
      } catch (e) {
        vite.ssrFixStacktrace(e as Error);
        next(e);
      }
    });
  } else {
    console.log("[Setup] Production mode active. Serving static compiled resources...");
    // Sirve la carpeta dist compilada de forma estática en Hetzner
    app.use(express.static(path.resolve(".", "dist")));
    
    app.get("*", (req, res) => {
      res.sendFile(path.resolve(".", "dist", "index.html"));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`ThreatRadar OSINT running on port ${PORT}`);
  });
}

startAppServer();
