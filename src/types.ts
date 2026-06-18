export interface TrafficEvent {
  id: string;
  timestamp: string;
  ip: string;
  country: string;
  countryCode: string;
  city?: string;
  lat: number;
  lon: number;
  type: "human" | "good_bot" | "malicious";
  method: string;
  path: string;
  userAgent: string;
  threatScore: number;
  tags: string[];
}

export interface RadarScores {
  vulnerabilities: number;
  configuration: number;
  surface: number;
  reputation: number;
  crypto: number;
}

export interface OpenPort {
  port: number;
  service: string;
  banner: string;
}

export interface Leak {
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
}

export interface CVEInfo {
  cve: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

export interface ScanResult {
  target: string;
  threatLevel: "Low" | "Medium" | "High" | "Critical";
  org: string;
  isp: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  summary: string;
  radarScores: RadarScores;
  openPorts: OpenPort[];
  leaks: Leak[];
  vulnerabilities: CVEInfo[];
  cached?: boolean;
}
