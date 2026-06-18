import React, { useState } from "react";
import { ScanResult } from "../types";
import RadarChart from "./RadarChart";
import { Search, Shield, ShieldCheck, ShieldAlert, Cpu, Database, Network, Globe, ListFilter, Trash2, ArrowRight } from "lucide-react";

interface IpScannerProps {
  onScanComplete?: (result: ScanResult) => void;
}

const SAMPLE_IPS = [
  { ip: "8.8.8.8", desc: "Google public DNS (Safe Target)" },
  { ip: "185.190.140.42", desc: "Known Malicious Command Center" },
  { ip: "66.249.66.1", desc: "Googlebot Crawling Subnet" },
];

export default function IpScanner({ onScanComplete }: IpScannerProps) {
  const [targetIp, setTargetIp] = useState("");
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<"ports" | "leaks" | "vulnerabilities">("ports");

  // Multi-step loading logs simulation to enhance OSINT thematic fidelity
  const simulateLoadingLogs = async (ip: string) => {
    const logs = [
      `Establishing OSINT sandbox handshake for target: ${ip}...`,
      "Querying Shodan raw open port banners...",
      "Analyzing LeakIX security log signatures...",
      "Parsing active vulnerabilities in known CVE repositories...",
      "Enriching exposing surface assessment with Gemini-3.5-flash AI engine...",
      "Building spider radar profiles and finalizing administrative actions..."
    ];

    for (let i = 0; i < logs.length; i++) {
      setStatusMessage(logs[i]);
      await new Promise((resolve) => setTimeout(resolve, 600));
    }
  };

  const handleScan = async (ip: string) => {
    if (!ip.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    // Run parallel interactive logging
    const logPromise = simulateLoadingLogs(ip.trim());

    try {
      const fetchPromise = fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip.trim() }),
      });

      // Wait for both status animation logs AND network feedback
      const [_, response] = await Promise.all([logPromise, fetchPromise]);

      if (!response.ok) {
        throw new Error("Failed to scan the specified endpoint. Verify target context.");
      }

      const data: ScanResult = await response.json();
      setResult(data);
      if (onScanComplete) {
        onScanComplete(data);
      }
    } catch (err: any) {
      console.error(err);
      setError(err.message || "An unexpected error occurred during tactical OSINT scanning.");
    } finally {
      setLoading(false);
    }
  };

  const handleClearCache = async () => {
    try {
      const response = await fetch("/api/scan/clear-cache", { method: "POST" });
      if (response.ok) {
        alert("扫描缓存已完全清理 Cached vulnerability logs evicted successfully.");
      }
    } catch (err) {
      console.error("Failed to clear cache", err);
    }
  };

  const getThreatBadgeStyle = (level: string) => {
    switch (level) {
      case "Critical":
        return "bg-rose-950/80 text-rose-400 border-rose-500/50 animate-pulse";
      case "High":
        return "bg-amber-950/80 text-amber-400 border-amber-600/50";
      case "Medium":
        return "bg-yellow-950/80 text-yellow-500 border-yellow-600/30";
      default:
        return "bg-emerald-950/80 text-emerald-400 border-emerald-600/30";
    }
  };

  const getSeverityBadgeStyle = (level: string) => {
    switch (level) {
      case "critical":
      case "high":
        return "text-rose-400 bg-rose-950/50 border-rose-800/50";
      case "medium":
        return "text-yellow-400 bg-yellow-950/50 border-yellow-800/50";
      default:
        return "text-slate-400 bg-slate-900/50 border-slate-800/50";
    }
  };

  return (
    <div className="bg-[#111114] border border-[#27272A] rounded-xl p-5 transition-all">
      {/* Profiler Header section */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-4 border-b border-[#27272A] pb-4">
        <div>
          <h2 className="font-display font-medium text-xs font-bold text-white uppercase flex items-center gap-2 tracking-wider">
            <Cpu className="text-blue-500 h-4 w-4" />
            TARGET IP SECURITY ANALYSIS
          </h2>
          <p className="text-[10px] text-[#71717A] italic mt-0.5">
            Sourcing exposures and risk indicators from Shodan & LeakIX database APIs
          </p>
        </div>
        <button
          onClick={handleClearCache}
          className="flex items-center gap-1.5 px-2.5 py-1 text-[9px] font-mono hover:text-rose-400 text-[#71717A] bg-black/40 hover:bg-black/60 border border-[#27272A] hover:border-rose-950 rounded-md transition-all cursor-pointer"
          title="Clear search caches for fresh fetch entries"
        >
          <Trash2 className="h-3 w-3" />
          CLEAR CACHE
        </button>
      </div>

      {/* Target search bar form */}
      <div className="flex flex-col gap-2.5 mb-5">
        <div className="flex flex-col md:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-[#71717A]" />
            <input
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              placeholder="Enter IP target (e.g. 185.190.140.42)..."
              onKeyDown={(e) => e.key === "Enter" && handleScan(targetIp)}
              disabled={loading}
              className="w-full pl-9 pr-4 py-1.5 bg-black/40 border border-[#27272A] rounded-lg text-xs text-[#E4E4E7] placeholder-zinc-600 focus:outline-none focus:border-blue-500 disabled:opacity-60 transition-all font-mono"
            />
          </div>
          <button
            onClick={() => handleScan(targetIp)}
            disabled={loading || !targetIp.trim()}
            className="flex items-center justify-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-xs font-bold text-white rounded-lg disabled:opacity-50 transition-all cursor-pointer"
          >
            {loading ? "PROFILING..." : "SCAN TARGET"}
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Quick Sample pre-filled IP queries */}
        <div className="flex flex-wrap items-center gap-2 mt-0.5">
          <span className="text-[9px] font-mono font-bold uppercase text-[#71717A] tracking-wider">PRESETS:</span>
          {SAMPLE_IPS.map((preset) => (
            <button
              key={preset.ip}
              onClick={() => {
                setTargetIp(preset.ip);
                handleScan(preset.ip);
              }}
              disabled={loading}
              className="text-[10px] font-mono px-2 py-0.5 bg-black/30 hover:bg-black/60 text-zinc-400 hover:text-white rounded border border-[#27272A] cursor-pointer transition-all"
              title={preset.desc}
            >
              {preset.ip}
            </button>
          ))}
        </div>

        {/* PASSIVE EVALUATION & COMPLIANCE CLAUSE */}
        <div className="mt-2.5 flex items-start gap-2 p-2 bg-blue-950/10 border border-blue-900/15 rounded text-[8.5px] text-zinc-500 font-mono leading-relaxed">
          <ShieldAlert className="text-[#3B82F6] h-3.5 w-3.5 shrink-0 mt-0.5" />
          <div>
            <span className="text-zinc-400 font-bold uppercase tracking-wider block mb-0.5">PASSIVE OSINT EVALUATION COMPLIANCE:</span>
            Performing an IP security audit is strictly passive. The queried target IP is never subject to active penetration tests, automated load attacks, package exploits, or real-time vulnerability scans. All profile diagnostics are aggregated safely from historical, cached public threat feeds.
          </div>
        </div>
      </div>

      {/* Loading Terminal UI Overlay */}
      {loading && (
        <div className="flex flex-col items-center justify-center py-10 px-4 border border-dashed border-[#27272A] rounded-xl bg-black/20">
          <div className="relative mb-3">
            <div className="h-10 w-10 rounded-full border-2 border-zinc-900 border-t-blue-500 animate-spin"></div>
            <Cpu className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-blue-400 h-4 w-4 animate-pulse" />
          </div>
          <span className="text-[10px] uppercase font-mono font-bold tracking-widest text-[#22C55E] animate-pulse">Running Deep OSINT Profiler</span>
          <p className="text-[10px] font-mono text-[#71717A] mt-1.5 text-center max-w-xs h-7">
            {statusMessage}
          </p>
        </div>
      )}

      {/* Error callout block */}
      {error && (
        <div className="flex gap-2.5 p-3 bg-rose-950/20 border border-rose-900/40 rounded-xl text-rose-200 text-xs mt-2">
          <ShieldAlert className="h-4 w-4 text-rose-500 shrink-0 mt-0.5" />
          <div>
            <strong className="font-semibold block font-display text-[11px]">TARGET OSINT FAILURE</strong>
            <span className="font-mono text-[10px] text-[#71717A] block mt-0.5">{error}</span>
          </div>
        </div>
      )}

      {/* Scan Results Layout */}
      {result && !loading && (
        <div className="mt-4 flex flex-col md:flex-row gap-5 animate-fade-in text-[#E4E4E7]">
          {/* Left Summary and Radar Panel */}
          <div className="flex-1 max-w-full md:max-w-[280px] flex flex-col gap-3 font-mono">
            {/* Target Card with Live Metadata */}
            <div className={`p-3 rounded-lg border bg-black/40 border-[#27272A]`}>
              <div className="flex justify-between items-center gap-2 mb-2 pb-1.5 border-b border-[#27272A]/60">
                <div className="text-[11px] font-bold text-white flex items-center gap-1.5 truncate">
                  <Network className="h-3.5 w-3.5 text-blue-400" />
                  {result.target}
                </div>
                <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded border ${getThreatBadgeStyle(result.threatLevel)}`}>
                  {result.threatLevel}
                </span>
              </div>

              <div className="space-y-1.5 text-[10px] text-zinc-400">
                <div className="flex justify-between gap-1">
                  <span>ASN:</span>
                  <span className="text-white truncate max-w-[130px] text-right" title={result.org}>{result.org}</span>
                </div>
                <div className="flex justify-between gap-1">
                  <span>ISP:</span>
                  <span className="text-white truncate max-w-[130px] text-right" title={result.isp}>{result.isp}</span>
                </div>
                <div className="flex justify-between gap-1">
                  <span>Location:</span>
                  <span className="text-white max-w-[130px] truncate text-right">
                    {result.city}, {result.country}
                  </span>
                </div>
                {result.cached && (
                  <div className="pt-1 text-center text-[9px] text-[#F59E0B] italic">
                    ◆ FROM LOCAL MEMORY SHIELD
                  </div>
                )}
              </div>
            </div>

            {/* Radar Spider display block */}
            <RadarChart scores={result.radarScores} />

            {/* AI Summary and Action Advice Card */}
            <div className="p-3 bg-black/35 border border-[#27272A] rounded-lg">
              <h4 className="text-[9px] font-bold text-zinc-400 mb-1 flex items-center gap-1">
                <Database className="text-blue-500 h-3 w-3" />
                TACTICAL RECOMMENDATION
              </h4>
              <p className="text-[10px] text-zinc-300 font-sans leading-normal">
                {result.summary}
              </p>
            </div>
          </div>

          {/* Right Detailed Tabbed vulnerability pane lists */}
          <div className="flex-1 min-w-0 bg-black/20 border border-[#27272A] rounded-lg overflow-hidden flex flex-col">
            {/* Tab Navigation header */}
            <div className="flex border-b border-[#27272A] bg-black/40 p-0.5">
              <button
                onClick={() => setActiveTab("ports")}
                className={`flex-1 py-1.5 text-[10px] font-semibold rounded transition-all flex items-center justify-center gap-1 cursor-pointer ${
                  activeTab === "ports"
                    ? "bg-[#27272A] text-white"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                <Network className="h-3 w-3" />
                PORTS ({result.openPorts?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab("leaks")}
                className={`flex-1 py-1.5 text-[10px] font-semibold rounded transition-all flex items-center justify-center gap-1 cursor-pointer ${
                  activeTab === "leaks"
                    ? "bg-[#27272A] text-white"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                <ListFilter className="h-3 w-3" />
                EXPOSURES ({result.leaks?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab("vulnerabilities")}
                className={`flex-1 py-1.5 text-[10px] font-semibold rounded transition-all flex items-center justify-center gap-1 cursor-pointer ${
                  activeTab === "vulnerabilities"
                    ? "bg-[#27272A] text-white"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                <Shield className="h-3 w-3" />
                CVEs ({result.vulnerabilities?.length || 0})
              </button>
            </div>

            {/* Tab content viewer */}
            <div className="p-3 flex-1 overflow-y-auto max-h-[380px] font-mono text-[10px]">
              {activeTab === "ports" && (
                <div className="flex flex-col gap-2">
                  {(!result.openPorts || result.openPorts.length === 0) ? (
                    <div className="text-center py-8 text-[#71717A]">
                      No active public service ports mapped.
                    </div>
                  ) : (
                    result.openPorts.map((itm) => (
                      <div key={itm.port} className="flex gap-3 p-2 bg-black/40 border border-[#27272A]/60 rounded">
                        <div className="bg-blue-950/30 text-blue-400 font-bold h-8 w-10 text-[11px] rounded flex items-center justify-center border border-blue-900/35 shrink-0">
                          :{itm.port}
                        </div>
                        <div className="min-w-0 flex-1">
                          <span className="text-[8px] font-bold uppercase text-blue-400 block mb-0.5">SERVICE: {itm.service}</span>
                          <p className="text-[10px] text-zinc-300 break-all bg-[#151518] px-1.5 py-0.5 rounded border border-[#27272A]/40 line-clamp-2">
                            {itm.banner || "BANNER NOT REPORTED"}
                          </p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {activeTab === "leaks" && (
                <div className="flex flex-col gap-2">
                  {(!result.leaks || result.leaks.length === 0) ? (
                    <div className="text-center py-8 text-[#71717A] flex flex-col items-center gap-1">
                      <ShieldCheck className="text-[#22C55E] h-5 w-5" />
                      <span>LeakIX reported 0 public exposures or credentials.</span>
                    </div>
                  ) : (
                    result.leaks.map((leak, idx) => (
                      <div key={idx} className="p-2.5 bg-black/40 border border-[#27272A]/60 rounded flex flex-col gap-1">
                        <div className="flex justify-between items-center gap-2">
                          <strong className="text-xs text-white font-medium">{leak.title}</strong>
                          <span className={`text-[8px] font-bold uppercase px-1 py-0.5 rounded border ${getSeverityBadgeStyle(leak.severity)}`}>
                            {leak.severity}
                          </span>
                        </div>
                        <p className="text-[10px] text-zinc-400 font-sans leading-normal">
                          {leak.description}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              )}

              {activeTab === "vulnerabilities" && (
                <div className="flex flex-col gap-2">
                  {(!result.vulnerabilities || result.vulnerabilities.length === 0) ? (
                    <div className="text-center py-8 text-[#71717A] flex flex-col items-center gap-1">
                      <ShieldCheck className="text-[#22C55E] h-5 w-5" />
                      <span>Shodan database matched 0 critical CVE references.</span>
                    </div>
                  ) : (
                    result.vulnerabilities.map((vuln, idx) => (
                      <div key={idx} className="p-2.5 bg-black/40 border border-[#27272A]/60 rounded flex flex-col gap-1">
                        <div className="flex justify-between items-center gap-2">
                          <span className="text-xs font-bold text-red-400">{vuln.cve}</span>
                          <span className={`text-[8px] font-bold uppercase px-1 py-0.5 rounded border ${getSeverityBadgeStyle(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <p className="text-[10px] text-zinc-400 font-sans leading-normal">
                          {vuln.description}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
