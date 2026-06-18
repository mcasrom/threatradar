import React, { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { TrafficEvent } from "../types";

interface ThreatMapProps {
  events: TrafficEvent[];
  onSelectEvent?: (event: TrafficEvent) => void;
}

export default function ThreatMap({ events, onSelectEvent }: ThreatMapProps) {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<L.Map | null>(null);
  const markersRef = useRef<{ [key: string]: L.CircleMarker }>({});

  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Standard fallback marker configuration adjustment for Leaflet default assets
    delete (L.Icon.Default.prototype as any)._getIconUrl;
    L.Icon.Default.mergeOptions({
      iconRetinaUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png",
      iconUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png",
      shadowUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png",
    });

    // Initialize map using Cartwright dark aesthetics (CartoDB Dark Matter tile server)
    try {
      const map = L.map(mapContainerRef.current, {
        zoomControl: true,
        fadeAnimation: true,
        zoomAnimation: true,
      }).setView([20, 0], 2);

      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: "abcd",
        maxZoom: 20,
      }).addTo(map);

      mapRef.current = map;
    } catch (e) {
      console.error("Leaflet initialization failed: ", e);
    }

    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, []);

  // Update map markers when the live events stream changes
  useEffect(() => {
    const map = mapRef.current;
    if (!map) return;

    // Clear old elements and only draw current active events
    const currentEventIds = new Set(events.map((e) => e.id));

    // Remove obsolete markers
    Object.keys(markersRef.current).forEach((id) => {
      if (!currentEventIds.has(id)) {
        markersRef.current[id].remove();
        delete markersRef.current[id];
      }
    });

    // Plot and center live events sequentially
    events.forEach((event) => {
      if (markersRef.current[event.id]) {
        // Already exists, skip plotting but update popup content dynamically
        return;
      }

      // Color mapping following threat rating parameters
      let color = "#10b981"; // Safe / Human - Green
      if (event.type === "malicious") {
        color = "#ef4444"; // Threat / Malicious - Red
      } else if (event.type === "good_bot") {
        color = "#94a3b8"; // Good Bot - Slate Gray
      }

      const marker = L.circleMarker([event.lat, event.lon], {
        radius: event.type === "malicious" ? 10 : 7,
        fillColor: color,
        color: "#ffffff",
        weight: 1.5,
        opacity: 0.8,
        fillOpacity: 0.6,
      });

      // Construct a highly polished tactical popup template
      const popupContent = `
        <div style="font-family: 'Inter', sans-serif; background: #0f172a; color: #f8fafc; padding: 4px; font-size: 11px;">
          <div style="font-family: 'Space Grotesk', sans-serif; font-weight: 600; font-size: 12px; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
            <span style="width: 8px; height: 8px; border-radius: 50%; background-color: ${color}; display: inline-block;"></span>
            ${event.ip}
          </div>
          <div style="color: #94a3b8; font-family: 'JetBrains Mono', monospace; font-size: 10px; margin-bottom: 6px;">
            GEO: ${event.city ? event.city + ", " : ""}${event.country} (${event.countryCode})
          </div>
          <div style="margin-bottom: 4px;">
            <strong style="color: #38bdf8;">METHOD:</strong> <span style="font-family: monospace;">${event.method}</span>
          </div>
          <div style="margin-bottom: 4px; word-break: break-all;">
            <strong style="color: #38bdf8;">TARGET:</strong> <span style="font-family: monospace;">${event.path}</span>
          </div>
          <div style="margin-top: 6px; border-top: 1px solid #1e293b; padding-top: 4px; font-size: 10px; color: #94a3b8;">
            Threat Score: <strong style="color: ${event.type === "malicious" ? "#f87171" : "#34d399"}">${event.threatScore}%</strong>
          </div>
        </div>
      `;

      marker.bindPopup(popupContent, {
        className: "custom-leaflet-popup",
        maxWidth: 240,
      });

      // Bind click triggers for detailed side panel profiling
      if (onSelectEvent) {
        marker.on("click", () => {
          onSelectEvent(event);
        });
      }

      marker.addTo(map);
      markersRef.current[event.id] = marker;
    });

    // Autocenter views on the newest critical threat incident
    const criticalEvents = events.filter((e) => e.type === "malicious");
    if (criticalEvents.length > 0) {
      const latestCritical = criticalEvents[criticalEvents.length - 1];
      map.setView([latestCritical.lat, latestCritical.lon], map.getZoom());
    }
  }, [events, onSelectEvent]);

  return (
    <div className="relative w-full rounded-xl overflow-hidden border border-[#27272A] bg-[#111114] h-[400px]">
      <div className="absolute top-3 left-3 z-[999] flex flex-col gap-2">
        <div className="rounded bg-black/80 py-1.5 px-2.5 backdrop-blur-md border border-[#27272A] text-[9px] font-mono">
          <div className="font-bold text-white tracking-widest mb-1.5 uppercase">INTELLIGENCE KEY</div>
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>HUMAN VISITORS</span>
            </div>
            <div className="flex items-center gap-1.5 text-zinc-400">
              <span className="h-1.5 w-1.5 rounded-full bg-zinc-400"></span>
              <span>GOOD SEOS / BOTS</span>
            </div>
            <div className="flex items-center gap-1.5 text-rose-400">
              <span className="h-1.5 w-1.5 bg-rose-500 animate-pulse"></span>
              <span>MALICIOUS ATTENTION</span>
            </div>
          </div>
        </div>
      </div>
      <div id="threat-map" ref={mapContainerRef} className="custom-leaflet-container" style={{ height: "100%" }} />
    </div>
  );
}
