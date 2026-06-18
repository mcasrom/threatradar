import React from "react";
import { RadarScores } from "../types";

interface RadarChartProps {
  scores: RadarScores;
}

export default function RadarChart({ scores }: RadarChartProps) {
  const axes = [
    { key: "vulnerabilities", label: "Vulnerability CVEs" },
    { key: "configuration", label: "Config Exposure" },
    { key: "surface", label: "Service Surface" },
    { key: "reputation", label: "Net Reputation" },
    { key: "crypto", label: "Crypto Strength" },
  ];

  const size = 320;
  const radius = 100;
  const cx = size / 2;
  const cy = size / 2;

  // Compute pentagon coordinates for standard 5 axes from central angular displacements
  const getAngle = (index: number) => {
    return (index * 2 * Math.PI) / 5 - Math.PI / 2;
  };

  // Convert (value, axisIndex) into (x, y) coordinate
  const getCoordinates = (value: number, index: number) => {
    const angle = getAngle(index);
    const distance = (value / 100) * radius;
    const x = cx + distance * Math.cos(angle);
    const y = cy + distance * Math.sin(angle);
    return { x, y };
  };

  // Build grid pentagons for background reference (20%, 40%, 60%, 80%, 100%)
  const gridLevels = [20, 40, 60, 80, 100];
  const gridPaths = gridLevels.map((level) => {
    const points = axes.map((_, index) => {
      const { x, y } = getCoordinates(level, index);
      return `${x},${y}`;
    });
    return points.join(" ") + " " + points[0]; // closed loops
  });

  // Calculate polygon nodes for actual values
  const dataPoints = axes.map((axis, index) => {
    const scoreVal = scores[axis.key as keyof RadarScores] || 0;
    return getCoordinates(scoreVal, index);
  });
  const valuePath = dataPoints.map((p) => `${p.x},${p.y}`).join(" ") + " " + `${dataPoints[0].x},${dataPoints[0].y}`;

  // Find label anchors with slight padding offset to stay visible in SVG container viewport
  const getLabelAnchor = (index: number) => {
    const angle = getAngle(index);
    const labelRadius = radius + 22;
    const x = cx + labelRadius * Math.cos(angle);
    const y = cy + labelRadius * Math.sin(angle);

    let textAnchor = "middle";
    if (Math.cos(angle) > 0.2) textAnchor = "start";
    else if (Math.cos(angle) < -0.2) textAnchor = "end";

    let alignmentBaseline = "middle";
    if (Math.sin(angle) > 0.5) alignmentBaseline = "hanging";
    else if (Math.sin(angle) < -0.5) alignmentBaseline = "baseline";

    return { x, y, textAnchor, alignmentBaseline };
  };

  return (
    <div className="flex flex-col items-center justify-center p-2 bg-black/30 rounded-lg border border-[#27272A]/80">
      <div className="w-full text-center mb-1">
        <h4 className="font-display font-medium text-xs tracking-wider text-slate-400 font-semibold uppercase">VULNERABILITY VECTOR SURFACE</h4>
      </div>

      <div className="relative w-full max-w-[340px] aspect-square">
        <svg viewBox={`0 0 ${size} ${size}`} className="w-full h-full">
          <defs>
            <radialGradient id="radar-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
            </radialGradient>
            <linearGradient id="area-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f87171" stopOpacity="0.65" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.3" />
            </linearGradient>
          </defs>

          {/* Reference Radial Sweeps / Axis Connector lines */}
          {axes.map((_, index) => {
            const pathEnd = getCoordinates(100, index);
            return (
              <line
                key={`axis-line-${index}`}
                x1={cx}
                y1={cy}
                x2={pathEnd.x}
                y2={pathEnd.y}
                className="stroke-slate-800 stroke-1 stroke-dasharray-[1,4]"
                strokeDasharray="2,3"
              />
            );
          })}

          {/* Concentric grid rings representing intervals */}
          {gridPaths.map((points, levelIndex) => (
            <polygon
              key={`grid-level-${levelIndex}`}
              points={points}
              className="fill-none stroke-slate-800/60 stroke-1"
            />
          ))}

          {/* Subtle percentage grid label lines */}
          {gridLevels.map((lvl, idx) => {
            const textCoord = getCoordinates(lvl, 0); // Along the vertical top axis for clean readouts
            return (
              <text
                key={`grid-label-${idx}`}
                x={textCoord.x + 4}
                y={textCoord.y + 10}
                className="fill-slate-600 font-mono text-[8px] select-none"
              >
                {lvl}%
              </text>
            );
          })}

          {/* Area polygon plot representing security risk (Red glow gradient) */}
          <polygon
            points={valuePath}
            fill="url(#area-gradient)"
            className="stroke-rose-500 stroke-2 outline-none"
            strokeLinejoin="round"
          />

          {/* Glowing central indicator dot */}
          <circle cx={cx} cy={cy} r="2" className="fill-slate-500" />

          {/* Vertex core nodes and data score readouts */}
          {dataPoints.map((pt, idx) => {
            const rawVal = scores[axes[idx].key as keyof RadarScores] || 0;
            return (
              <g key={`data-node-${idx}`}>
                <circle
                  cx={pt.x}
                  cy={pt.y}
                  r="4"
                  className="fill-rose-400 stroke-slate-950 stroke-1.5 hover:scale-150 transition-all cursor-help"
                />
                <text
                  x={pt.x}
                  y={pt.y - 8}
                  className="fill-rose-400 font-mono text-[10px] font-bold text-center"
                  textAnchor="middle"
                >
                  {rawVal}
                </text>
              </g>
            );
          })}

          {/* Axis Labels positioning */}
          {axes.map((axis, index) => {
            const anchor = getLabelAnchor(index);
            const val = scores[axis.key as keyof RadarScores] || 0;
            return (
              <g key={`axis-label-${index}`}>
                <text
                  x={anchor.x}
                  y={anchor.y}
                  textAnchor={anchor.textAnchor}
                  dominantBaseline={anchor.alignmentBaseline}
                  className="fill-slate-300 font-sans text-[10px] font-medium tracking-tight"
                >
                  {axis.label}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Tactical Risk Score Center Summary Callout */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
          <div className="text-[10px] uppercase font-mono font-bold tracking-widest text-slate-500 text-center">AVERAGE</div>
          <div className="text-xl font-display font-bold text-slate-100 text-center">
            {Math.round(
              Object.values(scores).reduce((a, b) => a + b, 0) / Object.values(scores).length
            )}%
          </div>
          <div className="text-[9px] font-mono text-emerald-400 font-medium">RISK SCORE</div>
        </div>
      </div>
    </div>
  );
}
