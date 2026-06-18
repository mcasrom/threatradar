export default function Methodology() {
  return (
    <div className="text-zinc-200 p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-4">OSINT Methodology</h1>

      <p>
        ThreatRadar aggregates passive signals, metadata leaks, and public exposure indicators.
      </p>

      <h2 className="mt-6 text-xl">Data Sources</h2>
      <ul className="list-disc ml-6">
        <li>Network exposure indicators</li>
        <li>Public leak databases (when available)</li>
        <li>AI-generated correlation analysis</li>
      </ul>

      <h2 className="mt-6 text-xl">Scoring Model</h2>
      <p>
        Risk score is computed using weighted indicators: exposure severity, frequency, and confidence level.
      </p>
    </div>
  );
}
