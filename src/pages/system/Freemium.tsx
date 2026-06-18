export default function Freemium() {
  return (
    <div className="text-zinc-200 p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-4">Freemium Model</h1>

      <ul className="list-disc ml-6">
        <li>Free: limited scans per day</li>
        <li>Premium: unlimited scans + email reports</li>
        <li>Pro: monitoring + alerts + historical tracking</li>
      </ul>
    </div>
  );
}
