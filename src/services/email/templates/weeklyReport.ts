export function weeklyReportTemplate(data) {
  return `
  <h1>ThreatRadar Report</h1>
  <p>Risk Score: ${data.riskScore}</p>

  <h2>Findings</h2>
  <ul>
    ${data.findings.map(f => `<li>${f.title} - ${f.severity}</li>`).join("")}
  </ul>

  <h2>AI Summary</h2>
  <p>${data.aiSummary}</p>
  `;
}
