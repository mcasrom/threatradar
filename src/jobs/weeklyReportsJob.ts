import cron from "node-cron";
import { summarizeThreat } from "../services/ai/summarizeThreat";
import { sendWeeklyReport } from "../services/email/sendWeeklyReport";

const users = [
  { email: "test@demo.com", plan: "premium", assets: ["8.8.8.8"] }
];

function mockScan(ip) {
  return {
    ip,
    riskScore: Math.floor(Math.random() * 100),
    findings: [
      { title: "Open port", severity: "medium" },
      { title: "Leak indicator", severity: "high" }
    ]
  };
}

export function startWeeklyReportsJob() {
  cron.schedule("0 8 * * 1", async () => {
    console.log("[CRON] running");

    for (const user of users) {
      if (user.plan !== "premium") continue;

      const scans = user.assets.map(mockScan);
      const aiSummary = await summarizeThreat(scans);

      const avg = scans.reduce((a,b)=>a+b.riskScore,0)/scans.length;

      await sendWeeklyReport(user.email, {
        riskScore: Math.round(avg),
        findings: scans.flatMap(s => s.findings),
        aiSummary
      });
    }
  });
}
