import { resend } from "./resend";
import { weeklyReportTemplate } from "./templates/weeklyReport";

export async function sendWeeklyReport(to, data) {
  return resend.emails.send({
    from: "ThreatRadar <reports@local>",
    to,
    subject: "Weekly Report",
    html: weeklyReportTemplate(data),
  });
}
