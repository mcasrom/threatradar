import { resend } from "./resend";
import { weeklyReportTemplate } from "./templates/weeklyReport";

export async function sendWeeklyReport(to: string | string[], data: any) {
  const fromEmail = process.env.EMAIL_FROM || "ThreatRadar <threatradar@viajeinteligencia.com>";

  return resend.emails.send({
    from: fromEmail,
    to,
    subject: "Weekly Report",
    html: weeklyReportTemplate(data),
  });
}
