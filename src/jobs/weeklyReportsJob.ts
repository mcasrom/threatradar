import cron from "node-cron";
import { summarizeThreat } from "../services/ai/summarizeThreat";
import { sendWeeklyReport } from "../services/email/sendWeeklyReport";

// CAMBIO: Pon tu correo verificado para que Resend permita el envío en local
const users = [
  { email: "threatradar@viajeinteligencia.com", plan: "premium", assets: ["8.8.8.8"] }
];

function mockScan(ip: string) {
  return {
    ip,
    riskScore: Math.floor(Math.random() * 100),
    findings: [
      { title: "Open port", severity: "medium" },
      { title: "Leak indicator", severity: "high" }
    ]
  };
}

// Función auxiliar para poder ejecutar el reporte bajo demanda sin esperar al Cron
async function runReportLifecycle() {
  console.log("[REPORT JOB] Iniciando procesamiento de informes...");

  for (const user of users) {
    if (user.plan !== "premium") continue;

    try {
      const scans = user.assets.map(mockScan);
      
      console.log(`[REPORT JOB] Solicitando análisis de IA a Gemini para ${user.email}...`);
      const aiSummary = await summarizeThreat(scans);
      console.log("[REPORT JOB] Respuesta de IA recibida correctamente.");

      const avg = scans.reduce((a, b) => a + b.riskScore, 0) / scans.length;

      console.log(`[REPORT JOB] Enviando correo vía Resend a ${user.email}...`);
      await sendWeeklyReport(user.email, {
        riskScore: Math.round(avg),
        findings: scans.flatMap(s => s.findings),
        aiSummary
      });
      console.log(`[REPORT JOB] ¡Informe enviado con éxito a ${user.email}!`);

    } catch (error) {
      console.error(`❌ [REPORT JOB] Error procesando el usuario ${user.email}:`, error);
    }
  }
}

export function startWeeklyReportsJob() {
  // 1. Forzar una ejecución inmediata al levantar el servidor para comprobar que la IA y el email funcionan
  runReportLifecycle();

  // 2. Mantener la programación para todos los lunes a las 8:00 AM
  cron.schedule("0 8 * * 1", async () => {
    console.log("[CRON] Ejecución programada de los lunes activada.");
    await runReportLifecycle();
  });
}
