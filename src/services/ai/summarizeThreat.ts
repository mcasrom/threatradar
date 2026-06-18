import { GoogleGenAI } from "@google/genai";

// Inicialización del SDK oficial usando tu clave del .env
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

export async function summarizeThreat(data: any): Promise<string> {
  try {
    if (!process.env.GEMINI_API_KEY) {
      console.error("❌ Error: GEMINI_API_KEY no detectada en el entorno.");
      return "Configuración de IA no disponible.";
    }

    // Un prompt profesional de OSINT sustituyendo la concatenación vaga anterior
    const prompt = `
Actúa como un Analista de Ciberseguridad y experto en Inteligencia de Amenazas (OSINT).
Analiza el siguiente conjunto de datos técnicos de escaneo (JSON) y genera un informe ejecutivo estructurado.

Reglas estrictas de salida:
1. Idioma: Español.
2. Tono: Profesional, directo y técnico pero comprensible para la directiva.
3. Estructura obligatoria:
   - 📌 RESUMEN EJECUTIVO DE AMENAZAS
   - ⚠️ ANÁLISIS DE RIESGO CRÍTICO (Evalúa los puertos y fugas detectadas)
   - 🛡️ ACCIONES DE MITIGACIÓN RECOMENDADAS

Datos a procesar:
${JSON.stringify(data, null, 2)}
`;

    const response = await ai.models.generateContent({
      model: "gemini-1.5-flash", // Cambiado a flash: ultra-rápido para evitar timeouts en el backend
      contents: prompt,
    });

    // Control de extracción seguro según la respuesta real del SDK unificado de Google
    if (response && response.text) {
      return response.text;
    } else if (response.candidates?.[0]?.content?.parts?.[0]?.text) {
      return response.candidates[0].content.parts[0].text;
    }

    return "La IA generó una respuesta vacía o no estructurada.";

  } catch (error) {
    console.error("❌ Error crítico en el módulo de IA (summarizeThreat):", error);
    return "Error interno al procesar el análisis de impacto de la amenaza.";
  }
}
