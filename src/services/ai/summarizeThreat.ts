import { GoogleGenAI } from "@google/genai";

// Inicialización correcta según el SDK oficial de Google Gen AI
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

export async function summarizeThreat(data: any): Promise<string> {
  try {
    if (!process.env.GEMINI_API_KEY) {
      console.error("❌ Error: GEMINI_API_KEY no está definida en el archivo .env");
      return "Error: Configuración de IA ausente.";
    }

    const response = await ai.models.generateContent({
      model: "gemini-1.5-flash", // Más rápido y eficiente para reportes automatizados
      contents: `Actúa como un analista experto en ciberinteligencia y OSINT. 
Analiza los siguientes datos de amenazas y genera un resumen ejecutivo claro, estructurado y directo para el informe semanal:

${JSON.stringify(data, null, 2)}`,
    });

    // Validar y extraer el texto de forma segura según el árbol de respuesta del SDK
    if (response && response.text) {
      return response.text;
    } else if (response.candidates?.[0]?.content?.parts?.[0]?.text) {
      return response.candidates[0].content.parts[0].text;
    }

    return "No se pudo extraer el texto del análisis de IA.";
  } catch (error) {
    console.error("❌ Error al llamar a la API de Gemini:", error);
    return "Error interno al generar el resumen de la amenaza.";
  }
}
