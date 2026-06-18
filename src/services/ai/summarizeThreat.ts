import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

export async function summarizeThreat(data) {
  const response = await ai.models.generateContent({
    model: "gemini-1.5-pro",
    contents: "Analyze this data: " + JSON.stringify(data),
  });

  return response.text || "";
}
