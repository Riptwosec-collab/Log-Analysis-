import { NextResponse } from "next/server";
import { analyzeLog } from "../../../lib/logAnalyzer";

export async function POST(req: Request) {
  try {
    const contentType = req.headers.get("content-type") || "";
    let logContent = "";

    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      logContent = file ? await file.text() : String(formData.get("log") || "");
    } else {
      const body = await req.json();
      logContent = String(body.log || "");
    }

    if (!logContent.trim()) {
      return NextResponse.json({ error: "Log content is required." }, { status: 400 });
    }

    return NextResponse.json(analyzeLog(logContent), { status: 200 });
  } catch (error) {
    console.error("Analyze API error:", error);
    return NextResponse.json({ error: "Unable to analyze the submitted log." }, { status: 500 });
  }
}
