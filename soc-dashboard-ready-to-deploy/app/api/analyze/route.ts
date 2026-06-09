import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  try {
    const formData = await req.formData();
    const file = formData.get('file') as File;
    
    if (!file) {
      return NextResponse.json({ error: "ไม่พบไฟล์" }, { status: 400 });
    }

    const logContent = await file.text();

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.AI_API_KEY}`
      },
      body: JSON.stringify({
        model: "gpt-4o", 
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content: `You are a Senior Security Engineer. Analyze the provided log and return a strictly structured JSON. Required keys: "incident_id", "severity", "root_cause", "recommended_fixes". Do not invent facts.`
          },
          { role: "user", content: `Analyze this log data:\n\n${logContent}` }
        ]
      })
    });

    const data = await response.json();

    if (data.error) {
        console.error("OpenAI API Error:", data.error);
        return NextResponse.json({ error: data.error.message }, { status: 500 });
    }

    const analysisResult = JSON.parse(data.choices[0].message.content || "{}");

    return NextResponse.json(analysisResult, { status: 200 });

  } catch (error) {
    console.error("System Error:", error);
    return NextResponse.json({ error: "เกิดข้อผิดพลาดในระบบ" }, { status: 500 });
  }
}