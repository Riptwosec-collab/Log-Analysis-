import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const { webhookUrl, payload, slackFormat } = await req.json();
    if (!webhookUrl?.startsWith("https://"))
      return NextResponse.json({ error: "Invalid webhook URL" }, { status: 400 });

    const body = slackFormat
      ? {
          text: `🚨 SOC Alert — Risk: ${payload.riskLevel} (${payload.riskScore}/100)`,
          blocks: [
            {
              type: "header",
              text: {
                type: "plain_text",
                text: `🚨 ${payload.riskLevel} Risk Detected`,
              },
            },
            {
              type: "section",
              fields: [
                { type: "mrkdwn", text: `*Score:* ${payload.riskScore}/100` },
                { type: "mrkdwn", text: `*Findings:* ${payload.findingCount}` },
                { type: "mrkdwn", text: `*Critical:* ${payload.criticalAlerts}` },
                { type: "mrkdwn", text: `*Top IP:* ${payload.topSourceIp ?? "N/A"}` },
              ],
            },
            {
              type: "section",
              text: {
                type: "mrkdwn",
                text: `*Summary:* ${payload.narrative}`,
              },
            },
            {
              type: "context",
              elements: [
                {
                  type: "mrkdwn",
                  text: `Generated: ${payload.generatedAt}`,
                },
              ],
            },
          ],
        }
      : payload;

    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    return NextResponse.json({ ok: res.ok, status: res.status });
  } catch (e: any) {
    return NextResponse.json({ error: e.message }, { status: 500 });
  }
}
