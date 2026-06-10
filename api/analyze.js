export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const log = String(body.log || '').slice(0, 12000);

    if (!log.trim()) {
      return res.status(400).json({ error: 'กรุณาใส่ Log ก่อนวิเคราะห์' });
    }

    const localResult = analyzeLocally(log);
    const apiKey = process.env.AI_API_KEY || process.env.OPENAI_API_KEY;

    if (!apiKey) {
      return res.status(200).json({
        mode: 'local',
        note: 'ยังไม่ได้ตั้งค่า AI_API_KEY หรือ