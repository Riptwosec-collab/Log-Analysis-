export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const log = String(body.log || '').slice(0, 12000);
    if (!log.trim()) return res.status(400).json({ error: 'กรุณาใส่ Log ก่อนวิเคราะห์' });

    const local = localAnalyze(log);
    const