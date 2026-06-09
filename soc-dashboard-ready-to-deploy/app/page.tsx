'use client';
import { useState } from 'react';

export default function SOCDashboard() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsAnalyzing(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
      }
      
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error("Upload failed", error);
      alert("เกิดข้อผิดพลาดในการวิเคราะห์ไฟล์ กรุณาตรวจสอบการตั้งค่า API Key");
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-200 p-8 font-sans">
      <div className="max-w-4xl mx-auto space-y-6">
        <header className="border-b border-slate-700 pb-4">
            <h1 className="text-3xl font-bold text-blue-400">🛡️ SOC Analytics Dashboard</h1>
            <p className="text-slate-400 mt-2">Next.js + AI Integration</p>
        </header>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg">
          <h2 className="text-xl font-semibold mb-4 text-white">Upload Log File</h2>
          <div className="relative border-2 border-dashed border-slate-500 rounded-lg p-10 text-center hover:border-blue-500 transition-colors bg-slate-800/50">
            <input 
              type="file" 
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10" 
              onChange={handleFileUpload}
              accept=".log,.txt,.csv"
              disabled={isAnalyzing}
            />
            <div className="space-y-3 pointer-events-none">
                <p className="text-lg font-medium text-slate-300">
                  {isAnalyzing ? "🤖 AI กำลังวิเคราะห์ข้อมูล..." : "ลากไฟล์ Log มาวางที่นี่ หรือคลิกเพื่อเลือกไฟล์"}
                </p>
            </div>
          </div>
        </div>

        {result && (
          <div className="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-lg animate-fade-in-up">
            <h2 className="text-xl font-semibold text-white mb-4">Analysis Result</h2>
            <pre className="bg-slate-950 p-4 rounded-lg text-green-400 text-sm overflow-x-auto border border-slate-800 whitespace-pre-wrap">
                {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}