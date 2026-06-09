import './globals.css';
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <title>SOC Dashboard</title>
      <body className="bg-slate-900 text-slate-200">{children}</body>
    </html>
  );
}