import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SOC Analytics Dashboard',
  description: 'AI Log Analysis Dashboard'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
