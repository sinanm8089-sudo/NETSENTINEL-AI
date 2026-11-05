import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NETSENTINEL AI — Autonomous Network Exposure & Security Command Center",
  description:
    "Autonomous Enterprise Network Discovery, Intelligence & Security Monitoring Platform. Created by Sinan Mohammed.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#050811] text-slate-100 antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
        {children}
      </body>
    </html>
  );
}

