import React from "react";
import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { ClerkProvider } from "@clerk/nextjs";
import "./globals.css";
import { SpeedInsights } from "@vercel/speed-insights/next";

const geist = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'),
  title: "Tiger Dorm Dashboard",
  description: "Real-time status tracking dashboard for dorm roommates",
  applicationName: "Tiger Dorm",
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "default",
    title: "Tiger Dorm",
    startupImage: [
      {
        url: "/icon-512x512.png?v=2",
        media: "(device-width: 375px) and (device-height: 812px) and (-webkit-device-pixel-ratio: 3)",
      },
    ],
  },
  formatDetection: {
    telephone: false,
  },
  icons: [
    { rel: "icon", url: "/icon-192x192.png?v=3", sizes: "192x192", type: "image/png" },
    { rel: "icon", url: "/icon-512x512.png?v=3", sizes: "512x512", type: "image/png" },
    { rel: "apple-touch-icon", url: "/icon-192x192.png?v=3", sizes: "192x192" },
    { rel: "shortcut icon", url: "/favicon.ico?v=3" },
  ],
};

export const viewport: Viewport = {
  themeColor: "#4f46e5",
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  minimumScale: 1,
  userScalable: false,
  viewportFit: "cover",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        {/* PWA-specific mobile optimizations */}
        <meta name="mobile-web-app-capable" content="yes" />
        <meta name="msapplication-TileColor" content="#4f46e5" />
        <meta name="msapplication-tap-highlight" content="no" />
      </head>
      <body className={`${geist.variable} ${geistMono.variable} antialiased`}>
        <ClerkProvider>
          {children}
          <SpeedInsights />
        </ClerkProvider>
      </body>
    </html>
  );
}
