# 🏠 Tiger Dorm  Dashboard

> A beautiful, real-time status tracking PWA for dorm roommates built with Next.js 15+ and modern architecture

<div align="center">

[![Next.js 15+](https://img.shields.io/badge/Next.js-15+-black?style=flat&logo=next.js)](https://nextjs.org/)
[![React 19](https://img.shields.io/badge/React-19-61dafb?style=flat&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5+-3178c6?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4+-06b6d4?style=flat&logo=tailwindcss)](https://tailwindcss.com/)
[![PWA](https://img.shields.io/badge/PWA-Ready-purple?style=flat)](https://web.dev/progressive-web-apps/)

![Live](https://img.shields.io/badge/status-Live-green?style=for-the-badge)
![Offline Ready](https://img.shields.io/badge/offline-Ready-blue?style=for-the-badge)
![Real-time](https://img.shields.io/badge/realtime-Active-red?style=for-the-badge)

</div>

## ✨ Features

📱 **PWA** - Install on any device, works offline  
⚡ **Real-time** - Instant status updates across devices  
🏗️ **Modern** - Next.js 15+ App Router & Server Components  
🎨 **Beautiful** - Dark theme with smooth animations  

**Status Options:** 🏠 In Room • 📚 Studying • 💪 Gym • 😴 Sleeping • 🚶 Out

## 🚀 Quick Start

```bash
git clone https://github.com/jschady/tigerdorm && cd tigerdorm && npm install
```

**Supabase Setup:**
```sql
CREATE TABLE members (
  id_member UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'AWAY',
  last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
ALTER TABLE members REPLICA IDENTITY FULL;
ALTER PUBLICATION supabase_realtime ADD TABLE members;
```

**Environment:**
```bash
# .env.local
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_anon_key
```

**Launch:**
```bash
npm run dev  # Open localhost:3000
```

## 📁 Project Structure

Built with **Next.js 15+ App Router** and organized using **route groups** for clean separation:

```
app/
├── layout.tsx                    # Root layout with metadata
├── page.tsx                     # Main dashboard (Client Component)
├── globals.css                  # Global Tailwind styles
└── (dashboard)/                 # Route group (doesn't affect URL)
    ├── (components)/           # UI Components route group
    
    │   ├── status-card.tsx     # Individual status display card
    │   └── modals/            # Modal components directory
    │       ├── status-update-modal.tsx   # Status selection modal
    │       ├── user-selection-modal.tsx  # User picker modal
    │       └── ios-install-modal.tsx     # PWA install guide
    └── (lib)/                 # Core Logic route group
        ├── supabase-client.ts  # Singleton Supabase client
        ├── types.ts           # TypeScript interfaces
        ├── constants.tsx      # Status options & icons
        └── hooks/            # Custom React hooks
            ├── use-pwa.ts     # PWA detection & functionality
            └── use-realtime.ts # Real-time subscriptions

public/
├── manifest.json              # PWA manifest configuration
├── sw.js                     # Service Worker for offline support
└── icon-*.png               # PWA app icons (various sizes)
```

## 📄 License

MIT License - Perfect for dorm life! 🎓

---

<div align="center">
Built with ❤️ for dorm communities • <strong>Install as PWA for best experience!</strong>
</div>
