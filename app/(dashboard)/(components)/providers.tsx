'use client';

import React from 'react';
import { usePWA } from '../(lib)/hooks/use-pwa';
interface ProvidersProps {
    children: React.ReactNode;
}

// Internal component to handle PWA functionality
function PWAManager({ children }: { children: React.ReactNode }) {
    const pwa = usePWA();

    // The PWA hook handles:
    // - Service Worker registration
    // - Install prompt management
    // - Online/offline detection
    // - App installation state

    return <>{children}</>;
}

export default function Providers({ children }: ProvidersProps) {
    return (
                <PWAManager>
                    {children}
                </PWAManager>
    );
} 