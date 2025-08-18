'use client';

import React from 'react';
import { usePWA } from '../(lib)/hooks/use-pwa';
// import { usePWAAuth } from '../(lib)/hooks/use-pwa-auth';
// import { EnhancedAuthProvider } from '../(lib)/auth/enhanced-auth-provider';
// import AuthErrorBoundary from './auth/auth-error-boundary-simple';

interface ProvidersProps {
    children: React.ReactNode;
}

// Internal component to handle PWA functionality
function PWAManager({ children }: { children: React.ReactNode }) {
    const pwa = usePWA();
    // const pwaAuth = usePWAAuth();

    // The PWA hook handles:
    // - Service Worker registration
    // - Install prompt management
    // - Online/offline detection
    // - App installation state

    // The PWA Auth hook handles (temporarily disabled):
    // - Service Worker authentication state sync
    // - Token management in Service Worker
    // - Offline authentication handling
    // - Background sync for auth refresh

    return <>{children}</>;
}

export default function Providers({ children }: ProvidersProps) {
    return (
        // Temporarily disable enhanced auth to fix login issues
        // <AuthErrorBoundary>
        //     <EnhancedAuthProvider>
                <PWAManager>
                    {children}
                </PWAManager>
        //     </EnhancedAuthProvider>
        // </AuthErrorBoundary>
    );
} 