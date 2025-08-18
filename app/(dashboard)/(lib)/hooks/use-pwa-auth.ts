'use client';

import { useEffect, useCallback, useRef } from 'react';
import { useAuth } from '@clerk/nextjs';
import { useEnhancedAuth } from '../auth/enhanced-auth-provider';

interface PWAAuthMessage {
  type: 'AUTH_STATE_UPDATE' | 'TOKEN_REFRESH' | 'SESSION_EXPIRED' | 'CLEAR_AUTH_CACHE';
  data?: any;
}

interface ServiceWorkerMessage {
  type: 'SESSION_EXPIRED_IN_SW' | 'REQUEST_AUTH_REFRESH';
  timestamp: number;
}

export function usePWAAuth() {
  const { isSignedIn, userId, getToken } = useAuth();
  const { 
    sessionStatus, 
    lastTokenRefresh, 
    refreshToken, 
    forceReauthentication 
  } = useEnhancedAuth();
  
  const serviceWorkerRef = useRef<ServiceWorker | null>(null);
  const messageQueue = useRef<PWAAuthMessage[]>([]);

  // Send message to Service Worker
  const sendToServiceWorker = useCallback((message: PWAAuthMessage) => {
    if (serviceWorkerRef.current) {
      console.log('PWA Auth: Sending to Service Worker:', message);
      serviceWorkerRef.current.postMessage(message);
    } else {
      // Queue message if SW is not ready
      messageQueue.current.push(message);
      console.log('PWA Auth: Queued message (SW not ready):', message);
    }
  }, []);

  // Initialize Service Worker communication
  const initializeServiceWorker = useCallback(async () => {
    if (!('serviceWorker' in navigator)) {
      console.warn('PWA Auth: Service Worker not supported');
      return;
    }

    try {
      // Get or register service worker
      let registration = await navigator.serviceWorker.getRegistration();
      
      if (!registration) {
        registration = await navigator.serviceWorker.register('/sw.js');
        console.log('PWA Auth: Service Worker registered');
      }

      // Get active service worker
      const sw = registration.active || registration.waiting || registration.installing;
      
      if (sw) {
        serviceWorkerRef.current = sw;
        
        // Send any queued messages
        while (messageQueue.current.length > 0) {
          const queuedMessage = messageQueue.current.shift();
          if (queuedMessage) {
            sendToServiceWorker(queuedMessage);
          }
        }
        
        console.log('PWA Auth: Service Worker communication initialized');
      }

      // Listen for SW state changes
      if (registration.installing) {
        registration.installing.addEventListener('statechange', (e) => {
          const sw = e.target as ServiceWorker;
          if (sw.state === 'activated') {
            serviceWorkerRef.current = sw;
          }
        });
      }
    } catch (error) {
      console.error('PWA Auth: Service Worker initialization failed:', error);
    }
  }, [sendToServiceWorker]);

  // Handle messages from Service Worker
  const handleServiceWorkerMessage = useCallback((event: MessageEvent<ServiceWorkerMessage>) => {
    console.log('PWA Auth: Received from Service Worker:', event.data);
    
    const { type, timestamp } = event.data;
    
    switch (type) {
      case 'SESSION_EXPIRED_IN_SW':
        console.log('PWA Auth: Session expired in Service Worker');
        forceReauthentication();
        break;
        
      case 'REQUEST_AUTH_REFRESH':
        console.log('PWA Auth: Service Worker requested auth refresh');
        refreshToken();
        break;
        
      default:
        console.log('PWA Auth: Unknown message from Service Worker:', type);
    }
  }, [forceReauthentication, refreshToken]);

  // Update Service Worker with auth state changes
  const updateServiceWorkerAuthState = useCallback(() => {
    if (isSignedIn && userId) {
      sendToServiceWorker({
        type: 'AUTH_STATE_UPDATE',
        data: {
          isAuthenticated: true,
          userId,
          sessionExpiry: lastTokenRefresh ? 
            lastTokenRefresh.getTime() + (60 * 60 * 1000) : // Assume 1 hour
            Date.now() + (60 * 60 * 1000),
          sessionStatus
        }
      });
    } else {
      sendToServiceWorker({
        type: 'AUTH_STATE_UPDATE',
        data: {
          isAuthenticated: false,
          userId: null,
          sessionExpiry: null,
          sessionStatus: 'expired'
        }
      });
    }
  }, [isSignedIn, userId, lastTokenRefresh, sessionStatus, sendToServiceWorker]);

  // Handle token refresh
  const handleTokenRefresh = useCallback(async () => {
    if (!isSignedIn || !userId) return;

    try {
      const token = await getToken({ template: 'supabase' });
      if (token) {
        sendToServiceWorker({
          type: 'TOKEN_REFRESH',
          data: {
            token,
            expiry: Date.now() + (60 * 60 * 1000) // Assume 1 hour expiry
          }
        });
        console.log('PWA Auth: Token refreshed and sent to Service Worker');
      }
    } catch (error) {
      console.error('PWA Auth: Token refresh failed:', error);
    }
  }, [isSignedIn, userId, getToken, sendToServiceWorker]);

  // Handle session expiration
  const handleSessionExpiration = useCallback(() => {
    sendToServiceWorker({
      type: 'SESSION_EXPIRED',
      data: { timestamp: Date.now() }
    });
    
    // Clear auth-related caches
    sendToServiceWorker({
      type: 'CLEAR_AUTH_CACHE'
    });
  }, [sendToServiceWorker]);

  // Initialize Service Worker communication
  useEffect(() => {
    initializeServiceWorker();

    // Listen for messages from Service Worker
    navigator.serviceWorker?.addEventListener('message', handleServiceWorkerMessage);

    return () => {
      navigator.serviceWorker?.removeEventListener('message', handleServiceWorkerMessage);
    };
  }, [initializeServiceWorker, handleServiceWorkerMessage]);

  // Update Service Worker when auth state changes
  useEffect(() => {
    updateServiceWorkerAuthState();
  }, [updateServiceWorkerAuthState]);

  // Handle token refresh events
  useEffect(() => {
    if (lastTokenRefresh) {
      handleTokenRefresh();
    }
  }, [lastTokenRefresh, handleTokenRefresh]);

  // Handle session expiration
  useEffect(() => {
    if (sessionStatus === 'expired' || sessionStatus === 'error') {
      handleSessionExpiration();
    }
  }, [sessionStatus, handleSessionExpiration]);

  // Periodic auth sync with Service Worker
  useEffect(() => {
    const syncInterval = setInterval(() => {
      if (isSignedIn && userId) {
        updateServiceWorkerAuthState();
      }
    }, 5 * 60 * 1000); // Every 5 minutes

    return () => clearInterval(syncInterval);
  }, [isSignedIn, userId, updateServiceWorkerAuthState]);

  // Handle page visibility changes
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        // Sync auth state when page becomes visible
        updateServiceWorkerAuthState();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [updateServiceWorkerAuthState]);

  // Background sync registration
  const registerBackgroundSync = useCallback(async (tag: string) => {
    if (!('serviceWorker' in navigator)) {
      console.warn('PWA Auth: Service Worker not supported');
      return;
    }

    try {
      const registration = await navigator.serviceWorker.ready;
      
      // Check if background sync is supported
      if ('sync' in registration) {
        await (registration as any).sync.register(tag);
        console.log('PWA Auth: Background sync registered:', tag);
      } else {
        console.warn('PWA Auth: Background sync not supported');
      }
    } catch (error) {
      console.error('PWA Auth: Background sync registration failed:', error);
    }
  }, []);

  // Request background auth refresh
  const requestAuthRefresh = useCallback(() => {
    registerBackgroundSync('auth-refresh');
  }, [registerBackgroundSync]);

  return {
    // State
    isServiceWorkerReady: !!serviceWorkerRef.current,
    
    // Actions
    updateAuthState: updateServiceWorkerAuthState,
    refreshAuthToken: handleTokenRefresh,
    clearAuthCache: () => sendToServiceWorker({ type: 'CLEAR_AUTH_CACHE' }),
    requestAuthRefresh,
    
    // Utilities
    sendToServiceWorker
  };
} 