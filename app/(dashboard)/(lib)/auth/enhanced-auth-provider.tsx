'use client';

import React, { createContext, useContext, useEffect, useState, useRef, useCallback } from 'react';
import { useAuth, useUser } from '@clerk/nextjs';
import type { UserResource } from '@clerk/types';

interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: UserResource | null;
  error: string | null;
  sessionStatus: 'active' | 'expired' | 'refreshing' | 'error' | 'unknown';
  lastTokenRefresh: Date | null;
  connectionStatus: 'online' | 'offline' | 'reconnecting';
}

interface AuthActions {
  refreshToken: () => Promise<boolean>;
  clearError: () => void;
  forceReauthentication: () => void;
  checkSessionHealth: () => Promise<boolean>;
}

interface EnhancedAuthContextValue extends AuthState, AuthActions {}

const EnhancedAuthContext = createContext<EnhancedAuthContextValue | null>(null);

interface EnhancedAuthProviderProps {
  children: React.ReactNode;
}

export function EnhancedAuthProvider({ children }: EnhancedAuthProviderProps) {
  const { 
    isLoaded: authLoaded, 
    isSignedIn, 
    userId, 
    getToken, 
    signOut 
  } = useAuth();
  
  const { 
    isLoaded: userLoaded, 
    user: clerkUser 
  } = useUser();

  // Enhanced auth state
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    user: null,
    error: null,
    sessionStatus: 'unknown',
    lastTokenRefresh: null,
    connectionStatus: 'online'
  });

  // Refs for managing timers and preventing race conditions
  const tokenRefreshTimer = useRef<NodeJS.Timeout | null>(null);
  const healthCheckTimer = useRef<NodeJS.Timeout | null>(null);
  const retryCount = useRef(0);
  const maxRetries = 3;

  // Connection status monitoring
  useEffect(() => {
    const handleOnline = () => setState(prev => ({ ...prev, connectionStatus: 'online' }));
    const handleOffline = () => setState(prev => ({ ...prev, connectionStatus: 'offline' }));

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // Enhanced token refresh with retry logic
  const refreshToken = useCallback(async (): Promise<boolean> => {
    if (!isSignedIn || !userId) return false;

    setState(prev => ({ ...prev, sessionStatus: 'refreshing', error: null }));

    try {
      const token = await getToken({ template: 'supabase' });
      
      if (token) {
        setState(prev => ({
          ...prev,
          sessionStatus: 'active',
          lastTokenRefresh: new Date(),
          error: null
        }));
        retryCount.current = 0;
        return true;
      } else {
        throw new Error('Failed to retrieve token');
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
      retryCount.current += 1;

      if (retryCount.current >= maxRetries) {
        setState(prev => ({
          ...prev,
          sessionStatus: 'error',
          error: 'Authentication session expired. Please sign in again.'
        }));
        return false;
      } else {
        // Retry with exponential backoff
        setTimeout(() => refreshToken(), 1000 * Math.pow(2, retryCount.current));
        return false;
      }
    }
  }, [isSignedIn, userId, getToken]);

  // Session health check
  const checkSessionHealth = useCallback(async (): Promise<boolean> => {
    if (!isSignedIn || !userId) return false;

    try {
      const token = await getToken({ template: 'supabase' });
      const isHealthy = !!token;
      
      setState(prev => ({
        ...prev,
        sessionStatus: isHealthy ? 'active' : 'expired',
        error: isHealthy ? null : 'Session may be expired'
      }));

      return isHealthy;
    } catch (error) {
      console.error('Session health check failed:', error);
      setState(prev => ({
        ...prev,
        sessionStatus: 'error',
        error: 'Unable to verify session status'
      }));
      return false;
    }
  }, [isSignedIn, userId, getToken]);

  // Force reauthentication
  const forceReauthentication = useCallback(() => {
    setState(prev => ({
      ...prev,
      sessionStatus: 'expired',
      error: 'Reauthentication required'
    }));
    signOut();
  }, [signOut]);

  // Clear error state
  const clearError = useCallback(() => {
    setState(prev => ({ ...prev, error: null }));
  }, []);

  // Setup automatic token refresh
  useEffect(() => {
    if (!isSignedIn || !userId) return;

    // Initial token refresh
    refreshToken();

    // Set up periodic token refresh (every 45 minutes)
    tokenRefreshTimer.current = setInterval(() => {
      refreshToken();
    }, 45 * 60 * 1000);

    return () => {
      if (tokenRefreshTimer.current) {
        clearInterval(tokenRefreshTimer.current);
        tokenRefreshTimer.current = null;
      }
    };
  }, [isSignedIn, userId, refreshToken]);

  // Setup periodic health checks
  useEffect(() => {
    if (!isSignedIn || !userId) return;

    // Health check every 5 minutes
    healthCheckTimer.current = setInterval(() => {
      checkSessionHealth();
    }, 5 * 60 * 1000);

    return () => {
      if (healthCheckTimer.current) {
        clearInterval(healthCheckTimer.current);
        healthCheckTimer.current = null;
      }
    };
  }, [isSignedIn, userId, checkSessionHealth]);

  // Update auth state when Clerk state changes
  useEffect(() => {
    if (!authLoaded || !userLoaded) {
      setState(prev => ({ ...prev, isLoading: true }));
      return;
    }

    setState(prev => ({
      ...prev,
      isLoading: false,
      isAuthenticated: !!isSignedIn,
      user: clerkUser || null,
      sessionStatus: isSignedIn ? 'active' : 'expired'
    }));
  }, [authLoaded, userLoaded, isSignedIn, clerkUser]);

  // Handle page visibility changes for session management
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && isSignedIn && userId) {
        // Check session health when page becomes visible
        checkSessionHealth();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [isSignedIn, userId, checkSessionHealth]);

  // Handle storage events for cross-tab synchronization
  useEffect(() => {
    const handleStorageChange = (event: StorageEvent) => {
      if (event.key === 'clerk-auth-state' && event.newValue !== event.oldValue) {
        // Sync auth state across tabs
        if (isSignedIn && userId) {
          checkSessionHealth();
        }
      }
    };

    window.addEventListener('storage', handleStorageChange);

    return () => {
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [isSignedIn, userId, checkSessionHealth]);

  // Context value with optimized memoization
  const contextValue = React.useMemo<EnhancedAuthContextValue>(() => ({
    ...state,
    refreshToken,
    clearError,
    forceReauthentication,
    checkSessionHealth
  }), [state, refreshToken, clearError, forceReauthentication, checkSessionHealth]);

  return (
    <EnhancedAuthContext.Provider value={contextValue}>
      {children}
    </EnhancedAuthContext.Provider>
  );
}

export function useEnhancedAuth(): EnhancedAuthContextValue {
  const context = useContext(EnhancedAuthContext);
  
  if (!context) {
    throw new Error('useEnhancedAuth must be used within an EnhancedAuthProvider');
  }

  return context;
}

// Hook for session management utilities
export function useSessionManagement() {
  const { 
    refreshToken, 
    checkSessionHealth, 
    sessionStatus, 
    lastTokenRefresh,
    connectionStatus 
  } = useEnhancedAuth();

  const isSessionHealthy = sessionStatus === 'active';
  const needsRefresh = sessionStatus === 'expired' || 
    (lastTokenRefresh && Date.now() - lastTokenRefresh.getTime() > 40 * 60 * 1000); // 40 minutes

  return {
    refreshToken,
    checkSessionHealth,
    isSessionHealthy,
    needsRefresh,
    sessionStatus,
    connectionStatus,
    lastTokenRefresh
  };
} 