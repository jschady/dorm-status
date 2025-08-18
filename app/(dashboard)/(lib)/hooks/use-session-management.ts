'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import { useEnhancedAuth } from '../auth/enhanced-auth-provider';

interface SessionHealthMetrics {
  lastHealthCheck: Date | null;
  consecutiveFailures: number;
  averageResponseTime: number;
  healthScore: number; // 0-100
}

interface SessionManagementConfig {
  healthCheckInterval?: number; // ms
  tokenRefreshThreshold?: number; // ms before expiry
  maxConsecutiveFailures?: number;
  enableMetrics?: boolean;
}

interface SessionManagementReturn {
  // Session state
  isSessionHealthy: boolean;
  sessionHealth: SessionHealthMetrics;
  lastTokenRefresh: Date | null;
  sessionStatus: 'active' | 'expired' | 'refreshing' | 'error' | 'unknown';
  
  // Actions
  refreshToken: () => Promise<boolean>;
  checkSessionHealth: () => Promise<boolean>;
  forceRefresh: () => Promise<void>;
  invalidateSession: () => void;
  
  // Utilities
  getTimeUntilExpiry: () => number | null;
  getSessionAge: () => number | null;
  shouldRefreshToken: () => boolean;
}

const DEFAULT_CONFIG: Required<SessionManagementConfig> = {
  healthCheckInterval: 5 * 60 * 1000, // 5 minutes
  tokenRefreshThreshold: 5 * 60 * 1000, // 5 minutes before expiry
  maxConsecutiveFailures: 3,
  enableMetrics: true
};

export function useSessionManagement(config: SessionManagementConfig = {}): SessionManagementReturn {
  const fullConfig = { ...DEFAULT_CONFIG, ...config };
  const { getToken, userId, isSignedIn } = useAuth();
  const { 
    refreshToken: enhancedRefreshToken,
    checkSessionHealth: enhancedHealthCheck,
    sessionStatus,
    lastTokenRefresh,
    forceReauthentication
  } = useEnhancedAuth();

  // Session health metrics
  const [healthMetrics, setHealthMetrics] = useState<SessionHealthMetrics>({
    lastHealthCheck: null,
    consecutiveFailures: 0,
    averageResponseTime: 0,
    healthScore: 100
  });

  // Refs for managing intervals and preventing race conditions
  const healthCheckInterval = useRef<NodeJS.Timeout | null>(null);
  const responseTimeHistory = useRef<number[]>([]);
  const tokenCache = useRef<{ token: string; expiry: Date } | null>(null);
  const isRefreshing = useRef(false);

  // Calculate session health score based on various factors
  const calculateHealthScore = useCallback((metrics: SessionHealthMetrics): number => {
    let score = 100;

    // Penalize consecutive failures
    score -= metrics.consecutiveFailures * 20;

    // Penalize slow response times (over 1 second)
    if (metrics.averageResponseTime > 1000) {
      score -= Math.min((metrics.averageResponseTime - 1000) / 100, 30);
    }

    // Penalize stale health checks (over 10 minutes old)
    if (metrics.lastHealthCheck) {
      const staleness = Date.now() - metrics.lastHealthCheck.getTime();
      if (staleness > 10 * 60 * 1000) {
        score -= Math.min(staleness / (60 * 1000), 25); // Max 25 point penalty
      }
    }

    return Math.max(0, Math.min(100, score));
  }, []);

  // Enhanced token refresh with caching and error handling
  const refreshToken = useCallback(async (): Promise<boolean> => {
    if (!isSignedIn || !userId || isRefreshing.current) {
      return false;
    }

    isRefreshing.current = true;
    const startTime = Date.now();

    try {
      const success = await enhancedRefreshToken();
      
      if (success) {
        // Update token cache
        const token = await getToken({ template: 'supabase' });
        if (token) {
          // Decode token to get expiry (simplified approach)
          // In production, you might want to use a JWT library
          const expiry = new Date(Date.now() + 60 * 60 * 1000); // Assume 1 hour expiry
          tokenCache.current = { token, expiry };
        }

        // Update metrics
        const responseTime = Date.now() - startTime;
        responseTimeHistory.current.push(responseTime);
        
        // Keep only last 10 response times
        if (responseTimeHistory.current.length > 10) {
          responseTimeHistory.current = responseTimeHistory.current.slice(-10);
        }

        setHealthMetrics(prev => ({
          ...prev,
          consecutiveFailures: 0,
          averageResponseTime: responseTimeHistory.current.reduce((a, b) => a + b, 0) / responseTimeHistory.current.length,
          healthScore: calculateHealthScore({
            ...prev,
            consecutiveFailures: 0,
            averageResponseTime: responseTimeHistory.current.reduce((a, b) => a + b, 0) / responseTimeHistory.current.length
          })
        }));
      }

      return success;
    } catch (error) {
      console.error('Token refresh failed:', error);
      
      setHealthMetrics(prev => {
        const newMetrics = {
          ...prev,
          consecutiveFailures: prev.consecutiveFailures + 1,
          healthScore: calculateHealthScore({
            ...prev,
            consecutiveFailures: prev.consecutiveFailures + 1
          })
        };
        return newMetrics;
      });

      return false;
    } finally {
      isRefreshing.current = false;
    }
  }, [isSignedIn, userId, enhancedRefreshToken, getToken, calculateHealthScore]);

  // Enhanced session health check
  const checkSessionHealth = useCallback(async (): Promise<boolean> => {
    if (!isSignedIn || !userId) {
      return false;
    }

    const startTime = Date.now();

    try {
      const isHealthy = await enhancedHealthCheck();
      const responseTime = Date.now() - startTime;

      setHealthMetrics(prev => {
        const newMetrics = {
          ...prev,
          lastHealthCheck: new Date(),
          consecutiveFailures: isHealthy ? 0 : prev.consecutiveFailures + 1,
          averageResponseTime: fullConfig.enableMetrics ? 
            (prev.averageResponseTime + responseTime) / 2 : prev.averageResponseTime
        };

        return {
          ...newMetrics,
          healthScore: calculateHealthScore(newMetrics)
        };
      });

      return isHealthy;
    } catch (error) {
      console.error('Health check failed:', error);
      
      setHealthMetrics(prev => {
        const newMetrics = {
          ...prev,
          lastHealthCheck: new Date(),
          consecutiveFailures: prev.consecutiveFailures + 1
        };

        return {
          ...newMetrics,
          healthScore: calculateHealthScore(newMetrics)
        };
      });

      return false;
    }
  }, [isSignedIn, userId, enhancedHealthCheck, fullConfig.enableMetrics, calculateHealthScore]);

  // Force refresh (bypasses caching)
  const forceRefresh = useCallback(async (): Promise<void> => {
    tokenCache.current = null;
    await refreshToken();
  }, [refreshToken]);

  // Invalidate session
  const invalidateSession = useCallback(() => {
    tokenCache.current = null;
    forceReauthentication();
  }, [forceReauthentication]);

  // Get time until token expiry
  const getTimeUntilExpiry = useCallback((): number | null => {
    if (!tokenCache.current) {
      return null;
    }

    return tokenCache.current.expiry.getTime() - Date.now();
  }, []);

  // Get session age
  const getSessionAge = useCallback((): number | null => {
    if (!lastTokenRefresh) {
      return null;
    }

    return Date.now() - lastTokenRefresh.getTime();
  }, [lastTokenRefresh]);

  // Check if token should be refreshed
  const shouldRefreshToken = useCallback((): boolean => {
    const timeUntilExpiry = getTimeUntilExpiry();
    
    if (timeUntilExpiry === null) {
      return true; // No cached token, should refresh
    }

    return timeUntilExpiry < fullConfig.tokenRefreshThreshold;
  }, [getTimeUntilExpiry, fullConfig.tokenRefreshThreshold]);

  // Setup periodic health checks
  useEffect(() => {
    if (!isSignedIn || !userId) {
      return;
    }

    // Initial health check
    checkSessionHealth();

    // Setup interval for periodic checks
    healthCheckInterval.current = setInterval(
      checkSessionHealth,
      fullConfig.healthCheckInterval
    );

    return () => {
      if (healthCheckInterval.current) {
        clearInterval(healthCheckInterval.current);
        healthCheckInterval.current = null;
      }
    };
  }, [isSignedIn, userId, checkSessionHealth, fullConfig.healthCheckInterval]);

  // Automatic token refresh based on expiry
  useEffect(() => {
    if (!isSignedIn || !userId) {
      return;
    }

    const checkAndRefresh = () => {
      if (shouldRefreshToken()) {
        refreshToken();
      }
    };

    // Check every minute
    const refreshCheckInterval = setInterval(checkAndRefresh, 60 * 1000);

    return () => {
      clearInterval(refreshCheckInterval);
    };
  }, [isSignedIn, userId, shouldRefreshToken, refreshToken]);

  // Session recovery on focus
  useEffect(() => {
    const handleFocus = () => {
      if (isSignedIn && userId) {
        checkSessionHealth();
        
        if (shouldRefreshToken()) {
          refreshToken();
        }
      }
    };

    window.addEventListener('focus', handleFocus);

    return () => {
      window.removeEventListener('focus', handleFocus);
    };
  }, [isSignedIn, userId, checkSessionHealth, shouldRefreshToken, refreshToken]);

  const isSessionHealthy = sessionStatus === 'active' && 
                          healthMetrics.healthScore > 50 && 
                          healthMetrics.consecutiveFailures < fullConfig.maxConsecutiveFailures;

  return {
    // Session state
    isSessionHealthy,
    sessionHealth: healthMetrics,
    lastTokenRefresh,
    sessionStatus,
    
    // Actions
    refreshToken,
    checkSessionHealth,
    forceRefresh,
    invalidateSession,
    
    // Utilities
    getTimeUntilExpiry,
    getSessionAge,
    shouldRefreshToken
  };
} 