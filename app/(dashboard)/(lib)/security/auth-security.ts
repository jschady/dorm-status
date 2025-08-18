'use client';

import { useAuth } from '@clerk/nextjs';

interface SecurityEvent {
  eventType: 'LOGIN' | 'LOGOUT' | 'TOKEN_REFRESH' | 'SESSION_EXPIRED' | 'SUSPICIOUS_ACTIVITY' | 'ERROR';
  userId?: string;
  sessionId?: string;
  ip?: string;
  userAgent?: string;
  timestamp: Date;
  details?: Record<string, any>;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

interface SecurityMetrics {
  failedAttempts: number;
  lastFailure: Date | null;
  isBlocked: boolean;
  blockUntil: Date | null;
  riskScore: number; // 0-100
}

interface SecurityConfig {
  maxFailedAttempts: number;
  blockDuration: number; // milliseconds
  tokenLifetime: number; // milliseconds
  enableAuditLogging: boolean;
  enableRiskAnalysis: boolean;
  enableCSRFProtection: boolean;
}

const DEFAULT_SECURITY_CONFIG: SecurityConfig = {
  maxFailedAttempts: 5,
  blockDuration: 15 * 60 * 1000, // 15 minutes
  tokenLifetime: 60 * 60 * 1000, // 1 hour
  enableAuditLogging: true,
  enableRiskAnalysis: true,
  enableCSRFProtection: true
};

class AuthSecurityManager {
  private config: SecurityConfig;
  private metrics: Map<string, SecurityMetrics> = new Map();
  private auditLog: SecurityEvent[] = [];
  private maxAuditLogSize = 1000;

  constructor(config: Partial<SecurityConfig> = {}) {
    this.config = { ...DEFAULT_SECURITY_CONFIG, ...config };
  }

  // Log security events
  logEvent(event: Omit<SecurityEvent, 'timestamp'>): void {
    const securityEvent: SecurityEvent = {
      ...event,
      timestamp: new Date()
    };

    if (this.config.enableAuditLogging) {
      this.auditLog.unshift(securityEvent);
      
      // Maintain audit log size
      if (this.auditLog.length > this.maxAuditLogSize) {
        this.auditLog = this.auditLog.slice(0, this.maxAuditLogSize);
      }

      // In production, send to external logging service
      if (process.env.NODE_ENV === 'production') {
        this.sendToLoggingService(securityEvent);
      }

      console.log('Security Event:', securityEvent);
    }
  }

  // Send to external logging service (placeholder)
  private async sendToLoggingService(event: SecurityEvent): Promise<void> {
    try {
      // Example: send to DataDog, LogRocket, or custom logging endpoint
      // await fetch('/api/security/log', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(event)
      // });
    } catch (error) {
      console.error('Failed to send security event to logging service:', error);
    }
  }

  // Update security metrics for a user
  updateMetrics(userId: string, eventType: SecurityEvent['eventType']): void {
    const metrics = this.metrics.get(userId) || {
      failedAttempts: 0,
      lastFailure: null,
      isBlocked: false,
      blockUntil: null,
      riskScore: 0
    };

    switch (eventType) {
      case 'LOGIN':
        // Reset failed attempts on successful login
        metrics.failedAttempts = 0;
        metrics.isBlocked = false;
        metrics.blockUntil = null;
        metrics.riskScore = Math.max(0, metrics.riskScore - 10);
        break;

      case 'ERROR':
      case 'SUSPICIOUS_ACTIVITY':
        metrics.failedAttempts++;
        metrics.lastFailure = new Date();
        metrics.riskScore = Math.min(100, metrics.riskScore + 15);

        // Check if user should be blocked
        if (metrics.failedAttempts >= this.config.maxFailedAttempts) {
          metrics.isBlocked = true;
          metrics.blockUntil = new Date(Date.now() + this.config.blockDuration);
        }
        break;

      case 'SESSION_EXPIRED':
        metrics.riskScore = Math.min(100, metrics.riskScore + 5);
        break;
    }

    // Auto-unblock if block period has passed
    if (metrics.blockUntil && Date.now() > metrics.blockUntil.getTime()) {
      metrics.isBlocked = false;
      metrics.blockUntil = null;
    }

    this.metrics.set(userId, metrics);
  }

  // Check if user is blocked
  isUserBlocked(userId: string): boolean {
    const metrics = this.metrics.get(userId);
    if (!metrics) return false;

    if (metrics.blockUntil && Date.now() > metrics.blockUntil.getTime()) {
      metrics.isBlocked = false;
      metrics.blockUntil = null;
      return false;
    }

    return metrics.isBlocked;
  }

  // Get user risk score
  getUserRiskScore(userId: string): number {
    const metrics = this.metrics.get(userId);
    return metrics?.riskScore || 0;
  }

  // Generate CSRF token
  generateCSRFToken(): string {
    if (!this.config.enableCSRFProtection) return '';

    const array = new Uint32Array(8);
    crypto.getRandomValues(array);
    return Array.from(array, dec => dec.toString(16)).join('');
  }

  // Validate CSRF token
  validateCSRFToken(token: string, storedToken: string): boolean {
    if (!this.config.enableCSRFProtection) return true;
    return token === storedToken;
  }

  // Analyze request for suspicious activity
  analyzeRequest(request: {
    userAgent?: string;
    ip?: string;
    timestamp: Date;
    userId?: string;
  }): { isSuspicious: boolean; riskFactors: string[] } {
    if (!this.config.enableRiskAnalysis) {
      return { isSuspicious: false, riskFactors: [] };
    }

    const riskFactors: string[] = [];

    // Check for suspicious user agent
    if (request.userAgent) {
      const suspiciousPatterns = [
        /bot/i,
        /crawler/i,
        /spider/i,
        /automated/i,
        /script/i
      ];

      if (suspiciousPatterns.some(pattern => pattern.test(request.userAgent!))) {
        riskFactors.push('Suspicious user agent');
      }

      // Check for missing or unusual user agent
      if (request.userAgent.length < 10 || request.userAgent.length > 500) {
        riskFactors.push('Unusual user agent length');
      }
    } else {
      riskFactors.push('Missing user agent');
    }

    // Check for rapid requests (potential brute force)
    if (request.userId) {
      const metrics = this.metrics.get(request.userId);
      if (metrics?.lastFailure) {
        const timeSinceLastFailure = Date.now() - metrics.lastFailure.getTime();
        if (timeSinceLastFailure < 1000) { // Less than 1 second
          riskFactors.push('Rapid successive requests');
        }
      }
    }

    // Check for unusual time patterns
    const hour = request.timestamp.getHours();
    if (hour < 6 || hour > 23) { // Late night/early morning activity
      riskFactors.push('Unusual time pattern');
    }

    return {
      isSuspicious: riskFactors.length > 0,
      riskFactors
    };
  }

  // Get security headers
  getSecurityHeaders(): Record<string, string> {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(self), microphone=(), camera=()',
      ...(this.config.enableCSRFProtection && {
        'X-CSRF-Protection': 'enabled'
      })
    };
  }

  // Get audit log
  getAuditLog(userId?: string, eventType?: SecurityEvent['eventType']): SecurityEvent[] {
    let filteredLog = this.auditLog;

    if (userId) {
      filteredLog = filteredLog.filter(event => event.userId === userId);
    }

    if (eventType) {
      filteredLog = filteredLog.filter(event => event.eventType === eventType);
    }

    return filteredLog.slice(0, 100); // Return last 100 events
  }

  // Clear user metrics (admin function)
  clearUserMetrics(userId: string): void {
    this.metrics.delete(userId);
    this.logEvent({
      eventType: 'SUSPICIOUS_ACTIVITY',
      userId,
      details: { action: 'metrics_cleared_by_admin' },
      riskLevel: 'LOW'
    });
  }

  // Get security summary
  getSecuritySummary(): {
    totalEvents: number;
    blockedUsers: number;
    highRiskUsers: number;
    recentSuspiciousActivity: number;
  } {
    const blockedUsers = Array.from(this.metrics.values()).filter(m => m.isBlocked).length;
    const highRiskUsers = Array.from(this.metrics.values()).filter(m => m.riskScore > 70).length;
    const recentSuspiciousActivity = this.auditLog.filter(
      event => event.timestamp > new Date(Date.now() - 24 * 60 * 60 * 1000) && // Last 24 hours
               event.eventType === 'SUSPICIOUS_ACTIVITY'
    ).length;

    return {
      totalEvents: this.auditLog.length,
      blockedUsers,
      highRiskUsers,
      recentSuspiciousActivity
    };
  }
}

// Global security manager instance
const securityManager = new AuthSecurityManager();

// React hook for using security features
export function useAuthSecurity() {
  const { userId } = useAuth();

  const logSecurityEvent = (
    eventType: SecurityEvent['eventType'],
    details?: Record<string, any>,
    riskLevel: SecurityEvent['riskLevel'] = 'LOW'
  ) => {
    securityManager.logEvent({
      eventType,
      userId: userId || undefined,
      details,
      riskLevel,
      userAgent: navigator.userAgent,
      ip: 'client-side' // In production, get from server
    });

    if (userId) {
      securityManager.updateMetrics(userId, eventType);
    }
  };

  const isBlocked = userId ? securityManager.isUserBlocked(userId) : false;
  const riskScore = userId ? securityManager.getUserRiskScore(userId) : 0;

  return {
    // Actions
    logSecurityEvent,
    generateCSRFToken: () => securityManager.generateCSRFToken(),
    validateCSRFToken: (token: string, stored: string) => 
      securityManager.validateCSRFToken(token, stored),
    analyzeRequest: (request: Parameters<typeof securityManager.analyzeRequest>[0]) =>
      securityManager.analyzeRequest(request),
    
    // State
    isBlocked,
    riskScore,
    
    // Utilities
    getAuditLog: (eventType?: SecurityEvent['eventType']) =>
      securityManager.getAuditLog(userId || undefined, eventType),
    getSecurityHeaders: () => securityManager.getSecurityHeaders(),
    getSecuritySummary: () => securityManager.getSecuritySummary()
  };
}

export { AuthSecurityManager, securityManager };
export type { SecurityEvent, SecurityMetrics, SecurityConfig }; 