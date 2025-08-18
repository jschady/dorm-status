'use client';

import React, { Component, ReactNode } from 'react';

interface AuthErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
  retryCount: number;
  isRetrying: boolean;
}

interface AuthErrorBoundaryProps {
  children: ReactNode;
  fallback?: (error: Error, retry: () => void) => ReactNode;
  maxRetries?: number;
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
}

class AuthErrorBoundary extends Component<AuthErrorBoundaryProps, AuthErrorBoundaryState> {
  private retryTimer: NodeJS.Timeout | null = null;

  constructor(props: AuthErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: 0,
      isRetrying: false
    };
  }

  static getDerivedStateFromError(error: Error): Partial<AuthErrorBoundaryState> {
    return {
      hasError: true,
      error
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Authentication Error Boundary caught an error:', error, errorInfo);
    
    this.setState({
      error,
      errorInfo
    });

    // Call custom error handler if provided
    this.props.onError?.(error, errorInfo);

    // Auto-retry for certain types of errors
    if (this.shouldAutoRetry(error) && this.state.retryCount < (this.props.maxRetries || 3)) {
      this.scheduleRetry();
    }
  }

  shouldAutoRetry = (error: Error): boolean => {
    const retryableErrors = [
      'network error',
      'timeout',
      'connection failed',
      'service unavailable',
      'token refresh failed'
    ];

    return retryableErrors.some(pattern => 
      error.message.toLowerCase().includes(pattern)
    );
  };

  scheduleRetry = () => {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
    }

    this.setState({ isRetrying: true });

    // Exponential backoff: 1s, 2s, 4s
    const delay = Math.min(1000 * Math.pow(2, this.state.retryCount), 10000);

    this.retryTimer = setTimeout(() => {
      this.handleRetry();
    }, delay);
  };

  handleRetry = () => {
    this.setState(prevState => ({
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: prevState.retryCount + 1,
      isRetrying: false
    }));
  };

  handleManualRetry = () => {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
    }

    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      isRetrying: false
    });
  };

  handleForceReload = () => {
    window.location.reload();
  };

  handleGoToSignIn = () => {
    window.location.href = '/sign-in';
  };

  componentWillUnmount() {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
    }
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    const { error } = this.state;
    const isNetworkError = error?.message.toLowerCase().includes('network') || 
                          error?.message.toLowerCase().includes('connection');
    const isAuthError = error?.message.toLowerCase().includes('auth') || 
                       error?.message.toLowerCase().includes('token') ||
                       error?.message.toLowerCase().includes('session');

    // Use custom fallback if provided
    if (this.props.fallback) {
      return this.props.fallback(error!, this.handleManualRetry);
    }

    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
        <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-6 text-center">
          {/* Error Icon */}
          <div className="flex justify-center mb-4">
            <div className="h-12 w-12 text-red-500 flex items-center justify-center text-2xl">
              ⚠️
            </div>
          </div>

          {/* Error Title */}
          <h1 className="text-xl font-semibold text-gray-900 mb-2">
            {isNetworkError && 'Connection Problem'}
            {isAuthError && 'Authentication Error'}
            {!isNetworkError && !isAuthError && 'Something Went Wrong'}
          </h1>

          {/* Error Message */}
          <p className="text-gray-600 mb-6">
            {isNetworkError && 'Unable to connect to our servers. Please check your internet connection and try again.'}
            {isAuthError && 'There was a problem with your authentication session. You may need to sign in again.'}
            {!isNetworkError && !isAuthError && 'An unexpected error occurred. Please try refreshing the page or signing in again.'}
          </p>

          {/* Connection Status */}
          <div className="flex items-center justify-center mb-6 text-sm">
            {navigator.onLine ? (
              <div className="flex items-center text-green-600">
                <span className="mr-2">📶</span>
                Internet Connected
              </div>
            ) : (
              <div className="flex items-center text-red-600">
                <span className="mr-2">📵</span>
                No Internet Connection
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="space-y-3">
            {/* Retry Button */}
            <button
              onClick={this.handleManualRetry}
              disabled={this.state.isRetrying}
              className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-400 text-white font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
            >
              {this.state.isRetrying ? (
                <>
                  <span className="mr-2 animate-spin">🔄</span>
                  Retrying...
                </>
              ) : (
                <>
                  <span className="mr-2">🔄</span>
                  Try Again
                </>
              )}
            </button>

            {/* Sign In Button (for auth errors) */}
            {isAuthError && (
              <button
                onClick={this.handleGoToSignIn}
                className="w-full bg-gray-100 hover:bg-gray-200 text-gray-800 font-medium py-2 px-4 rounded-md transition-colors flex items-center justify-center"
              >
                <span className="mr-2">🔑</span>
                Sign In Again
              </button>
            )}

            {/* Reload Page Button */}
            <button
              onClick={this.handleForceReload}
              className="w-full bg-gray-100 hover:bg-gray-200 text-gray-800 font-medium py-2 px-4 rounded-md transition-colors"
            >
              Reload Page
            </button>
          </div>

          {/* Error Details (Development Only) */}
          {process.env.NODE_ENV === 'development' && error && (
            <details className="mt-6 text-left">
              <summary className="text-sm font-medium text-gray-700 cursor-pointer">
                Error Details
              </summary>
              <div className="mt-2 p-3 bg-gray-100 rounded text-xs font-mono text-gray-800 whitespace-pre-wrap">
                {error.toString()}
                {this.state.errorInfo?.componentStack && (
                  <>
                    {'\n\nComponent Stack:'}
                    {this.state.errorInfo.componentStack}
                  </>
                )}
              </div>
            </details>
          )}

          {/* Retry Counter */}
          {this.state.retryCount > 0 && (
            <p className="mt-4 text-xs text-gray-500">
              Retry attempts: {this.state.retryCount} / {this.props.maxRetries || 3}
            </p>
          )}
        </div>
      </div>
    );
  }
}

// HOC for wrapping components with auth error boundary
export function withAuthErrorBoundary<T extends {}>(
  WrappedComponent: React.ComponentType<T>,
  errorBoundaryProps?: Omit<AuthErrorBoundaryProps, 'children'>
) {
  return function AuthErrorBoundaryWrapper(props: T) {
    return (
      <AuthErrorBoundary {...errorBoundaryProps}>
        <WrappedComponent {...props} />
      </AuthErrorBoundary>
    );
  };
}

// Hook for triggering auth errors from components
export function useAuthErrorHandler() {
  return {
    triggerAuthError: (error: Error) => {
      // This will be caught by the nearest AuthErrorBoundary
      throw error;
    },
    triggerNetworkError: () => {
      throw new Error('Network error: Unable to connect to authentication service');
    },
    triggerSessionError: () => {
      throw new Error('Authentication session expired');
    }
  };
}

export default AuthErrorBoundary; 