import { defaultCache } from "@serwist/next/worker";
import type { PrecacheEntry, SerwistGlobalConfig } from "serwist";
import { Serwist } from "serwist";

// This declares the value of `injectionPoint` to TypeScript.
// `injectionPoint` is the string that will be replaced by the
// actual precache manifest. By default, this string is set to
// `"self.__SW_MANIFEST"`.
declare global {
  interface WorkerGlobalScope extends SerwistGlobalConfig {
    __SW_MANIFEST: (PrecacheEntry | string)[] | undefined;
  }
}

declare const self: ServiceWorkerGlobalScope;

// Authentication state management
let authState = {
  isAuthenticated: false,
  userId: null,
  sessionExpiry: null,
  lastAuthCheck: null
};

// Authentication-related routes that should not be cached
const AUTH_PROTECTED_ROUTES = [
  '/dashboard',
  '/create',
  '/api'
];

const PUBLIC_ROUTES = [
  '/',
  '/join',
  '/sign-in',
  '/sign-up'
];

const serwist = new Serwist({
  precacheEntries: self.__SW_MANIFEST,
  skipWaiting: true,
  clientsClaim: true,
  navigationPreload: true,
  disableDevLogs: false,
  runtimeCaching: defaultCache,
});

// Add Serwist event listeners
serwist.addEventListeners();

// Custom fetch event listener for authentication-aware handling
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  const url = new URL(event.request.url);

  // Skip Supabase API requests for real-time functionality
  if (url.hostname.includes('supabase.co')) {
    return;
  }

  // Skip Chrome extensions
  if (url.protocol === 'chrome-extension:' || url.protocol === 'moz-extension:') {
    return;
  }

  // Handle authentication-protected routes
  if (isAuthProtectedRoute(url.pathname)) {
    event.respondWith(handleProtectedRoute(event.request));
    return;
  }

  // Let Serwist handle other routes with default caching
});

// Custom event listeners for authentication and enhanced functionality

// Handle authentication-protected routes
async function handleProtectedRoute(request: Request): Promise<Response> {
  const url = new URL(request.url);
  
  // Check if session is valid
  if (!isSessionValid()) {
    console.log('Service Worker: Invalid session for protected route:', url.pathname);
    
    // For API requests, return 401
    if (url.pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Authentication required',
        code: 'SESSION_EXPIRED'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // For page requests, redirect to sign-in
    if (request.destination === 'document') {
      const signInUrl = new URL('/sign-in', url.origin);
      signInUrl.searchParams.set('redirectTo', url.pathname);
      
      return Response.redirect(signInUrl.toString(), 302);
    }
  }
  
  // Session is valid, proceed with network request
  try {
    const response = await fetch(request);
    
    // If 401/403, session might be expired on server
    if (response.status === 401 || response.status === 403) {
      await handleSessionExpired();
    }
    
    return response;
  } catch (error) {
    console.error('Service Worker: Protected route fetch failed:', error);
    
    // For offline scenarios, return appropriate error
    if (request.destination === 'document') {
      return getOfflineAuthPage();
    }
    
    return new Response(JSON.stringify({
      error: 'Service Unavailable',
      message: 'Unable to connect to server',
      code: 'NETWORK_ERROR'
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Enhanced message handling for authentication state
self.addEventListener('message', (event) => {
  console.log('Service Worker: Message received', event.data);
  
  const { type, data } = event.data;
  
  switch (type) {
    case 'AUTH_STATE_UPDATE':
      updateAuthState(data);
      break;
    case 'TOKEN_REFRESH':
      handleTokenRefresh(data);
      break;
    case 'SESSION_EXPIRED':
      handleSessionExpired();
      break;
    case 'CLEAR_AUTH_CACHE':
      clearAuthRelatedCaches();
      break;
    default:
      console.log('Service Worker: Unknown message type:', type);
  }
});

// Update authentication state
function updateAuthState(newState: any) {
  authState = {
    ...authState,
    ...newState,
    lastAuthCheck: Date.now()
  };
  console.log('Service Worker: Auth state updated', authState);
}

// Handle token refresh
async function handleTokenRefresh(tokenData: any) {
  if (tokenData && tokenData.token) {
    authState.sessionExpiry = tokenData.expiry || Date.now() + (60 * 60 * 1000); // Default 1 hour
    console.log('Service Worker: Token refreshed, new expiry:', new Date(authState.sessionExpiry!));
  }
}

// Handle session expiration
async function handleSessionExpired() {
  console.log('Service Worker: Session expired, clearing auth state');
  authState.isAuthenticated = false;
  authState.userId = null;
  authState.sessionExpiry = null;
  
  // Clear auth-related caches
  await clearAuthRelatedCaches();
  
  // Notify all clients about session expiration
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({
      type: 'SESSION_EXPIRED_IN_SW',
      timestamp: Date.now()
    });
  });
}

// Clear authentication-related caches
async function clearAuthRelatedCaches() {
  try {
    const cacheNames = await caches.keys();
    const authCacheNames = cacheNames.filter(name => 
      name.includes('api') || name.includes('auth')
    );
    
    await Promise.all(
      authCacheNames.map(cacheName => caches.delete(cacheName))
    );
    
    console.log('Service Worker: Cleared auth caches:', authCacheNames);
  } catch (error) {
    console.error('Service Worker: Failed to clear auth cache:', error);
  }
}

// Check if route requires authentication
function isAuthProtectedRoute(pathname: string): boolean {
  return AUTH_PROTECTED_ROUTES.some(route => pathname.startsWith(route));
}

// Check if route is public
function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some(route => 
    pathname === route || pathname.startsWith(route + '/')
  );
}

// Enhanced authentication check
function isSessionValid(): boolean {
  if (!authState.isAuthenticated || !authState.userId) {
    return false;
  }
  
  if (authState.sessionExpiry && Date.now() >= authState.sessionExpiry) {
    console.log('Service Worker: Session expired');
    return false;
  }
  
  return true;
}

// Get offline authentication page response
function getOfflineAuthPage(): Response {
  return new Response(
    `<!DOCTYPE html>
    <html lang="en">
    <head>
      <title>TigerDorm - Authentication Required</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="theme-color" content="#4f46e5">
      <style>
        body { 
          font-family: system-ui, -apple-system, sans-serif; 
          background: #111827; 
          color: white; 
          display: flex; 
          align-items: center; 
          justify-content: center; 
          min-height: 100vh; 
          margin: 0;
          text-align: center;
          padding: 2rem;
        }
        .auth-container { max-width: 400px; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #f59e0b; margin-bottom: 1rem; font-size: 2rem; }
        p { color: #9ca3af; line-height: 1.6; margin-bottom: 1rem; }
        .auth-btn {
          background: #4f46e5;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 0.5rem;
          cursor: pointer;
          margin: 0.5rem;
          font-size: 1rem;
          font-weight: 600;
          transition: background 0.2s;
          text-decoration: none;
          display: inline-block;
        }
        .auth-btn:hover { background: #4338ca; }
        .status-indicator {
          display: inline-block;
          width: 8px;
          height: 8px;
          background: #f59e0b;
          border-radius: 50%;
          margin-right: 8px;
        }
      </style>
    </head>
    <body>
      <div class="auth-container">
        <div class="icon">🔐</div>
        <h1>Authentication Required</h1>
        <p><span class="status-indicator"></span>Session expired or invalid</p>
        <p>You need to be signed in to access this content.</p>
        <p>Please connect to the internet and sign in to continue.</p>
        <a href="/sign-in" class="auth-btn">Sign In</a>
        <button class="auth-btn" onclick="window.location.reload()">Retry</button>
      </div>
      <script>
        // Auto-reload when connection is restored
        window.addEventListener('online', () => {
          setTimeout(() => window.location.reload(), 1000);
        });
      </script>
    </body>
    </html>`,
    { 
      headers: { 
        'Content-Type': 'text/html',
        'Cache-Control': 'no-cache'
      } 
    }
  );
}

// Handle background sync for status updates (when back online)
self.addEventListener('sync', (event) => {
  console.log('Service Worker: Background sync triggered');
  
  if (event.tag === 'status-update') {
    event.waitUntil(syncStatusUpdates());
  } else if (event.tag === 'auth-refresh') {
    event.waitUntil(syncAuthState());
  }
});

// Sync authentication state
async function syncAuthState() {
  try {
    console.log('Service Worker: Syncing auth state');
    
    // Notify main thread to check auth state
    const clients = await self.clients.matchAll();
    clients.forEach(client => {
      client.postMessage({
        type: 'REQUEST_AUTH_REFRESH',
        timestamp: Date.now()
      });
    });
  } catch (error) {
    console.error('Service Worker: Auth sync failed', error);
  }
}

// Sync function for offline status updates
async function syncStatusUpdates() {
  try {
    // This would sync any pending status updates stored in IndexedDB
    console.log('Service Worker: Syncing status updates');
    // Implementation would depend on offline storage strategy
  } catch (error) {
    console.error('Service Worker: Sync failed', error);
  }
}

// Handle push notifications
self.addEventListener('push', (event) => {
  console.log('Service Worker: Push received');
  
  if (!event.data) return;

  const data = event.data.json();
  const options = {
    body: data.body,
    icon: '/icon-192x192.png?v=3',
    badge: '/icon-192x192.png?v=3',
    vibrate: [200, 100, 200],
    data: data.data || {},
    actions: [
      {
        action: 'view',
        title: 'View Status',
        icon: '/icon-192x192.png?v=3'
      }
    ]
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'TigerDorm', options)
  );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
  console.log('Service Worker: Notification clicked');
  
  event.notification.close();
  
  event.waitUntil(
    self.clients.openWindow('/')
  );
}); 