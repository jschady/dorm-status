// Service Worker for Tiger Dorm PWA - Next.js 15+ Optimized with Authentication

// DEVELOPMENT FLAG - Set to true to disable all caching for testing
const DISABLE_CACHE_FOR_TESTING = true; // Change to false to re-enable caching

const CACHE_NAME = 'tigerdorm-v4'; // Updated for authentication features
const STATIC_CACHE = 'tigerdorm-static-v4'; // Updated for authentication features
const API_CACHE = 'tigerdorm-api-v2';
const AUTH_CACHE = 'tigerdorm-auth-v1';

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

// Files to cache for offline functionality
const STATIC_FILES = [
  '/',
  '/manifest.json',
  '/icon-192x192.png',
  '/icon-256x256.png',
  '/icon-384x384.png',
  '/icon-512x512.png'
];

// Next.js specific routes to cache
const NEXT_JS_ROUTES = [
  '/_next/static/',
  '/_next/image'
];

// Cache strategies
const CACHE_STRATEGIES = {
  CACHE_FIRST: 'cache-first',
  NETWORK_FIRST: 'network-first',
  STALE_WHILE_REVALIDATE: 'stale-while-revalidate'
};

// Install event - cache static files
self.addEventListener('install', (event) => {
  console.log('Service Worker: Installing');
  
  if (DISABLE_CACHE_FOR_TESTING) {
    console.log('Service Worker: Caching disabled for testing, skipping initial cache');
    event.waitUntil(self.skipWaiting());
    return;
  }
  
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('Service Worker: Caching static files');
        return cache.addAll(STATIC_FILES);
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('Service Worker: Activating');
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            // Keep current caches
            if (cacheName !== CACHE_NAME && 
                cacheName !== STATIC_CACHE && 
                cacheName !== API_CACHE && 
                cacheName !== AUTH_CACHE) {
              console.log('Service Worker: Deleting old cache', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => {
        // Initialize auth state on activation
        console.log('Service Worker: Initialized with auth support');
        return self.clients.claim();
      })
  );
});

// Fetch event - enhanced caching strategies for Next.js 15+
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

  // BYPASS CACHING FOR TESTING - Always fetch from network
  if (DISABLE_CACHE_FOR_TESTING) {
    console.log('Service Worker: Caching disabled for testing, fetching from network:', event.request.url);
    event.respondWith(fetch(event.request));
    return;
  }

  event.respondWith(handleFetchRequest(event.request));
});

// Enhanced fetch handler with authentication-aware caching strategies
async function handleFetchRequest(request) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  
  // Handle authentication-protected routes
  if (isAuthProtectedRoute(pathname)) {
    return handleProtectedRoute(request);
  }
  
  // Handle public routes
  if (isPublicRoute(pathname)) {
    return handlePublicRoute(request);
  }
  
  // Next.js static assets - Cache First
  if (isStaticAsset(pathname)) {
    return cacheFirst(request, STATIC_CACHE);
  }

  // Next.js build assets - Cache First with long TTL
  if (pathname.startsWith('/_next/static/')) {
    return cacheFirst(request, CACHE_NAME);
  }

  // Images - Stale While Revalidate
  if (request.destination === 'image' || pathname.match(/\.(jpg|jpeg|png|gif|webp|svg|ico)$/)) {
    return staleWhileRevalidate(request, CACHE_NAME);
  }

  // App pages - Network First (for fresh content, cache as fallback)
  if (request.destination === 'document') {
    return networkFirst(request, CACHE_NAME);
  }

  // Default: Network First
  return networkFirst(request, CACHE_NAME);
}

// Handle authentication-protected routes
async function handleProtectedRoute(request) {
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
  
  // Session is valid, proceed with network-first strategy
  // Don't cache protected content for security
  try {
    const response = await fetch(request);
    
    // If 401/403, session might be expired on server
    if (response.status === 401 || response.status === 403) {
      handleSessionExpired();
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

// Handle public routes
async function handlePublicRoute(request) {
  // Public routes can use normal caching strategies
  if (request.destination === 'document') {
    return networkFirst(request, CACHE_NAME);
  }
  
  return networkFirst(request, CACHE_NAME);
}

// Check if request is for static assets
function isStaticAsset(pathname) {
  return STATIC_FILES.some(file => pathname === file) ||
         pathname.startsWith('/icon-') ||
         pathname === '/manifest.json' ||
         pathname === '/favicon.ico';
}

// Cache First strategy - serve from cache, fallback to network
async function cacheFirst(request, cacheName) {
  try {
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }

    const response = await fetch(request);
    if (response.status === 200) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    console.error('Cache first strategy failed:', error);
    return new Response('Service Unavailable', { status: 503 });
  }
}

// Network First strategy - try network, fallback to cache
async function networkFirst(request, cacheName) {
  try {
    const response = await fetch(request);
    if (response.status === 200) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    console.log('Network failed, serving from cache:', request.url);
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }

    // If requesting a document and no cache, serve offline page
    if (request.destination === 'document') {
      return getOfflinePage();
    }

    return new Response('Service Unavailable', { status: 503 });
  }
}

// Stale While Revalidate strategy - serve cached, update in background
async function staleWhileRevalidate(request, cacheName) {
  const cachedResponse = await caches.match(request);
  
  const fetchPromise = fetch(request).then(response => {
    if (response.status === 200) {
      const cache = caches.open(cacheName);
      cache.then(c => c.put(request, response.clone()));
    }
    return response;
  }).catch(error => {
    console.error('Background fetch failed:', error);
    return cachedResponse || new Response('Service Unavailable', { status: 503 });
  });

  return cachedResponse || fetchPromise;
}

// Get offline page response
function getOfflinePage() {
  return new Response(
    `<!DOCTYPE html>
    <html lang="en">
    <head>
      <title>TigerDorm - Offline</title>
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
        .offline-container { max-width: 400px; }
        .icon { font-size: 4rem; margin-bottom: 1rem; }
        h1 { color: #fbbf24; margin-bottom: 1rem; font-size: 2rem; }
        p { color: #9ca3af; line-height: 1.6; margin-bottom: 1rem; }
        .retry-btn {
          background: #4f46e5;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 0.5rem;
          cursor: pointer;
          margin-top: 1rem;
          font-size: 1rem;
          font-weight: 600;
          transition: background 0.2s;
        }
        .retry-btn:hover { background: #4338ca; }
        .status-indicator {
          display: inline-block;
          width: 8px;
          height: 8px;
          background: #ef4444;
          border-radius: 50%;
          margin-right: 8px;
        }
      </style>
    </head>
    <body>
      <div class="offline-container">
        <div class="icon">📱</div>
        <h1>You're Offline</h1>
        <p><span class="status-indicator"></span>No internet connection</p>
        <p>TigerDorm needs an internet connection to sync status updates in real-time.</p>
        <p>Your cached data is still available, but updates won't sync until you're back online.</p>
        <button class="retry-btn" onclick="window.location.reload()">Try Again</button>
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

// Get offline authentication page response
function getOfflineAuthPage() {
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

// Handle messages from main thread (including auth state updates)
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
function updateAuthState(newState) {
  authState = {
    ...authState,
    ...newState,
    lastAuthCheck: Date.now()
  };
  console.log('Service Worker: Auth state updated', authState);
}

// Handle token refresh
async function handleTokenRefresh(tokenData) {
  if (tokenData && tokenData.token) {
    authState.sessionExpiry = tokenData.expiry || Date.now() + (60 * 60 * 1000); // Default 1 hour
    console.log('Service Worker: Token refreshed, new expiry:', new Date(authState.sessionExpiry));
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
    await caches.delete(AUTH_CACHE);
    console.log('Service Worker: Cleared auth cache');
  } catch (error) {
    console.error('Service Worker: Failed to clear auth cache:', error);
  }
}

// Check if route requires authentication
function isAuthProtectedRoute(pathname) {
  return AUTH_PROTECTED_ROUTES.some(route => pathname.startsWith(route));
}

// Check if route is public
function isPublicRoute(pathname) {
  return PUBLIC_ROUTES.some(route => 
    pathname === route || pathname.startsWith(route + '/')
  );
}

// Enhanced authentication check
function isSessionValid() {
  if (!authState.isAuthenticated || !authState.userId) {
    return false;
  }
  
  if (authState.sessionExpiry && Date.now() >= authState.sessionExpiry) {
    console.log('Service Worker: Session expired');
    return false;
  }
  
  return true;
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

// Handle push notifications (for future use)
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
    clients.openWindow('/')
  );
});

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