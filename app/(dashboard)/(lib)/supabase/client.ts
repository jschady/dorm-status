import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { useAuth } from '@clerk/nextjs';
import { useMemo } from 'react';
import { Database } from '../types';

/**
 * Centralized Supabase Client Management
 * 
 * This module provides a single source of truth for all Supabase client creation
 * with proper separation of concerns for different use cases:
 * - Client-side components with Clerk authentication
 * - Server-side components and Server Actions
 * - Admin operations and webhooks
 */

// Environment variable validation
const validateEnvironmentVariables = () => {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl) {
    throw new Error(
      '❌ Missing NEXT_PUBLIC_SUPABASE_URL environment variable.\n' +
      'Please add it to your .env.local file.\n' +
      'You can find this in your Supabase project settings.'
    );
  }

  if (!supabaseAnonKey) {
    throw new Error(
      '❌ Missing NEXT_PUBLIC_SUPABASE_ANON_KEY environment variable.\n' +
      'Please add it to your .env.local file.\n' +
      'You can find this in your Supabase project API settings.'
    );
  }

  return { supabaseUrl, supabaseAnonKey, supabaseServiceKey };
};

/**
 * Client-side Supabase hook with Clerk JWT integration
 * 
 * Use this hook in client components that need to interact with Supabase.
 * It automatically handles Clerk authentication and provides RLS-enabled access.
 * 
 * @example
 * ```tsx
 * 'use client';
 * 
 * function MyComponent() {
 *   const supabase = useSupabase();
 *   
 *   const fetchData = async () => {
 *     const { data, error } = await supabase
 *       .from('geofences')
 *       .select('*');
 *   };
 *   
 *   return <div>...</div>;
 * }
 * ```
 */
export function useSupabase(): SupabaseClient<Database> {
  const { getToken } = useAuth();
  
  const supabase = useMemo(() => {
    const { supabaseUrl, supabaseAnonKey } = validateEnvironmentVariables();
    
    return createClient<Database>(supabaseUrl, supabaseAnonKey, {
      global: {
        fetch: async (url, options = {}) => {
          // Get Clerk token for Supabase authentication
          const token = await getToken({ template: 'supabase' });

          const headers = new Headers(options.headers);
          if (token) {
            headers.set('Authorization', `Bearer ${token}`);
          }

          return fetch(url, {
            ...options,
            headers,
          });
        },
      },
      auth: {
        persistSession: false, // We rely on Clerk for session management
        detectSessionInUrl: false,
        autoRefreshToken: false,
      },
    });
  }, [getToken]);

  return supabase;
}

/**
 * Server-side Supabase client for components and Server Actions
 * 
 * Use this function in Server Components and Server Actions to create
 * an authenticated Supabase client with the provided JWT token.
 * 
 * @param token - Clerk JWT token from auth().getToken({ template: 'supabase' })
 * @returns Authenticated Supabase client instance
 * 
 * @example
 * ```tsx
 * // In a Server Component
 * import { auth } from '@clerk/nextjs/server';
 * 
 * export default async function ServerPage() {
 *   const { getToken } = auth();
 *   const token = await getToken({ template: 'supabase' });
 *   const supabase = createServerClient(token);
 *   
 *   const { data } = await supabase
 *     .from('geofences')
 *     .select('*');
 *     
 *   return <div>...</div>;
 * }
 * ```
 * 
 * @example
 * ```tsx
 * // In a Server Action
 * 'use server';
 * 
 * export async function myServerAction() {
 *   const { getToken } = auth();
 *   const token = await getToken({ template: 'supabase' });
 *   const supabase = createServerClient(token);
 *   
 *   // Perform database operation...
 * }
 * ```
 */
export function createServerClient(token: string | null): SupabaseClient<Database> {
  const { supabaseUrl, supabaseAnonKey } = validateEnvironmentVariables();

  return createClient<Database>(supabaseUrl, supabaseAnonKey, {
    global: {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    },
    auth: {
      persistSession: false,
      detectSessionInUrl: false,
      autoRefreshToken: false,
    },
  });
}

/**
 * Admin Supabase client for webhooks and system operations
 * 
 * ⚠️  SECURITY WARNING: This client uses the service role key and bypasses RLS.
 * Only use this for:
 * - Webhook operations (like Clerk user lifecycle events)
 * - Admin operations that require elevated permissions
 * - Server-side operations that need to access data across all users
 * 
 * 🚨 NEVER expose this client to client-side code!
 * 
 * @returns Admin Supabase client with service role permissions
 * 
 * @example
 * ```tsx
 * // In a webhook API route
 * import { createAdminClient } from '@/app/(dashboard)/(lib)/supabase/client';
 * 
 * export async function POST(request: Request) {
 *   const supabase = createAdminClient();
 *   
 *   // Admin operation that bypasses RLS
 *   const { data, error } = await supabase
 *     .from('users')
 *     .insert({ ... });
 *     
 *   return Response.json({ success: true });
 * }
 * ```
 */
export function createAdminClient(): SupabaseClient<Database> {
  const { supabaseUrl, supabaseServiceKey } = validateEnvironmentVariables();

  if (!supabaseServiceKey) {
    throw new Error(
      '❌ Missing SUPABASE_SERVICE_ROLE_KEY environment variable.\n' +
      'This is required for admin operations and webhooks.\n' +
      'You can find this in your Supabase project API settings.\n' +
      '🚨 NEVER expose this key to client-side code!'
    );
  }

  return createClient<Database>(supabaseUrl, supabaseServiceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
    // No global headers needed - service role key provides full access
  });
}

/**
 * Type exports for better developer experience
 */
export type { Database } from '../types';
export type DatabaseClient = SupabaseClient<Database>; 