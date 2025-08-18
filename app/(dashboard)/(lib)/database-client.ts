import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { useAuth } from '@clerk/nextjs';
import { useMemo } from 'react';
import * as React from 'react';

/**
 * Client-side Supabase client with Clerk JWT integration
 * This enforces Row Level Security based on the authenticated user
 */
export function useSupabaseClient() {
  const { getToken, userId } = useAuth();
  
  const supabase = useMemo(() => {
    return createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        auth: {
          persistSession: false,
          detectSessionInUrl: false
        }
      }
    );
  }, []);

  // Set auth token for RLS
  React.useEffect(() => {
    const setAuthToken = async () => {
      if (userId) {
        const token = await getToken({ template: 'supabase' });
        if (token) {
          await supabase.auth.setSession({
            access_token: token,
            refresh_token: ''
          });
        }
      }
    };

    setAuthToken();
  }, [supabase, getToken, userId]);

  return supabase;
}

/**
 * Server-side Supabase client with Clerk JWT integration
 * Use this in server components and API routes
 */
export async function createServerClient(token: string | null) {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      global: {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      }
    }
  );
}

/**
 * Database types for the new multi-user schema
 */
export interface User {
  id_user: string;
  email: string;
  full_name?: string;
  created_at: string;
  updated_at: string;
}

export interface Geofence {
  id_geofence: string;
  id_user: string;
  name: string;
  invite_code: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  hysteresis_meters: number;
  created_at: string;
  updated_at: string;
}

export interface GeofenceMember {
  id_geofence: string;
  id_user: string;
  role: 'owner' | 'member';
  status: 'IN_ROOM' | 'AWAY';
  last_updated: string;
  last_gps_update?: string;
  joined_at: string;
}

export interface DeviceMapping {
  id: string;
  device_id: string;
  id_user: string;
  enabled: boolean;
  created_at: string;
  last_location_update?: string;
}

/**
 * Type-safe database operations for client-side use
 * All operations automatically enforce RLS based on the authenticated user
 */
export class DatabaseService {
  constructor(private supabase: SupabaseClient) {}

  // User operations
  async getCurrentUser(): Promise<User | null> {
    const { data, error } = await this.supabase
      .from('users')
      .select('*')
      .single();

    if (error && error.code !== 'PGRST116') {
      throw error;
    }

    return data;
  }

  async updateUserProfile(updates: Partial<Pick<User, 'full_name'>>): Promise<User> {
    const { data, error } = await this.supabase
      .from('users')
      .update({
        ...updates,
        updated_at: new Date().toISOString()
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  // Geofence operations
  async getUserGeofences(): Promise<Geofence[]> {
    const { data, error } = await this.supabase
      .from('geofences')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    return data || [];
  }

  async createGeofence(geofenceData: {
    name: string;
    center_latitude: number;
    center_longitude: number;
    radius_meters?: number;
    hysteresis_meters?: number;
  }): Promise<Geofence> {
    // Generate unique invite code
    const { customAlphabet } = await import('nanoid');
    const nanoid = customAlphabet('23456789ABCDEFGHJKLMNPQRSTUVWXYZ', 8);
    
    const { data, error } = await this.supabase
      .from('geofences')
      .insert({
        ...geofenceData,
        invite_code: nanoid(),
        radius_meters: geofenceData.radius_meters || 50,
        hysteresis_meters: geofenceData.hysteresis_meters || 10
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async updateGeofence(id_geofence: string, updates: Partial<Pick<Geofence, 'name' | 'radius_meters' | 'hysteresis_meters'>>): Promise<Geofence> {
    const { data, error } = await this.supabase
      .from('geofences')
      .update({
        ...updates,
        updated_at: new Date().toISOString()
      })
      .eq('id_geofence', id_geofence)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async deleteGeofence(id_geofence: string): Promise<void> {
    const { error } = await this.supabase
      .from('geofences')
      .delete()
      .eq('id_geofence', id_geofence);

    if (error) throw error;
  }

  // Geofence member operations
  async getGeofenceMembers(id_geofence: string): Promise<GeofenceMember[]> {
    const { data, error } = await this.supabase
      .from('geofence_members')
      .select(`
        *,
        users!inner(full_name, email)
      `)
      .eq('id_geofence', id_geofence)
      .order('joined_at', { ascending: true });

    if (error) throw error;
    return data || [];
  }

  async updateMemberStatus(id_geofence: string, status: 'IN_ROOM' | 'AWAY'): Promise<GeofenceMember> {
    const { data, error } = await this.supabase
      .from('geofence_members')
      .update({
        status,
        last_updated: new Date().toISOString()
      })
      .eq('id_geofence', id_geofence)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  // Device mapping operations
  async getUserDevice(): Promise<DeviceMapping | null> {
    const { data, error } = await this.supabase
      .from('device_mappings')
      .select('*')
      .single();

    if (error && error.code !== 'PGRST116') {
      throw error;
    }

    return data;
  }

  async registerDevice(device_id: string): Promise<DeviceMapping> {
    const { data, error } = await this.supabase
      .from('device_mappings')
      .upsert({
        device_id,
        enabled: true,
        created_at: new Date().toISOString(),
        last_location_update: new Date().toISOString()
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async updateDeviceStatus(enabled: boolean): Promise<DeviceMapping> {
    const { data, error } = await this.supabase
      .from('device_mappings')
      .update({ enabled })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async removeDevice(): Promise<void> {
    const { error } = await this.supabase
      .from('device_mappings')
      .delete();

    if (error) throw error;
  }

  // Real-time subscriptions
  subscribeToGeofenceMembers(
    id_geofence: string,
    callback: (payload: any) => void,
    statusCallback?: (status: string) => void
  ) {
    return this.supabase
      .channel(`geofence-${id_geofence}`)
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'geofence_members',
          filter: `id_geofence=eq.${id_geofence}`
        },
        callback
      )
      .subscribe((status) => {
        console.log('Real-time subscription status:', status);
        if (statusCallback) {
          statusCallback(status);
        }
      });
  }

  subscribeToUserDevice(
    callback: (payload: any) => void,
    statusCallback?: (status: string) => void
  ) {
    return this.supabase
      .channel('user-device')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'device_mappings'
        },
        callback
      )
      .subscribe((status) => {
        console.log('Device subscription status:', status);
        if (statusCallback) {
          statusCallback(status);
        }
      });
  }

  unsubscribe(channel: any) {
    return this.supabase.removeChannel(channel);
  }
}

/**
 * Hook to get database service with authentication
 */
export function useDatabase() {
  const supabase = useSupabaseClient();
  return useMemo(() => new DatabaseService(supabase), [supabase]);
} 