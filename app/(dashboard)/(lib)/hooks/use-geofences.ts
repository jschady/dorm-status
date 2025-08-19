'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@clerk/nextjs';
import { useSupabase } from '../supabase/client';
import type { GeofenceListItem, CreateGeofenceResponse } from '../types';

interface UseGeofencesOptions {
  autoFetch?: boolean;
  refetchInterval?: number;
}

interface UseGeofencesReturn {
  geofences: GeofenceListItem[];
  isLoading: boolean;
  error: string | null;
  fetchGeofences: () => Promise<void>;
  refreshGeofences: () => Promise<void>;
  addGeofence: (geofence: CreateGeofenceResponse) => void;
  removeGeofence: (geofenceId: string) => void;
}

export function useGeofences({ 
  autoFetch = true, 
  refetchInterval 
}: UseGeofencesOptions = {}): UseGeofencesReturn {
  
  const { isSignedIn, userId, isLoaded } = useAuth();
  const supabase = useSupabase();
  const [geofences, setGeofences] = useState<GeofenceListItem[]>([]);
  const [isLoading, setIsLoading] = useState(autoFetch);
  const [error, setError] = useState<string | null>(null);

  // Keep loading state true until auth is loaded
  const effectiveIsLoading = isLoading || (autoFetch && !isLoaded);

  // Fetch geofences from API
  const fetchGeofences = useCallback(async () => {
    // Don't do anything if Clerk hasn't loaded yet
    if (!isLoaded) {
      return;
    }
    
    if (!isSignedIn || !userId) {
      setGeofences([]);
      setIsLoading(false);
      return;
    }

    try {
      setError(null);
      
      // Use centralized Supabase client instead of API routes
      const { data: geofencesData, error: queryError } = await supabase
        .from('geofences')
        .select(`
          id_geofence,
          name,
          invite_code,
          created_at,
          geofence_members!inner (
            role,
            id_user
          )
        `)
        .eq('geofence_members.id_user', userId)
        .order('created_at', { ascending: false });

      if (queryError) {
        throw new Error(queryError.message);
      }

      // Get member counts for each geofence
      const geofenceIds = geofencesData.map(g => g.id_geofence);
      
      const { data: memberCounts, error: countError } = await supabase
        .from('geofence_members')
        .select('id_geofence')
        .in('id_geofence', geofenceIds);

      if (countError) {
        throw new Error('Failed to retrieve member counts');
      }

      // Count members per geofence
      const memberCountMap = memberCounts.reduce((acc, member) => {
        acc[member.id_geofence] = (acc[member.id_geofence] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      // Format response
      const data: GeofenceListItem[] = geofencesData.map(geofence => ({
        id_geofence: geofence.id_geofence,
        name: geofence.name,
        member_count: memberCountMap[geofence.id_geofence] || 0,
        created_at: geofence.created_at,
        invite_code: geofence.invite_code,
        role: geofence.geofence_members[0]?.role || 'member'
      }));

      setGeofences(data);
    } catch (error) {
      console.error('Failed to fetch geofences:', error);
      setError(error instanceof Error ? error.message : 'Failed to fetch geofences');
      setGeofences([]);
    } finally {
      setIsLoading(false);
    }
  }, [isSignedIn, userId, isLoaded]);

  // Refresh geofences (with loading state)
  const refreshGeofences = useCallback(async () => {
    setIsLoading(true);
    await fetchGeofences();
  }, [fetchGeofences]);

  // Add geofence to local state (optimistic update)
  const addGeofence = useCallback((geofence: CreateGeofenceResponse) => {
    const newGeofence: GeofenceListItem = {
      id_geofence: geofence.id_geofence,
      name: geofence.name,
      member_count: 1, // Owner is automatically added as member
      created_at: geofence.created_at,
      invite_code: geofence.invite_code,
      role: 'owner' // Creator is always the owner
    };
    
    setGeofences(prev => [newGeofence, ...prev]);
  }, []);

  // Remove geofence from local state
  const removeGeofence = useCallback((geofenceId: string) => {
    setGeofences(prev => prev.filter(g => g.id_geofence !== geofenceId));
  }, []);

  // Auto-fetch on mount and when auth state changes
  useEffect(() => {
    if (autoFetch && isLoaded && isSignedIn) {
      fetchGeofences();
    } else if (isLoaded && !isSignedIn) {
      setGeofences([]);
      setIsLoading(false);
      setError(null);
    }
  }, [fetchGeofences, autoFetch, isSignedIn, isLoaded]);

  // Set up auto-refresh interval
  useEffect(() => {
    if (!refetchInterval || !isLoaded || !isSignedIn) return;

    const interval = setInterval(() => {
      fetchGeofences();
    }, refetchInterval);

    return () => clearInterval(interval);
  }, [fetchGeofences, refetchInterval, isSignedIn, isLoaded]);

  // Handle auth state changes
  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      setGeofences([]);
      setError(null);
      setIsLoading(false);
    }
  }, [isSignedIn, isLoaded]);

  return {
    geofences,
    isLoading: effectiveIsLoading,
    error,
    fetchGeofences,
    refreshGeofences,
    addGeofence,
    removeGeofence,
  };
} 