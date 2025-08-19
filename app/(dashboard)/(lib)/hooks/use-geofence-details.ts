'use client';

import { useState, useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import supabase from '../supabase-client';
import { Geofence } from '../types';

interface UseGeofenceDetailsResult {
  geofence: (Geofence & { role: 'owner' | 'member' }) | null;
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useGeofenceDetails(geofenceId: string | null): UseGeofenceDetailsResult {
  const { user } = useUser();
  const [geofence, setGeofence] = useState<(Geofence & { role: 'owner' | 'member' }) | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchGeofence = async () => {
    if (!geofenceId || !user) {
      setGeofence(null);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // First, fetch the geofence data
      const { data: geofenceData, error: geofenceError } = await supabase
        .from('geofences')
        .select('*')
        .eq('id_geofence', geofenceId)
        .maybeSingle();

      if (geofenceError) {
        throw new Error(geofenceError.message);
      }

      if (!geofenceData) {
        throw new Error('Geofence not found');
      }

      // Then, fetch the user's role in this geofence
      const { data: memberData, error: memberError } = await supabase
        .from('geofence_members')
        .select('role')
        .eq('id_geofence', geofenceId)
        .eq('id_user', user.id)
        .maybeSingle();

      if (memberError) {
        throw new Error(`Access denied: ${memberError.message}`);
      }

      if (!memberData) {
        throw new Error('You do not have access to this geofence');
      }

      // Combine the data
      const geofenceWithRole = {
        ...geofenceData,
        role: memberData.role as 'owner' | 'member'
      };
      
      setGeofence(geofenceWithRole);
    } catch (err) {
      console.error('Failed to fetch geofence:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch geofence');
    } finally {
      setIsLoading(false);
    }
  };

  // Initial fetch
  useEffect(() => {
    fetchGeofence();
  }, [geofenceId, user]);

  return {
    geofence,
    isLoading,
    error,
    refetch: fetchGeofence
  };
} 