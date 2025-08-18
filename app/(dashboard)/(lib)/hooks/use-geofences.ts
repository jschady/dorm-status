'use client';

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '@clerk/nextjs';
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
  
  const { isSignedIn, userId } = useAuth();
  const [geofences, setGeofences] = useState<GeofenceListItem[]>([]);
  const [isLoading, setIsLoading] = useState(autoFetch);
  const [error, setError] = useState<string | null>(null);

  // Fetch geofences from API
  const fetchGeofences = useCallback(async () => {
    if (!isSignedIn || !userId) {
      setGeofences([]);
      setIsLoading(false);
      return;
    }

    try {
      setError(null);
      
      const response = await fetch('/api/geofences', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Failed to fetch geofences: ${response.status}`);
      }

      const data: GeofenceListItem[] = await response.json();
      setGeofences(data);
    } catch (error) {
      console.error('Failed to fetch geofences:', error);
      setError(error instanceof Error ? error.message : 'Failed to fetch geofences');
      setGeofences([]);
    } finally {
      setIsLoading(false);
    }
  }, [isSignedIn, userId]);

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
    if (autoFetch && isSignedIn) {
      fetchGeofences();
    } else if (!isSignedIn) {
      setGeofences([]);
      setIsLoading(false);
      setError(null);
    }
  }, [fetchGeofences, autoFetch, isSignedIn]);

  // Set up auto-refresh interval
  useEffect(() => {
    if (!refetchInterval || !isSignedIn) return;

    const interval = setInterval(() => {
      fetchGeofences();
    }, refetchInterval);

    return () => clearInterval(interval);
  }, [fetchGeofences, refetchInterval, isSignedIn]);

  // Handle auth state changes
  useEffect(() => {
    if (!isSignedIn) {
      setGeofences([]);
      setError(null);
      setIsLoading(false);
    }
  }, [isSignedIn]);

  return {
    geofences,
    isLoading,
    error,
    fetchGeofences,
    refreshGeofences,
    addGeofence,
    removeGeofence,
  };
} 