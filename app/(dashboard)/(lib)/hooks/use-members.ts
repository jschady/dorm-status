'use client';

import { useState, useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import supabase from '../supabase-client';
import { GeofenceMemberWithUser } from '../types';

interface UseMembersResult {
  members: GeofenceMemberWithUser[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useMembers(geofenceId: string | null): UseMembersResult {
  const { user } = useUser();
  const [members, setMembers] = useState<GeofenceMemberWithUser[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMembers = async () => {
    if (!geofenceId || !user) {
      setMembers([]);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // Fetch members via API endpoint
      const response = await fetch(`/api/geofences/${geofenceId}/members`);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }
      
      const { members } = await response.json();
      setMembers(members || []);
    } catch (err) {
      console.error('Failed to fetch members:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch members');
    } finally {
      setIsLoading(false);
    }
  };

  // Initial fetch
  useEffect(() => {
    fetchMembers();
  }, [geofenceId, user]);

  // Real-time subscription for member updates - optimized for incremental updates
  useEffect(() => {
    if (!geofenceId || !user) return;

    const channel = supabase
      .channel(`geofence-members-${geofenceId}`)
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'geofence_members',
          filter: `id_geofence=eq.${geofenceId}`
        },
        (payload) => {
          console.log('Real-time member update received:', payload);
          
          // Update only the specific member that changed
          setMembers(prevMembers => {
            return prevMembers.map(member => {
              if (member.id_geofence === payload.new.id_geofence && 
                  member.id_user === payload.new.id_user) {
                // Merge the updated fields while preserving user data
                return {
                  ...member,
                  status: payload.new.status,
                  last_updated: payload.new.last_updated,
                  last_gps_update: payload.new.last_gps_update
                };
              }
              return member;
            });
          });
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'geofence_members',
          filter: `id_geofence=eq.${geofenceId}`
        },
        () => {
          // For new members, we need to refetch to get user data
          console.log('New member added, refetching...');
          fetchMembers();
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'DELETE',
          schema: 'public',
          table: 'geofence_members',
          filter: `id_geofence=eq.${geofenceId}`
        },
        (payload) => {
          console.log('Member removed:', payload);
          
          // Remove the member from the list
          setMembers(prevMembers => {
            return prevMembers.filter(member => 
              !(member.id_geofence === payload.old.id_geofence && 
                member.id_user === payload.old.id_user)
            );
          });
        }
      )
      .subscribe();

    return () => {
      channel.unsubscribe();
    };
  }, [geofenceId, user]);

  return {
    members,
    isLoading,
    error,
    refetch: fetchMembers
  };
} 