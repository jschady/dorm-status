'use client';

import { useState, useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import { useSupabase } from '../supabase/client';
import { GeofenceMemberWithUser } from '../types';

interface UseMembersResult {
  members: GeofenceMemberWithUser[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useMembers(geofenceId: string | null): UseMembersResult {
  const { user, isLoaded } = useUser();
  const supabase = useSupabase();
  const [members, setMembers] = useState<GeofenceMemberWithUser[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchMembers = async () => {
    if (!isLoaded || !geofenceId || !user) {
      setMembers([]);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const { data: membersData, error: membersError } = await supabase
        .from('geofence_members')
        .select(`
          id_geofence,
          id_user,
          role,
          status, 
          last_updated,
          last_gps_update,
          joined_at,
          users (
            email,
            full_name
          )
        `)
        .eq('id_geofence', geofenceId)
        .order('joined_at', { ascending: false });

      if (membersError) {
        throw new Error(membersError.message);
      }

      // Transform the data to match GeofenceMemberWithUser type
      const transformedMembers = (membersData || []).map(member => ({
        ...member,
        users: member.users?.[0] || null
      }));
      
      setMembers(transformedMembers);

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
  }, [geofenceId, user, isLoaded]);

  // Real-time subscription for member updates
  useEffect(() => {
    if (!isLoaded || !geofenceId || !user) return;

    const channel = supabase
      .channel(`geofence-members-${geofenceId}`)
      .on(
        'postgres_changes',
        {
          event: '*', // Listen to all events to simplify logic
          schema: 'public',
          table: 'geofence_members',
          filter: `id_geofence=eq.${geofenceId}`
        },
        (payload) => {
          console.log('Real-time member change received:', payload);
          // Refetch the entire list to ensure consistency with joined user data
          fetchMembers();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [geofenceId, user, isLoaded]);

  return {
    members,
    isLoading,
    error,
    refetch: fetchMembers
  };
}