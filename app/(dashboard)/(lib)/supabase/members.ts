'use server';

import { auth } from '@clerk/nextjs/server';
import { createServerClient } from './client';
import type { ServerActionResult } from './geofences';

/**
 * Members Server Actions
 * 
 * Server actions for member management operations
 */

/**
 * Get members of a specific geofence
 * 
 * @param geofenceId - The ID of the geofence
 * @returns Promise<ServerActionResult<Member[]>>
 */
export async function getGeofenceMembers(geofenceId: string): Promise<ServerActionResult<any[]>> {
  try {
    // Verify authentication
    const { getToken, userId } = await auth();
    
    if (!userId) {
      return {
        success: false,
        error: 'Unauthorized - Please sign in to view members'
      };
    }

    // Create authenticated client
    const token = await getToken({ template: 'supabase' });
    const supabase = createServerClient(token);

    // First verify user has access to this geofence
    const { data: memberCheck, error: memberCheckError } = await supabase
      .from('geofence_members')
      .select('role')
      .eq('id_geofence', geofenceId)
      .eq('id_user', userId)
      .single();

    if (memberCheckError || !memberCheck) {
      return {
        success: false,
        error: 'You do not have access to this geofence'
      };
    }

    // Get all members of the geofence
    const { data: members, error: membersError } = await supabase
      .from('geofence_members')
      .select(`
        id_geofence,
        id_user,
        role,
        status,
        last_updated,
        joined_at,
        users (
          full_name,
          email
        )
      `)
      .eq('id_geofence', geofenceId)
      .order('joined_at', { ascending: false });

    if (membersError) {
      console.error('Failed to fetch members:', membersError);
      return {
        success: false,
        error: 'Failed to retrieve members',
        details: membersError
      };
    }

    return { success: true, data: members || [] };

  } catch (error) {
    console.error('Members retrieval error:', error);
    return {
      success: false,
      error: 'Internal server error',
      details: error
    };
  }
}

/**
 * Remove a member from a geofence
 * 
 * Replaces: DELETE /api/geofences/[geofenceId]/members
 * 
 * @param geofenceId - The ID of the geofence
 * @param targetUserId - The ID of the user to remove
 * @returns Promise<ServerActionResult<void>>
 */
export async function removeMember(geofenceId: string, targetUserId: string): Promise<ServerActionResult<void>> {
  try {
    // Verify authentication
    const { getToken, userId } = await auth();
    
    if (!userId) {
      return {
        success: false,
        error: 'Unauthorized - Please sign in to remove members'
      };
    }

    if (!targetUserId) {
      return {
        success: false,
        error: 'User ID is required'
      };
    }

    // Create authenticated client
    const token = await getToken({ template: 'supabase' });
    const supabase = createServerClient(token);

    // First, verify the requesting user is an owner of this geofence
    const { data: requesterMembership, error: requesterError } = await supabase
      .from('geofence_members')
      .select('role')
      .eq('id_geofence', geofenceId)
      .eq('id_user', userId)
      .single();
    
    if (requesterError || !requesterMembership) {
      return {
        success: false,
        error: 'You do not have access to this geofence'
      };
    }

    if (requesterMembership.role !== 'owner') {
      return {
        success: false,
        error: 'Only geofence owners can remove members'
      };
    }

    // Verify the target user is actually a member of this geofence
    const { data: targetMembership, error: targetError } = await supabase
      .from('geofence_members')
      .select('role')
      .eq('id_geofence', geofenceId)
      .eq('id_user', targetUserId)
      .single();
    
    if (targetError || !targetMembership) {
      return {
        success: false,
        error: 'User is not a member of this geofence'
      };
    }

    // Prevent owners from removing themselves
    if (targetUserId === userId) {
      return {
        success: false,
        error: 'You cannot remove yourself from a geofence you own'
      };
    }

    // Prevent removing other owners
    if (targetMembership.role === 'owner') {
      return {
        success: false,
        error: 'Cannot remove the geofence owner'
      };
    }

    // Remove the member
    const { error: deleteError } = await supabase
      .from('geofence_members')
      .delete()
      .eq('id_geofence', geofenceId)
      .eq('id_user', targetUserId);

    if (deleteError) {
      console.error('Failed to remove member:', deleteError);
      return {
        success: false,
        error: 'Failed to remove member from geofence',
        details: deleteError
      };
    }

    return { success: true, data: undefined };

  } catch (error) {
    console.error('Remove member error:', error);
    return {
      success: false,
      error: 'Internal server error',
      details: error
    };
  }
}

/**
 * Update a member's role in a geofence
 * 
 * @param geofenceId - The ID of the geofence
 * @param targetUserId - The ID of the user whose role to update
 * @param newRole - The new role ('owner' | 'member')
 * @returns Promise<ServerActionResult<void>>
 */
export async function updateMemberRole(
  geofenceId: string, 
  targetUserId: string, 
  newRole: 'owner' | 'member'
): Promise<ServerActionResult<void>> {
  try {
    // Verify authentication
    const { getToken, userId } = await auth();
    
    if (!userId) {
      return {
        success: false,
        error: 'Unauthorized - Please sign in to update member roles'
      };
    }

    if (!targetUserId || !newRole) {
      return {
        success: false,
        error: 'User ID and new role are required'
      };
    }

    // Create authenticated client
    const token = await getToken({ template: 'supabase' });
    const supabase = createServerClient(token);

    // Verify the requesting user is an owner of this geofence
    const { data: requesterMembership, error: requesterError } = await supabase
      .from('geofence_members')
      .select('role')
      .eq('id_geofence', geofenceId)
      .eq('id_user', userId)
      .single();
    
    if (requesterError || !requesterMembership) {
      return {
        success: false,
        error: 'You do not have access to this geofence'
      };
    }

    if (requesterMembership.role !== 'owner') {
      return {
        success: false,
        error: 'Only geofence owners can update member roles'
      };
    }

    // Verify the target user is a member of this geofence
    const { data: targetMembership, error: targetError } = await supabase
      .from('geofence_members')
      .select('role')
      .eq('id_geofence', geofenceId)
      .eq('id_user', targetUserId)
      .single();
    
    if (targetError || !targetMembership) {
      return {
        success: false,
        error: 'User is not a member of this geofence'
      };
    }

    // If promoting to owner, demote current owner to member (only one owner allowed)
    if (newRole === 'owner' && targetUserId !== userId) {
      // First demote the current owner to member
      const { error: demoteError } = await supabase
        .from('geofence_members')
        .update({ role: 'member' })
        .eq('id_geofence', geofenceId)
        .eq('id_user', userId);

      if (demoteError) {
        console.error('Failed to demote current owner:', demoteError);
        return {
          success: false,
          error: 'Failed to transfer ownership',
          details: demoteError
        };
      }
    }

    // Update the target user's role
    const { error: updateError } = await supabase
      .from('geofence_members')
      .update({ role: newRole })
      .eq('id_geofence', geofenceId)
      .eq('id_user', targetUserId);

    if (updateError) {
      console.error('Failed to update member role:', updateError);
      return {
        success: false,
        error: 'Failed to update member role',
        details: updateError
      };
    }

    return { success: true, data: undefined };

  } catch (error) {
    console.error('Update member role error:', error);
    return {
      success: false,
      error: 'Internal server error',
      details: error
    };
  }
}

/**
 * Add a member to a geofence directly (for admin/owner use)
 * 
 * Note: For joining via invite code, use joinGeofence() from geofences.ts
 * 
 * @param geofenceId - The ID of the geofence
 * @param targetUserId - The ID of the user to add
 * @param role - The role to assign ('member' by default)
 * @returns Promise<ServerActionResult<void>>
 */
export async function addMember(
  geofenceId: string, 
  targetUserId: string, 
  role: 'owner' | 'member' = 'member'
): Promise<ServerActionResult<void>> {
  try {
    // Verify authentication
    const { getToken, userId } = await auth();
    
    if (!userId) {
      return {
        success: false,
        error: 'Unauthorized - Please sign in to add members'
      };
    }

    if (!targetUserId) {
      return {
        success: false,
        error: 'User ID is required'
      };
    }

    // Create authenticated client
    const token = await getToken({ template: 'supabase' });
    const supabase = createServerClient(token);

    // Verify the requesting user is an owner of this geofence
    const { data: requesterMembership, error: requesterError } = await supabase
      .from('geofence_members')
      .select('role')
      .eq('id_geofence', geofenceId)
      .eq('id_user', userId)
      .single();
    
    if (requesterError || !requesterMembership) {
      return {
        success: false,
        error: 'You do not have access to this geofence'
      };
    }

    if (requesterMembership.role !== 'owner') {
      return {
        success: false,
        error: 'Only geofence owners can add members'
      };
    }

    // Check if user is already a member
    const { data: existingMember, error: memberCheckError } = await supabase
      .from('geofence_members')
      .select('id_user')
      .eq('id_geofence', geofenceId)
      .eq('id_user', targetUserId)
      .single();

    if (memberCheckError && memberCheckError.code !== 'PGRST116') {
      console.error('Failed to check existing membership:', memberCheckError);
      return {
        success: false,
        error: 'Failed to verify membership status',
        details: memberCheckError
      };
    }

    if (existingMember) {
      return {
        success: false,
        error: 'User is already a member of this geofence'
      };
    }

    // Add the member
    const { error: insertError } = await supabase
      .from('geofence_members')
      .insert({
        id_geofence: geofenceId,
        id_user: targetUserId,
        role,
        joined_at: new Date().toISOString()
      });

    if (insertError) {
      console.error('Failed to add member:', insertError);
      return {
        success: false,
        error: 'Failed to add member to geofence',
        details: insertError
      };
    }

    return { success: true, data: undefined };

  } catch (error) {
    console.error('Add member error:', error);
    return {
      success: false,
      error: 'Internal server error',
      details: error
    };
  }
} 