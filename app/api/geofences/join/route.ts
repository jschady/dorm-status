/**
 * POST /api/geofences/join - Join a geofence using invite code
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { createClient } from '@supabase/supabase-js';
import type { 
  JoinGeofenceRequest, 
  JoinGeofenceResponse 
} from '../../../(dashboard)/(lib)/types';
import { InviteValidationResponse } from '../../../(dashboard)/(lib)/types';

// Supabase configuration
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('Missing Supabase environment variables');
}

// Service role client for privileged operations
const supabase = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

export async function GET(request: NextRequest) {
    try {
      const { searchParams } = new URL(request.url);
      const inviteCode = searchParams.get('code');
  
      if (!inviteCode) {
        return NextResponse.json({
          valid: false,
          error: 'Invite code is required'
        } as InviteValidationResponse, { status: 400 });
      }
  
      // This is the validation logic moved from the old [code] route
      const { data: geofence, error: geofenceError } = await supabase
        .from('geofences')
        .select(`
          id_geofence,
          name,
          created_at,
          owner:users!geofences_id_user_fkey(full_name)
        `)
        .eq('invite_code', inviteCode)
        .single();
  
      if (geofenceError || !geofence) {
        return NextResponse.json({
          valid: false,
          error: geofenceError?.message || geofence 
        } as InviteValidationResponse, { status: 404 });
      }
  
      const { data: members, error: membersError } = await supabase
        .from('geofence_members')
        .select('id_user')
        .eq('id_geofence', geofence.id_geofence);
  
      if (membersError) {
        console.error('Failed to get member count:', membersError);
        return NextResponse.json({
          valid: false,
          error: 'Failed to load geofence details'
        } as InviteValidationResponse, { status: 500 });
      }
  
      const response: InviteValidationResponse = {
        valid: true,
        geofence: {
          id_geofence: geofence.id_geofence,
          name: geofence.name,
          owner_name: (geofence as any).owner?.full_name || 'Unknown',
          member_count: members?.length || 0,
          created_at: geofence.created_at
        }
      };
  
      return NextResponse.json(response, { status: 200 });
  
    } catch (error) {
      console.error('Invite validation error:', error);
      return NextResponse.json({
        valid: false,
        error: 'Internal server error'
      } as InviteValidationResponse, { status: 500 });
    }
  }

export async function POST(request: NextRequest) {
  try {
    // Verify authentication
    const { userId } = await auth();
    
    if (!userId) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized - Please sign in to join geofences' },
        { status: 401 }
      );
    }

    // Parse and validate request body
    let requestData: JoinGeofenceRequest;
    try {
      requestData = await request.json();
    } catch (error) {
      return NextResponse.json(
        { success: false, message: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }

    const { invite_code } = requestData;

    if (!invite_code?.trim()) {
      return NextResponse.json(
        { success: false, message: 'Invite code is required' },
        { status: 400 }
      );
    }

    // Find geofence by invite code
    const { data: geofence, error: geofenceError } = await supabase
      .from('geofences')
      .select('id_geofence, name, id_user')
      .eq('invite_code', invite_code.trim())
      .single();

    if (geofenceError || !geofence) {
      return NextResponse.json(
        { success: false, message: 'Invalid or expired invitation code' },
        { status: 404 }
      );
    }

    // Check if user is already a member
    const { data: existingMember, error: memberCheckError } = await supabase
      .from('geofence_members')
      .select('id_user')
      .eq('id_geofence', geofence.id_geofence)
      .eq('id_user', userId)
      .single();

    if (memberCheckError && memberCheckError.code !== 'PGRST116') {
      // PGRST116 is "not found" which is expected for new members
      console.error('Failed to check existing membership:', memberCheckError);
      return NextResponse.json(
        { success: false, message: 'Failed to check membership status' },
        { status: 500 }
      );
    }

    if (existingMember) {
      return NextResponse.json(
        { success: false, message: 'You are already a member of this geofence' },
        { status: 409 }
      );
    }

    // Ensure user exists in our users table
    const { error: userUpsertError } = await supabase
      .from('users')
      .upsert(
        { 
          id_user: userId,
          email: '', // Will be populated by webhook
          updated_at: new Date().toISOString()
        },
        { 
          onConflict: 'id_user',
          ignoreDuplicates: false 
        }
      );

    if (userUpsertError) {
      console.error('Failed to upsert user:', userUpsertError);
      return NextResponse.json(
        { success: false, message: 'Failed to initialize user account' },
        { status: 500 }
      );
    }

    // Add user as member
    const { error: joinError } = await supabase
      .from('geofence_members')
      .insert({
        id_geofence: geofence.id_geofence,
        id_user: userId,
        role: 'member',
        status: 'AWAY', // Default status
        last_updated: new Date().toISOString(),
        joined_at: new Date().toISOString()
      });

    if (joinError) {
      console.error('Failed to add member:', joinError);
      
      // Check for specific error types
      if (joinError.code === '23505') { // Unique constraint violation
        return NextResponse.json(
          { success: false, message: 'You are already a member of this geofence' },
          { status: 409 }
        );
      }

      return NextResponse.json(
        { success: false, message: 'Failed to join geofence' },
        { status: 500 }
      );
    }

    // Return success response
    const response: JoinGeofenceResponse = {
      success: true,
      geofence: {
        id_geofence: geofence.id_geofence,
        name: geofence.name,
        role: 'member'
      },
      message: `Successfully joined ${geofence.name}!`
    };

    return NextResponse.json(response, { status: 200 });

  } catch (error) {
    console.error('Join geofence error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 