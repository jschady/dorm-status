/**
 * Next.js 15 App Router API Route for Geofence Management
 * Handles CRUD operations for geofences with Clerk authentication
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { createClient } from '@supabase/supabase-js';
import { nanoid } from 'nanoid';
import type { 
  CreateGeofenceRequest, 
  CreateGeofenceResponse,
  GeofenceListItem,
  Database 
} from '../../(dashboard)/(lib)/types';

// Supabase configuration
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('Missing Supabase environment variables');
}

// Service role client for privileged operations
const supabase = createClient<Database>(supabaseUrl, supabaseServiceKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false
  }
});

/**
 * POST /api/geofences - Create a new geofence
 */
export async function POST(request: NextRequest) {
  try {
    // Verify authentication
    const { userId } = await auth();
    
    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized - Please sign in to create geofences' },
        { status: 401 }
      );
    }

    // Parse and validate request body
    let requestData: CreateGeofenceRequest;
    try {
      requestData = await request.json();
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid JSON in request body' },
        { status: 400 }
      );
    }

    // Validate required fields
    const { name, center_latitude, center_longitude, radius_meters, hysteresis_meters } = requestData;

    if (!name?.trim()) {
      return NextResponse.json(
        { error: 'Geofence name is required' },
        { status: 400 }
      );
    }

    if (typeof center_latitude !== 'number' || typeof center_longitude !== 'number') {
      return NextResponse.json(
        { error: 'Valid latitude and longitude coordinates are required' },
        { status: 400 }
      );
    }

    // Validate coordinate ranges
    if (Math.abs(center_latitude) > 90 || Math.abs(center_longitude) > 180) {
      return NextResponse.json(
        { error: 'Coordinates are out of valid range' },
        { status: 400 }
      );
    }

    // Validate radius and hysteresis
    if (radius_meters < 10 || radius_meters > 1000) {
      return NextResponse.json(
        { error: 'Radius must be between 10 and 1000 meters' },
        { status: 400 }
      );
    }

    if (hysteresis_meters < 5 || hysteresis_meters >= radius_meters) {
      return NextResponse.json(
        { error: 'Hysteresis must be between 5 meters and less than radius' },
        { status: 400 }
      );
    }

    // Generate unique invite code
    const invite_code = nanoid(10);

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
          ignoreDuplicates: true 
        }
      );

    if (userUpsertError) {
      console.error('Failed to upsert user:', userUpsertError);
      return NextResponse.json(
        { error: 'Failed to initialize user account' },
        { status: 500 }
      );
    }

    // Create geofence
    const { data: geofence, error: createError } = await supabase
      .from('geofences')
      .insert({
        id_user: userId,
        name: name.trim(),
        invite_code,
        center_latitude,
        center_longitude,
        radius_meters,
        hysteresis_meters
      })
      .select()
      .single();

    if (createError) {
      console.error('Failed to create geofence:', createError);
      
      // Check for specific error types
      if (createError.code === '23505') { // Unique constraint violation
        return NextResponse.json(
          { error: 'A geofence with this invite code already exists. Please try again.' },
          { status: 409 }
        );
      }

      return NextResponse.json(
        { error: 'Failed to create geofence' },
        { status: 500 }
      );
    }

    // Format response
    const response: CreateGeofenceResponse = {
      id_geofence: geofence.id_geofence,
      name: geofence.name,
      invite_code: geofence.invite_code,
      center_latitude: geofence.center_latitude,
      center_longitude: geofence.center_longitude,
      radius_meters: geofence.radius_meters,
      hysteresis_meters: geofence.hysteresis_meters,
      created_at: geofence.created_at
    };

    return NextResponse.json(response, { status: 201 });

  } catch (error) {
    console.error('Geofence creation error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * GET /api/geofences - Get user's geofences
 */
export async function GET(request: NextRequest) {
  try {
    // Verify authentication
    const { userId } = await auth();
    
    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized - Please sign in to view geofences' },
        { status: 401 }
      );
    }

    // Query geofences where user is a member
    const { data: geofences, error: queryError } = await supabase
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
      console.error('Failed to query geofences:', queryError);
      return NextResponse.json(
        { error: 'Failed to retrieve geofences' },
        { status: 500 }
      );
    }

    // Get member counts for each geofence
    const geofenceIds = geofences.map(g => g.id_geofence);
    
    const { data: memberCounts, error: countError } = await supabase
      .from('geofence_members')
      .select('id_geofence')
      .in('id_geofence', geofenceIds);

    if (countError) {
      console.error('Failed to get member counts:', countError);
      return NextResponse.json(
        { error: 'Failed to retrieve member counts' },
        { status: 500 }
      );
    }

    // Count members per geofence
    const memberCountMap = memberCounts.reduce((acc, member) => {
      acc[member.id_geofence] = (acc[member.id_geofence] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Format response
    const response: GeofenceListItem[] = geofences.map(geofence => ({
      id_geofence: geofence.id_geofence,
      name: geofence.name,
      member_count: memberCountMap[geofence.id_geofence] || 0,
      created_at: geofence.created_at,
      invite_code: geofence.invite_code,
      role: geofence.geofence_members[0]?.role || 'member'
    }));

    return NextResponse.json(response, { status: 200 });

  } catch (error) {
    console.error('Geofence retrieval error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
} 