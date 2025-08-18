import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { createClient } from '@supabase/supabase-js';
import type { Database } from '../../../(dashboard)/(lib)/types';

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

interface UpdateGeofenceRequest {
  name: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  hysteresis_meters: number;
}

/**
 * PUT /api/geofences/[geofenceId] - Update a geofence
 */
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ geofenceId: string }> }
) {
  try {
    // Verify authentication
    const { userId } = await auth();
    
    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized - Please sign in to update geofences' },
        { status: 401 }
      );
    }

    const { geofenceId } = await params;

    // Parse and validate request body
    let requestData: UpdateGeofenceRequest;
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

    // First verify the user owns this geofence
    const { data: geofence, error: geofenceError } = await supabase
      .from('geofences')
      .select('id_user')
      .eq('id_geofence', geofenceId)
      .single();

    if (geofenceError) {
      console.error('Failed to check geofence ownership:', geofenceError);
      return NextResponse.json(
        { error: 'Geofence not found' },
        { status: 404 }
      );
    }

    if (geofence.id_user !== userId) {
      return NextResponse.json(
        { error: 'You can only edit geofences you own' },
        { status: 403 }
      );
    }

    // Update geofence
    const { data: updatedGeofence, error: updateError } = await supabase
      .from('geofences')
      .update({
        name: name.trim(),
        center_latitude,
        center_longitude,
        radius_meters,
        hysteresis_meters,
        updated_at: new Date().toISOString()
      })
      .eq('id_geofence', geofenceId)
      .select()
      .single();

    if (updateError) {
      console.error('Failed to update geofence:', updateError);
      return NextResponse.json(
        { error: 'Failed to update geofence' },
        { status: 500 }
      );
    }

    return NextResponse.json(updatedGeofence);

  } catch (error) {
    console.error('Geofence update error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

/**
 * DELETE /api/geofences/[geofenceId] - Delete a geofence
 */
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ geofenceId: string }> }
) {
  try {
    // Verify authentication
    const { userId } = await auth();
    
    if (!userId) {
      return NextResponse.json(
        { error: 'Unauthorized - Please sign in to delete geofences' },
        { status: 401 }
      );
    }

    const { geofenceId } = await params;

    // First verify the user owns this geofence
    const { data: geofence, error: geofenceError } = await supabase
      .from('geofences')
      .select('id_user')
      .eq('id_geofence', geofenceId)
      .single();

    if (geofenceError) {
      console.error('Failed to check geofence ownership:', geofenceError);
      return NextResponse.json(
        { error: 'Geofence not found' },
        { status: 404 }
      );
    }

    if (geofence.id_user !== userId) {
      return NextResponse.json(
        { error: 'You can only delete geofences you own' },
        { status: 403 }
      );
    }

    // Delete geofence (cascade will handle members)
    const { error: deleteError } = await supabase
      .from('geofences')
      .delete()
      .eq('id_geofence', geofenceId);

    if (deleteError) {
      console.error('Failed to delete geofence:', deleteError);
      return NextResponse.json(
        { error: 'Failed to delete geofence' },
        { status: 500 }
      );
    }

    return NextResponse.json({ 
      message: 'Geofence deleted successfully' 
    });

  } catch (error) {
    console.error('Geofence deletion error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
} 