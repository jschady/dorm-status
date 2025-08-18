/**
 * Next.js 15 App Router API Route for GPS Location Processing
 * Receives location data from Overland GPS iOS app and processes geofencing logic
 * Updated for multi-user schema with Clerk authentication
 */

import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

// Types for location processing
interface LocationUpdateRequest {
  device_id: string;
  latitude: number;
  longitude: number;
  timestamp: string;
  accuracy?: number;
}

interface LocationUpdateResponse {
  success: boolean;
  status_updated?: boolean;
  current_status?: 'IN_ROOM' | 'AWAY';
  geofence_id?: string;
  message?: string;
  error?: string;
}

interface DeviceMapping {
  id: string;
  device_id: string;
  id_user: string;
  enabled: boolean;
  created_at: string;
  last_location_update?: string;
}

interface Geofence {
  id_geofence: string;
  id_user: string;
  name: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  hysteresis_meters: number;
}

interface GeofenceMember {
  id_geofence: string;
  id_user: string;
  role: 'owner' | 'member';
  status: 'IN_ROOM' | 'AWAY';
  last_updated: string;
  last_gps_update?: string;
}

/**
 * Create Supabase client with service role for API operations
 */
function createServiceClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  );
}

/**
 * Calculate distance between two GPS coordinates using Haversine formula
 */
function calculateDistance(
  lat1: number, lon1: number,
  lat2: number, lon2: number
): number {
  const R = 6371000; // Earth's radius in meters
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;

  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
           Math.cos(φ1) * Math.cos(φ2) *
           Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  
  return R * c;
}

/**
 * Determine if status should change based on location and hysteresis logic
 */
function calculateGeofenceStatus(
  location: { latitude: number; longitude: number },
  geofence: Geofence,
  currentStatus: 'IN_ROOM' | 'AWAY'
): 'IN_ROOM' | 'AWAY' {
  const distance = calculateDistance(
    location.latitude,
    location.longitude,
    geofence.center_latitude,
    geofence.center_longitude
  );
  
  const radius = geofence.radius_meters;
  const hysteresis = geofence.hysteresis_meters;
  
  // Apply hysteresis to prevent status flapping
  if (currentStatus === 'AWAY') {
    // Need to be well inside to change to IN_ROOM
    return distance <= (radius - hysteresis) ? 'IN_ROOM' : 'AWAY';
  } else {
    // Need to be well outside to change to AWAY  
    return distance >= (radius + hysteresis) ? 'AWAY' : 'IN_ROOM';
  }
}

/**
 * Validate incoming location update request
 */
function validateLocationRequest(body: any): LocationUpdateRequest | null {
  if (!body) return null;
  
  const { device_id, latitude, longitude, timestamp, accuracy } = body;
  
  // Check required fields
  if (!device_id || typeof device_id !== 'string') return null;
  if (typeof latitude !== 'number' || latitude < -90 || latitude > 90) return null;
  if (typeof longitude !== 'number' || longitude < -180 || longitude > 180) return null;
  if (!timestamp || typeof timestamp !== 'string') return null;
  
  // Validate timestamp
  if (isNaN(Date.parse(timestamp))) return null;
  
  return {
    device_id,
    latitude,
    longitude,
    timestamp,
    accuracy: typeof accuracy === 'number' ? accuracy : undefined
  };
}

/**
 * POST handler for location updates
 */
export async function POST(request: NextRequest) {
  console.log('Location update request received');
  
  try {
    // Parse request body
    let body;
    try {
      body = await request.json();
    } catch (error) {
      console.error('Invalid JSON in request body:', error);
      return NextResponse.json({
        success: false,
        error: 'Invalid JSON in request body'
      } as LocationUpdateResponse, { status: 400 });
    }

    // Handle Overland GPS format (locations array) or simple format
    let locationData;
    if (body.locations && Array.isArray(body.locations) && body.locations.length > 0) {
      // Overland GPS format - use the first location
      const location = body.locations[0];
      locationData = {
        device_id: location.properties.device_id,
        latitude: location.geometry.coordinates[1],
        longitude: location.geometry.coordinates[0], 
        timestamp: location.properties.timestamp,
        accuracy: location.properties.horizontal_accuracy
      };
    } else {
      // Simple format
      locationData = body;
    }

    // Validate request
    const validatedRequest = validateLocationRequest(locationData);
    if (!validatedRequest) {
      console.error('Invalid location request format');
      return NextResponse.json({
        success: false,
        error: 'Invalid request format'
      } as LocationUpdateResponse, { status: 400 });
    }

    const supabase = createServiceClient();

    // Step 1: Look up device mapping
    const { data: deviceMapping, error: deviceError } = await supabase
      .from('device_mappings')
      .select('*')
      .eq('device_id', validatedRequest.device_id)
      .eq('enabled', true)
      .single();

    if (deviceError || !deviceMapping) {
      console.error('Device mapping not found:', validatedRequest.device_id);
      return NextResponse.json({
        success: false,
        error: 'Device not registered'
      } as LocationUpdateResponse, { status: 404 });
    }

    console.log(`Processing location for user: ${deviceMapping.id_user}`);

    // Step 2: Get all geofences user is a member of
    const { data: userGeofences, error: geofenceError } = await supabase
      .from('geofence_members')
      .select(`
        *,
        geofences!inner(*)
      `)
      .eq('id_user', deviceMapping.id_user);

    if (geofenceError) {
      console.error('Error fetching user geofences:', geofenceError);
      return NextResponse.json({
        success: false,
        error: 'Failed to fetch geofences'
      } as LocationUpdateResponse, { status: 500 });
    }

    if (!userGeofences || userGeofences.length === 0) {
      console.log('User is not a member of any geofences');
      // Update device last seen timestamp
      await supabase
        .from('device_mappings')
        .update({ last_location_update: new Date().toISOString() })
        .eq('device_id', validatedRequest.device_id);

      return NextResponse.json({
        success: true,
        message: 'Location processed - no geofences'
      } as LocationUpdateResponse);
    }

    // Step 3: Process each geofence the user is a member of
    let statusUpdated = false;
    let updatedGeofenceId: string | undefined;

    for (const memberData of userGeofences) {
      const member = memberData as GeofenceMember & { geofences: Geofence };
      const geofence = member.geofences;
      
      console.log(`Checking geofence: ${geofence.name} (${geofence.id_geofence})`);
      
      // Calculate new status based on location and hysteresis
      const newStatus = calculateGeofenceStatus(
        { latitude: validatedRequest.latitude, longitude: validatedRequest.longitude },
        geofence,
        member.status
      );

      // Update status if it changed
      if (newStatus !== member.status) {
        console.log(`Status change for ${geofence.name}: ${member.status} -> ${newStatus}`);
        
        const { error: updateError } = await supabase
          .from('geofence_members')
          .update({
            status: newStatus,
            last_updated: new Date().toISOString(),
            last_gps_update: validatedRequest.timestamp
          })
          .eq('id_geofence', geofence.id_geofence)
          .eq('id_user', deviceMapping.id_user);

        if (updateError) {
          console.error('Error updating member status:', updateError);
        } else {
          statusUpdated = true;
          updatedGeofenceId = geofence.id_geofence;
        }
      } else {
        console.log(`No status change needed for ${geofence.name}: ${member.status}`);
      }
    }

    // Step 4: Update device last seen timestamp
    await supabase
      .from('device_mappings')
      .update({ last_location_update: new Date().toISOString() })
      .eq('device_id', validatedRequest.device_id);

    console.log(`Location processing complete. Status updated: ${statusUpdated}`);

    return NextResponse.json({
      result: 'ok'
    });

  } catch (error) {
    console.error('Unexpected error processing location:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    } as LocationUpdateResponse, { status: 500 });
  }
}

/**
 * GET handler for testing
 */
export async function GET() {
  return NextResponse.json({
    status: 'ok',
    message: 'Location update endpoint is running',
    timestamp: new Date().toISOString()
  });
} 