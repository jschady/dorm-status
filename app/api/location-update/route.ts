// app/api/location-update/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { createAdminClient } from '@/app/(dashboard)/(lib)/supabase/client';
import { determineStatusChange } from '@/app/(dashboard)/(lib)/geofence';
import type { Geofence } from '@/app/(dashboard)/(lib)/types';

// Simplified type for this file
interface LocationData {
  device_id: string;
  latitude: number;
  longitude: number;
  timestamp: string;
}

/**
 * POST handler for location updates from external GPS trackers
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    let locationData: LocationData;

    // Handle Overland GPS format or simple format
    if (body.locations && Array.isArray(body.locations) && body.locations.length > 0) {
      const loc = body.locations[0];
      locationData = {
        device_id: loc.properties.device_id,
        latitude: loc.geometry.coordinates[1],
        longitude: loc.geometry.coordinates[0],
        timestamp: loc.properties.timestamp,
      };
    } else {
      locationData = body;
    }
    
    // Create an admin client to bypass RLS for this system-level operation
    const supabase = createAdminClient();

    // 1. Find the user associated with this device ID
    const { data: deviceMapping } = await supabase
      .from('device_mappings')
      .select('id_user')
      .eq('device_id', locationData.device_id)
      .eq('enabled', true)
      .single();

    if (!deviceMapping) {
      return NextResponse.json({ error: 'Device not registered or disabled' }, { status: 404 });
    }

    // 2. Get all geofences this user is a member of
    const { data: memberships } = await supabase
      .from('geofence_members')
      .select('*, geofences(*)')
      .eq('id_user', deviceMapping.id_user);

    if (!memberships || memberships.length === 0) {
      // Still update the device's last seen time even if no geofences
      await supabase
        .from('device_mappings')
        .update({ last_location_update: new Date().toISOString() })
        .eq('device_id', locationData.device_id);
      return NextResponse.json({ result: 'ok', message: 'No geofences to process.' });
    }

    // 3. Process each geofence
    for (const member of memberships) {
      const geofence = member.geofences as Geofence;
      
      const result = determineStatusChange(
        { latitude: locationData.latitude, longitude: locationData.longitude },
        geofence,
        member.status as 'IN_ROOM' | 'AWAY'
      );

      if (result.status_should_change) {
        await supabase
          .from('geofence_members')
          .update({
            status: result.new_status,
            last_updated: new Date().toISOString(),
            last_gps_update: locationData.timestamp,
          })
          .eq('id_geofence', member.id_geofence)
          .eq('id_user', member.id_user);
      }
    }

    // 4. Update the device's last seen time
    await supabase
      .from('device_mappings')
      .update({ last_location_update: new Date().toISOString() })
      .eq('device_id', locationData.device_id);

    return NextResponse.json({ result: 'ok' });

  } catch (error) {
    console.error('Location update error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}