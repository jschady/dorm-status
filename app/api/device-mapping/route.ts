/**
 * Device Mapping API Route
 * Handles device registration, updates, and management for GPS tracking
 */

import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { createClient } from '@supabase/supabase-js';

interface DeviceMapping {
  id: string;
  device_id: string;
  id_user: string;
  enabled: boolean;
  created_at: string;
  last_location_update?: string;
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
 * GET - Get current user's device mapping
 */
export async function GET() {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const supabase = createServiceClient();

    // Get user's device mapping
    const { data, error } = await supabase
      .from('device_mappings')
      .select('*')
      .eq('id_user', userId)
      .single();

    if (error && error.code !== 'PGRST116') {
      console.error('Error fetching device mapping:', error);
      return NextResponse.json({ error: 'Failed to fetch device' }, { status: 500 });
    }

    return NextResponse.json({ device: data });

  } catch (error) {
    console.error('Unexpected error in GET device-mapping:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

/**
 * POST - Register or update user's device mapping
 */
export async function POST(request: NextRequest) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { device_id, enabled = true } = body;

    // Validate input
    if (!device_id || typeof device_id !== 'string') {
      return NextResponse.json({ error: 'Device ID is required' }, { status: 400 });
    }

    const supabase = createServiceClient();

    // Check if user already has a device mapping
    const { data: existing, error: checkError } = await supabase
      .from('device_mappings')
      .select('*')
      .eq('id_user', userId)
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      console.error('Error checking existing device:', checkError);
      return NextResponse.json({ error: 'Database error' }, { status: 500 });
    }

    let result;

    if (existing) {
      // Update existing device mapping
      const { data, error } = await supabase
        .from('device_mappings')
        .update({
          device_id: device_id.trim(),
          enabled,
          last_location_update: new Date().toISOString()
        })
        .eq('id_user', userId)
        .select()
        .single();

      if (error) {
        console.error('Error updating device mapping:', error);
        return NextResponse.json({ error: 'Failed to update device' }, { status: 500 });
      }

      result = data;
    } else {
      // Create new device mapping
      const { data, error } = await supabase
        .from('device_mappings')
        .insert({
          device_id: device_id.trim(),
          id_user: userId,
          enabled,
          created_at: new Date().toISOString(),
          last_location_update: new Date().toISOString()
        })
        .select()
        .single();

      if (error) {
        console.error('Error creating device mapping:', error);
        if (error.code === '23505') {
          return NextResponse.json({ error: 'Device ID already registered' }, { status: 409 });
        }
        return NextResponse.json({ error: 'Failed to register device' }, { status: 500 });
      }

      result = data;
    }

    return NextResponse.json({ 
      message: existing ? 'Device updated successfully' : 'Device registered successfully',
      device: result
    });

  } catch (error) {
    console.error('Unexpected error in POST device-mapping:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

/**
 * PUT - Update device settings (enable/disable)
 */
export async function PUT(request: NextRequest) {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await request.json();
    const { enabled } = body;

    if (typeof enabled !== 'boolean') {
      return NextResponse.json({ error: 'Enabled status is required' }, { status: 400 });
    }

    const supabase = createServiceClient();

    // Update device status
    const { data, error } = await supabase
      .from('device_mappings')
      .update({ enabled })
      .eq('id_user', userId)
      .select()
      .single();

    if (error) {
      console.error('Error updating device status:', error);
      return NextResponse.json({ error: 'Failed to update device status' }, { status: 500 });
    }

    return NextResponse.json({ 
      message: `Device ${enabled ? 'enabled' : 'disabled'} successfully`,
      device: data
    });

  } catch (error) {
    console.error('Unexpected error in PUT device-mapping:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

/**
 * DELETE - Remove user's device mapping
 */
export async function DELETE() {
  try {
    const { userId } = await auth();
    if (!userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const supabase = createServiceClient();

    // Delete device mapping
    const { error } = await supabase
      .from('device_mappings')
      .delete()
      .eq('id_user', userId);

    if (error) {
      console.error('Error deleting device mapping:', error);
      return NextResponse.json({ error: 'Failed to remove device' }, { status: 500 });
    }

    return NextResponse.json({ message: 'Device removed successfully' });

  } catch (error) {
    console.error('Unexpected error in DELETE device-mapping:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
} 