'use server';

import { auth } from '@clerk/nextjs/server';
import { createServerClient, createAdminClient } from './client';
import { revalidatePath } from 'next/cache';
import type { ServerActionResult } from './geofences';

/**
 * Device Management Server Actions
 * 
 * This module replaces device-related API routes with Server Actions
 * for better performance, simpler error handling, and improved caching.
 * 
 * Replaces:
 * - GET /api/device-mapping
 * - POST /api/device-mapping  
 * - POST /api/location-update
 */

// Device mapping interface
interface DeviceMapping {
  id: string;
  device_id: string;
  id_user: string;
  enabled: boolean;
  created_at: string;
  last_location_update?: string;
}

// Location update interfaces
interface LocationUpdateRequest {
  device_id: string;
  latitude: number;
  longitude: number;
  timestamp: string;
  accuracy?: number;
}

/**
 * Get current user's device mapping
 * 
 * Replaces: GET /api/device-mapping
 * 
 * @returns Promise<ServerActionResult<DeviceMapping | null>>
 * 
 * @example
 * ```tsx
 * const result = await getDeviceMapping();
 * if (result.success && result.data) {
 *   console.log('Device:', result.data.device_id);
 * }
 * ```
 */
export async function getDeviceMapping(): Promise<ServerActionResult<DeviceMapping | null>> {
  try {
    // Verify authentication
    const { getToken, userId } = await auth();
    
    if (!userId) {
      return {
        success: false,
        error: 'Unauthorized - Please sign in to view device'
      };
    }

    // Create authenticated client  
    const token = await getToken({ template: 'supabase' });
    const supabase = createServerClient(token);

    // Get user's device mapping
    const { data, error } = await supabase
      .from('device_mappings')
      .select('*')
      .eq('id_user', userId)
      .single();

    if (error && error.code !== 'PGRST116') {
      console.error('Error fetching device mapping:', error);
      return {
        success: false,
        error: 'Failed to fetch device',
        details: error
      };
    }

    return { success: true, data: data || null };

  } catch (error) {
    console.error('Device mapping retrieval error:', error);
    return {
      success: false,
      error: 'Internal server error',
      details: error
    };
  }
}

/**
 * Register or update user's device mapping
 * 
 * Replaces: POST /api/device-mapping
 * 
 * @param deviceId - The device ID to register
 * @param enabled - Whether the device is enabled (default: true)
 * @returns Promise<ServerActionResult<DeviceMapping>>
 * 
 * @example
 * ```tsx
 * const result = await updateDeviceMapping('my-device-123', true);
 * if (result.success) {
 *   console.log('Device registered:', result.data.device_id);
 * }
 * ```
 */
export async function updateDeviceMapping(
  deviceId: string, 
  enabled: boolean = true
): Promise<ServerActionResult<DeviceMapping>> {
  try {
    // Verify authentication
    const { getToken, userId } = await auth();
    
    if (!userId) {
      return {
        success: false,
        error: 'Unauthorized - Please sign in to register device'
      };
    }

    // Validate input
    if (!deviceId || typeof deviceId !== 'string') {
      return {
        success: false,
        error: 'Device ID is required'
      };
    }

    // Create authenticated client
    const token = await getToken({ template: 'supabase' });
    const supabase = createServerClient(token);

    // Check if user already has a device mapping
    const { data: existing, error: checkError } = await supabase
      .from('device_mappings')
      .select('*')
      .eq('id_user', userId)
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      console.error('Error checking existing device:', checkError);
      return {
        success: false,
        error: 'Database error',
        details: checkError
      };
    }

    let result;

    if (existing) {
      // Update existing device mapping
      const { data, error } = await supabase
        .from('device_mappings')
        .update({
          device_id: deviceId.trim(),
          enabled,
          last_location_update: new Date().toISOString()
        })
        .eq('id_user', userId)
        .select()
        .single();

      if (error) {
        console.error('Error updating device mapping:', error);
        return {
          success: false,
          error: 'Failed to update device',
          details: error
        };
      }

      result = data;
    } else {
      // Create new device mapping
      const { data, error } = await supabase
        .from('device_mappings')
        .insert({
          device_id: deviceId.trim(),
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
          return {
            success: false,
            error: 'Device ID already registered'
          };
        }
        return {
          success: false,
          error: 'Failed to register device',
          details: error
        };
      }

      result = data;
    }

    // Revalidate relevant paths
    revalidatePath('/dashboard');

    return { 
      success: true, 
      data: result
    };

  } catch (error) {
    console.error('Device mapping error:', error);
    return {
      success: false,
      error: 'Internal server error',
      details: error
    };
  }
}

/**
 * Delete user's device mapping (permanently remove from database)
 * 
 * @returns Promise<ServerActionResult<void>>
 * 
 * @example
 * ```tsx
 * const result = await deleteDeviceMapping();
 * if (result.success) {
 *   console.log('Device successfully removed');
 * }
 * ```
 */
export async function deleteDeviceMapping(): Promise<ServerActionResult<void>> {
  try {
    // Verify authentication
    const { getToken, userId } = await auth();
    
    if (!userId) {
      return {
        success: false,
        error: 'Unauthorized - Please sign in to delete device'
      };
    }

    // Create authenticated client
    const token = await getToken({ template: 'supabase' });
    const supabase = createServerClient(token);

    // Delete the device mapping
    const { error: deleteError } = await supabase
      .from('device_mappings')
      .delete()
      .eq('id_user', userId);

    if (deleteError) {
      console.error('Error deleting device mapping:', deleteError);
      return {
        success: false,
        error: 'Failed to delete device',
        details: deleteError
      };
    }

    // Revalidate relevant paths
    revalidatePath('/dashboard');

    return { success: true, data: undefined };

  } catch (error) {
    console.error('Device deletion error:', error);
    return {
      success: false,
      error: 'Internal server error',
      details: error
    };
  }
}
