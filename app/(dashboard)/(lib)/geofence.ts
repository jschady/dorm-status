/**
 * Geofence Calculation Utilities for Location-Based Status System
 * Implements distance calculations and hysteresis logic for status determination
 */

import type { Geofence, GeofenceMember } from './database-client';

/**
 * Coordinate pair for distance calculations
 */
export interface Coordinates {
  latitude: number;
  longitude: number;
}

/**
 * Result of geofence boundary calculation
 */
export interface GeofenceResult {
  inside_boundary: boolean;
  distance_meters: number;
  status_should_change: boolean;
  new_status?: 'IN_ROOM' | 'AWAY';
  calculation_time_ms: number;
  hysteresis_applied: boolean;
  geofence_id: string;
  geofence_name: string;
}

/**
 * Calculate the great circle distance between two GPS coordinates using the Haversine formula
 * 
 * Formula: a = sin²(Δφ/2) + cos φ1 ⋅ cos φ2 ⋅ sin²(Δλ/2)
 *          c = 2 ⋅ atan2( √a, √(1−a) )
 *          d = R ⋅ c
 * 
 * @param point1 First GPS coordinate
 * @param point2 Second GPS coordinate
 * @returns Distance in meters
 */
export function calculateDistance(point1: Coordinates, point2: Coordinates): number {
  const R = 6371000; // Earth's radius in meters
  
  // Convert degrees to radians
  const φ1 = point1.latitude * Math.PI / 180;
  const φ2 = point2.latitude * Math.PI / 180;
  const Δφ = (point2.latitude - point1.latitude) * Math.PI / 180;
  const Δλ = (point2.longitude - point1.longitude) * Math.PI / 180;

  // Apply Haversine formula
  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
           Math.cos(φ1) * Math.cos(φ2) *
           Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

/**
 * Validate GPS coordinates are within valid ranges
 * @param coords Coordinates to validate
 * @returns True if valid, false otherwise
 */
export function validateCoordinates(coords: Coordinates): boolean {
  const { latitude, longitude } = coords;

  // Check if coordinates are numbers
  if (typeof latitude !== 'number' || typeof longitude !== 'number') {
    return false;
  }

  // Check for invalid values (NaN, Infinity)
  if (!isFinite(latitude) || !isFinite(longitude)) {
    return false;
  }

  // Check latitude range (-90 to 90)
  if (latitude < -90 || latitude > 90) {
    return false;
  }

  // Check longitude range (-180 to 180)
  if (longitude < -180 || longitude > 180) {
    return false;
  }

  return true;
}

/**
 * Determine if status should change based on location, geofence, and hysteresis logic
 * 
 * Hysteresis prevents rapid status changes when near boundary:
 * - To enter: distance must be < (radius - hysteresis)
 * - To exit: distance must be > (radius + hysteresis)
 * - In between: maintain previous status
 * 
 * @param location Current GPS coordinate
 * @param geofence Geofence configuration
 * @param currentStatus Current location status
 * @returns Geofence result with status change determination
 */
export function determineStatusChange(
  location: Coordinates,
  geofence: Geofence,
  currentStatus: 'IN_ROOM' | 'AWAY'
): GeofenceResult {
  const startTime = performance.now();

  // Validate coordinates
  if (!validateCoordinates(location)) {
    throw new Error('Invalid location coordinates');
  }

  const geofenceCenter: Coordinates = {
    latitude: geofence.center_latitude,
    longitude: geofence.center_longitude
  };

  // Calculate distance to geofence center
  const distance = calculateDistance(location, geofenceCenter);

  // Calculate hysteresis boundaries
  const radius = geofence.radius_meters;
  const hysteresis = geofence.hysteresis_meters;
  const enterRadius = radius - hysteresis;  // Smaller radius to enter
  const exitRadius = radius + hysteresis;   // Larger radius to exit

  let statusShouldChange = false;
  let newStatus: 'IN_ROOM' | 'AWAY' | undefined;
  let hysteresisApplied = false;

  // Determine status based on hysteresis logic
  if (distance <= enterRadius) {
    // Clearly inside - should be IN_ROOM
    if (currentStatus === 'AWAY') {
      statusShouldChange = true;
      newStatus = 'IN_ROOM';
    }
  } else if (distance >= exitRadius) {
    // Clearly outside - should be AWAY
    if (currentStatus === 'IN_ROOM') {
      statusShouldChange = true;
      newStatus = 'AWAY';
    }
  } else {
    // In hysteresis zone - maintain previous status
    hysteresisApplied = true;
  }

  const calculationTime = performance.now() - startTime;

  return {
    inside_boundary: distance <= radius,
    distance_meters: distance,
    status_should_change: statusShouldChange,
    new_status: newStatus,
    calculation_time_ms: calculationTime,
    hysteresis_applied: hysteresisApplied,
    geofence_id: geofence.id_geofence,
    geofence_name: geofence.name
  };
}

/**
 * Process location update for multiple geofences
 * Returns array of results for each geofence the user is a member of
 * 
 * @param location Current GPS coordinate
 * @param userGeofences Array of geofence memberships with geofence data
 * @returns Array of geofence results
 */
export function processMultipleGeofences(
  location: Coordinates,
  userGeofences: Array<GeofenceMember & { geofences: Geofence }>
): GeofenceResult[] {
  const results: GeofenceResult[] = [];

  for (const memberData of userGeofences) {
    const member = memberData;
    const geofence = member.geofences;

    try {
      const result = determineStatusChange(location, geofence, member.status);
      results.push(result);
    } catch (error) {
      console.error(`Error processing geofence ${geofence.name}:`, error);
      // Continue processing other geofences
    }
  }

  return results;
}

/**
 * Simple boundary check without hysteresis (for testing/debugging)
 * @param location GPS coordinate to check
 * @param geofence Geofence configuration
 * @returns Basic geofence result
 */
export function isInsideGeofence(
  location: Coordinates,
  geofence: Geofence
): { inside: boolean; distance: number } {
  const geofenceCenter: Coordinates = {
    latitude: geofence.center_latitude,
    longitude: geofence.center_longitude
  };

  const distance = calculateDistance(location, geofenceCenter);
  const inside = distance <= geofence.radius_meters;

  return { inside, distance };
}

/**
 * Create test location coordinates for debugging
 * @param centerLat Base latitude
 * @param centerLon Base longitude
 * @param offsetMeters Distance offset in meters
 * @param bearing Direction in degrees (0 = north, 90 = east)
 * @returns New coordinates offset by the specified distance and bearing
 */
export function createTestLocation(
  centerLat: number,
  centerLon: number,
  offsetMeters: number,
  bearing: number
): Coordinates {
  const R = 6371000; // Earth's radius in meters
  const lat1 = centerLat * Math.PI / 180;
  const lon1 = centerLon * Math.PI / 180;
  const bearingRad = bearing * Math.PI / 180;

  const lat2 = Math.asin(
    Math.sin(lat1) * Math.cos(offsetMeters / R) +
    Math.cos(lat1) * Math.sin(offsetMeters / R) * Math.cos(bearingRad)
  );

  const lon2 = lon1 + Math.atan2(
    Math.sin(bearingRad) * Math.sin(offsetMeters / R) * Math.cos(lat1),
    Math.cos(offsetMeters / R) - Math.sin(lat1) * Math.sin(lat2)
  );

  return {
    latitude: lat2 * 180 / Math.PI,
    longitude: lon2 * 180 / Math.PI
  };
}

/**
 * Get status summary for multiple geofence results
 * @param results Array of geofence results
 * @returns Summary of status changes
 */
export function getStatusSummary(results: GeofenceResult[]): {
  totalGeofences: number;
  statusChanges: number;
  insideCount: number;
  outsideCount: number;
  hysteresisCount: number;
} {
  return {
    totalGeofences: results.length,
    statusChanges: results.filter(r => r.status_should_change).length,
    insideCount: results.filter(r => r.inside_boundary).length,
    outsideCount: results.filter(r => !r.inside_boundary).length,
    hysteresisCount: results.filter(r => r.hysteresis_applied).length
  };
} 