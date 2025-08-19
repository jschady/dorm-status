import { getGeofenceDetails } from '../../(dashboard)/(lib)/supabase/geofences';
import { getGeofenceMembers } from '../../(dashboard)/(lib)/supabase/members';
import { GeofenceDetailClient } from './geofence-detail-client';
import { ExclamationTriangleIcon, ArrowLeftIcon } from '@heroicons/react/24/outline';
import Link from 'next/link';

// Force dynamic rendering since we use server actions that call auth() -> headers()
export const dynamic = 'force-dynamic';

interface GeofenceDetailPageProps {
  params: Promise<{ geofenceId: string }>;
}

/**
 * Geofence Detail Server Component
 * 
 * Fetches initial geofence and members data server-side for better performance
 * and passes it to the client component for interactive UI.
 */
export default async function GeofenceDetailPage({ params }: GeofenceDetailPageProps) {
  const { geofenceId } = await params;
  
  // Fetch geofence and members data server-side in parallel
  const [geofenceResult, membersResult] = await Promise.all([
    getGeofenceDetails(geofenceId),
    getGeofenceMembers(geofenceId)
  ]);

  // Handle geofence not found or access denied
  if (!geofenceResult.success) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl p-8 max-w-md w-full text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-yellow-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-4">Access Denied</h1>
          <p className="text-gray-400 mb-6">
            {geofenceResult.error}
          </p>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg transition-colors"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  // Handle members fetch error (show geofence but with empty members)
  const members = membersResult.success ? membersResult.data : [];
  if (!membersResult.success) {
    console.error('Failed to fetch members:', membersResult.error);
  }

  // Pass server-fetched data to client component
  return (
    <GeofenceDetailClient 
      initialGeofence={geofenceResult.data}
      initialMembers={members}
      geofenceId={geofenceId}
    />
  );
} 