import { getGeofences } from '../(dashboard)/(lib)/supabase/geofences';
import { DashboardClient } from './dashboard-client';

// Force dynamic rendering since we use auth() which calls headers()
export const dynamic = 'force-dynamic';

/**
 * Dashboard Server Component
 * 
 * Fetches initial geofence data server-side for better performance
 * and passes it to the client component for interactive UI.
 */
export default async function DashboardPage() {
  // Fetch geofences data server-side
  const result = await getGeofences();

  // Handle server-side errors
  if (!result.success) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-lg font-medium text-red-600 mb-4">
            Error Loading Dashboard
          </h2>
          <p className="text-sm text-gray-600 mb-4">
            {result.error}
          </p>
          <p className="text-xs text-gray-500">
            Please refresh the page to try again
          </p>
        </div>
      </div>
    );
  }

  // Pass server-fetched data to client component
  return <DashboardClient initialGeofences={result.data} />;
} 