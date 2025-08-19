import { DashboardClient } from './dashboard-client';

/**
 * Dashboard Server Component
 * 
 * Simple wrapper that renders the client component.
 * Data fetching is now handled client-side by the useGeofences hook
 * for better real-time updates and error handling.
 */
export default function DashboardPage() {
  return <DashboardClient />;
} 