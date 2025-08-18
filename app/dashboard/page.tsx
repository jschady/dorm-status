'use client';

import React, { useState } from 'react';
import { SignOutButton } from '@clerk/nextjs';
import { useAuth } from '@clerk/nextjs';
import { useGeofences } from '../(dashboard)/(lib)/hooks/use-geofences';
import { GeofenceListItem } from '../(dashboard)/(lib)/types';
import { GeofenceList } from '../(dashboard)/(components)/geofence/geofence-list';
import { CreateGeofenceModal } from '../(dashboard)/(components)/modals/create-geofence-modal';
import { InviteShareModal } from '../(dashboard)/(components)/modals/invite-share-modal';
import { DeviceManagementCard } from '../(dashboard)/(components)/device/device-management-card';
import { 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  UserGroupIcon,
  MapPinIcon,
  PlusIcon
} from '@heroicons/react/24/outline';

export default function DashboardPage() {
  const { isSignedIn, isLoaded } = useAuth();
  
  const {
    geofences,
    isLoading: isLoadingGeofences,
    error: geofencesError,
    refreshGeofences,
    addGeofence,
    removeGeofence,
  } = useGeofences();

  // Modal states
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [showShareModal, setShowShareModal] = useState(false);
  const [selectedGeofence, setSelectedGeofence] = useState<GeofenceListItem | null>(null);

  // Show loading while auth is initializing
  if (!isLoaded) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  // Redirect to sign-in if not authenticated (this should not happen due to middleware)
  if (!isSignedIn) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-lg font-medium text-gray-900">Please sign in to continue</h2>
          <p className="mt-2 text-sm text-gray-600">
            You need to be authenticated to access the dashboard.
          </p>
        </div>
      </div>
    );
  }

  const handleCreateGeofence = () => {
    setIsCreateModalOpen(true);
  };

  const handleGeofenceCreated = (geofence: any) => {
    addGeofence(geofence);
    setIsCreateModalOpen(false);
  };

  const handleDeleteGeofence = async (geofenceId: string) => {
    try {
      const response = await fetch(`/api/geofences/${geofenceId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete geofence');
      }

      removeGeofence(geofenceId);
    } catch (error) {
      console.error('Failed to delete geofence:', error);
      // You could show a toast notification here
    }
  };

  // Handle geofence sharing
  const handleShare = (geofence: GeofenceListItem) => {
    setSelectedGeofence(geofence);
    setShowShareModal(true);
  };

  // Handle share modal close
  const handleShareModalClose = () => {
    setShowShareModal(false);
    setSelectedGeofence(null);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation Header */}
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-semibold text-gray-900">
                Tiger Dorm Dashboard
              </h1>
            </div>
            <div className="flex items-center space-x-4">
              <SignOutButton>
                <button className="bg-gray-100 hover:bg-gray-200 text-gray-700 px-3 py-2 rounded-md text-sm font-medium transition-colors">
                  Sign Out
                </button>
              </SignOutButton>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          {/* Error Alert */}
          {geofencesError && (
            <div className="mb-6 rounded-md bg-red-50 p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <XCircleIcon className="h-5 w-5 text-red-400" />
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">
                    Error Loading Geofences
                  </h3>
                  <p className="mt-1 text-sm text-red-700">
                    {geofencesError}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* GPS Device Management */}
          <div className="mb-6">
            <DeviceManagementCard />
          </div>

          {/* Geofences Section */}
          <div className="bg-white shadow rounded-lg">
            <div className="px-4 py-5 sm:p-6">
              <GeofenceList
                geofences={geofences || []}
                isLoading={isLoadingGeofences}
                onCreateNew={() => setIsCreateModalOpen(true)}
                onRefresh={refreshGeofences}
                onShare={handleShare}
              />
            </div>
          </div>

          {/* Quick Stats */}
          {!isLoadingGeofences && geofences.length > 0 && (
            <div className="mt-6 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className="w-8 h-8 bg-indigo-500 rounded-md flex items-center justify-center">
                        <span className="text-white font-medium text-sm">
                          {geofences.length}
                        </span>
                      </div>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Total Geofences
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          {geofences.length}
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className="w-8 h-8 bg-green-500 rounded-md flex items-center justify-center">
                        <span className="text-white font-medium text-sm">
                          {geofences.filter(g => g.role === 'owner').length}
                        </span>
                      </div>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Owned
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          {geofences.filter(g => g.role === 'owner').length}
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className="w-8 h-8 bg-purple-500 rounded-md flex items-center justify-center">
                        <span className="text-white font-medium text-sm">
                          {geofences.filter(g => g.role === 'member').length}
                        </span>
                      </div>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Joined
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          {geofences.filter(g => g.role === 'member').length}
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white overflow-hidden shadow rounded-lg">
                <div className="p-5">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className="w-8 h-8 bg-orange-500 rounded-md flex items-center justify-center">
                        <span className="text-white font-medium text-sm">
                          {geofences.reduce((total, g) => total + g.member_count, 0)}
                        </span>
                      </div>
                    </div>
                    <div className="ml-5 w-0 flex-1">
                      <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">
                          Total Members
                        </dt>
                        <dd className="text-lg font-medium text-gray-900">
                          {geofences.reduce((total, g) => total + g.member_count, 0)}
                        </dd>
                      </dl>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Create Geofence Modal */}
      <CreateGeofenceModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onGeofenceCreated={handleGeofenceCreated}
      />

      {/* Share Invitation Modal */}
      {selectedGeofence && (
        <InviteShareModal
          isOpen={showShareModal}
          onClose={handleShareModalClose}
          geofence={{
            id_geofence: selectedGeofence.id_geofence,
            name: selectedGeofence.name,
            invite_code: selectedGeofence.invite_code
          }}
        />
      )}
    </div>
  );
} 