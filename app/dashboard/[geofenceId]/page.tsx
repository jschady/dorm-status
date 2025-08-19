'use client';

import React, { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { useUser } from '@clerk/nextjs';
import { 
  MapPinIcon, 
  ArrowLeftIcon, 
  ShareIcon,
  Cog6ToothIcon,
  ExclamationTriangleIcon,
  TrashIcon
} from '@heroicons/react/24/outline';
import Link from 'next/link';
import { MemberList } from '../../(dashboard)/(components)/members/member-list';
import { InviteShareModal } from '../../(dashboard)/(components)/modals/invite-share-modal';
import { GeofenceSettingsModal } from '../../(dashboard)/(components)/modals/geofence-settings-modal';
import { DeleteGeofenceModal } from '../../(dashboard)/(components)/modals/delete-geofence-modal';
import { useGeofenceDetails } from '../../(dashboard)/(lib)/hooks/use-geofence-details';
import { useMembers } from '../../(dashboard)/(lib)/hooks/use-members';

export default function GeofenceDetailPage() {
  const params = useParams();
  const router = useRouter();
  const { user } = useUser();
  const geofenceId = params.geofenceId as string;
  
  const { geofence, isLoading: geofenceLoading, error: geofenceError } = useGeofenceDetails(geofenceId);
  const { members, isLoading: membersLoading, error: membersError } = useMembers(geofenceId);
  
  const [showShareModal, setShowShareModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  
  const isOwner = geofence?.role === 'owner';
  
  // Loading state
  if (geofenceLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
      </div>
    );
  }
  
  // Geofence not found
  if (!geofence) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl p-8 max-w-md w-full text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-yellow-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-4">Geofence Not Found</h1>
          <p className="text-gray-400 mb-6">
            This geofence doesn't exist or you don't have access to it.
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

  const handleDeleteGeofence = async (geofenceId: string) => {
    try {
      const response = await fetch(`/api/geofences/${geofenceId}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete geofence');
      }

      // Redirect to dashboard after successful deletion
      router.push('/dashboard');
    } catch (error) {
      console.error('Failed to delete geofence:', error);
      throw error; // Re-throw so modal can handle it
    }
  };

  const formatDate = (timestamp: string) => {
    return new Date(timestamp).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="max-w-4xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <button
              onClick={() => router.back()}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <ArrowLeftIcon className="h-6 w-6" />
            </button>
            <div>
              <h1 className="text-3xl font-bold text-white">{geofence.name}</h1>
              <p className="text-gray-400">
                {isOwner ? 'You own this geofence' : 'You are a member'}
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {isOwner && (
              <button
                onClick={() => setShowShareModal(true)}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg transition-colors"
              >
                <ShareIcon className="h-4 w-4" />
                Share
              </button>
            )}
            
            {isOwner && (
              <button 
                onClick={() => setShowSettingsModal(true)}
                className="flex items-center gap-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white font-semibold rounded-lg transition-colors"
              >
                <Cog6ToothIcon className="h-4 w-4" />
                Settings
              </button>
            )}
            
            {isOwner && (
              <button 
                onClick={() => setShowDeleteModal(true)}
                className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-semibold rounded-lg transition-colors"
              >
                <TrashIcon className="h-4 w-4" />
                Delete
              </button>
            )}
          </div>
        </div>

        {/* Geofence Info */}
        <div className="bg-gray-800 rounded-2xl p-6 mb-8">
          <div className="flex items-start gap-4">
            <div className="bg-indigo-600 rounded-lg p-3">
              <MapPinIcon className="h-8 w-8 text-white" />
            </div>
            <div className="flex-1">
              <h2 className="text-xl font-semibold text-white mb-4">Location Details</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-400">Latitude:</span>
                  <span className="text-white ml-2 font-mono">
                    {geofence.center_latitude?.toFixed(6) || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-gray-400">Longitude:</span>
                  <span className="text-white ml-2 font-mono">
                    {geofence.center_longitude?.toFixed(6) || 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-gray-400">Radius:</span>
                  <span className="text-white ml-2">
                    {geofence.radius_meters ? `${geofence.radius_meters}m` : 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-gray-400">Created:</span>
                  <span className="text-white ml-2">
                    {formatDate(geofence.created_at)}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Invitation Info for Owners */}
          {isOwner && (
            <div className="mt-6 pt-6 border-t border-gray-700">
              <h3 className="text-lg font-semibold text-white mb-3">Invitation Link</h3>
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-300 text-sm mb-1">
                      Share this code with friends:
                    </p>
                    <code className="text-indigo-400 font-mono text-lg">
                      {geofence.invite_code}
                    </code>
                  </div>
                  <button
                    onClick={() => setShowShareModal(true)}
                    className="text-indigo-400 hover:text-indigo-300 transition-colors"
                  >
                    <ShareIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Members Section */}
        <div className="bg-gray-800 rounded-2xl p-6">
          {(membersError || geofenceError) && (
            <div className="bg-red-900/20 border border-red-500 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-3">
                <ExclamationTriangleIcon className="h-5 w-5 text-red-400 flex-shrink-0" />
                <p className="text-red-400 text-sm">{membersError || geofenceError}</p>
              </div>
            </div>
          )}
          
          <MemberList 
            members={members}
            isLoading={membersLoading}
            currentUserId={user?.id}
          />
        </div>

        {/* Share Modal */}
        <InviteShareModal
          isOpen={showShareModal}
          onClose={() => setShowShareModal(false)}
          geofence={{
            id_geofence: geofence.id_geofence,
            name: geofence.name,
            invite_code: geofence.invite_code
          }}
        />

        {/* Settings Modal */}
        {isOwner && (
          <GeofenceSettingsModal
            isOpen={showSettingsModal}
            onClose={() => setShowSettingsModal(false)}
            geofence={geofence}
            onGeofenceUpdated={(updatedGeofence) => {
              // Refresh the geofence data
              // The hook should automatically refresh when the component re-renders
              console.log('Geofence updated:', updatedGeofence);
            }}
          />
        )}

        {/* Delete Confirmation Modal */}
        {isOwner && (
          <DeleteGeofenceModal
            isOpen={showDeleteModal}
            onClose={() => setShowDeleteModal(false)}
            onConfirm={handleDeleteGeofence}
            geofence={{
              id_geofence: geofence.id_geofence,
              name: geofence.name
            }}
          />
        )}
      </div>
    </div>
  );
} 