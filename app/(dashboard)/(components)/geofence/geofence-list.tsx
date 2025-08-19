'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { GeofenceListProps } from '../../(lib)/types';
import { GeofenceCard } from './geofence-card';
import { PlusIcon, MapIcon, ArrowPathIcon } from '@heroicons/react/24/outline';

export function GeofenceList({ 
  geofences, 
  isLoading = false, 
  onCreateNew, 
  onRefresh
}: GeofenceListProps) {
  const router = useRouter();
  
  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Loading Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <MapIcon className="h-6 w-6 text-gray-400" />
            <h2 className="text-xl font-semibold text-gray-900">Your Geofences</h2>
          </div>
          <div className="flex space-x-3">
            <button
              disabled={true}
              className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-400 bg-gray-100 cursor-not-allowed"
            >
              <ArrowPathIcon className="h-4 w-4 mr-2" />
              Refresh
            </button>
            <button
              disabled={true}
              className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-gray-400 cursor-not-allowed"
            >
              <PlusIcon className="h-4 w-4 mr-2" />
              Create Geofence
            </button>
          </div>
        </div>

        {/* Loading Cards */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="bg-white shadow rounded-lg border border-gray-200">
              <div className="px-4 py-5 sm:p-6">
                <div className="animate-pulse">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gray-200 rounded-lg"></div>
                    <div className="flex-1">
                      <div className="h-4 bg-gray-200 rounded w-3/4 mb-2"></div>
                      <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                    </div>
                  </div>
                  <div className="mt-4 flex justify-between">
                    <div className="h-3 bg-gray-200 rounded w-20"></div>
                    <div className="h-3 bg-gray-200 rounded w-16"></div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-4 sm:space-y-0">
        <div className="flex items-center space-x-2">
          <MapIcon className="h-6 w-6 text-indigo-600" />
          <h2 className="text-xl font-semibold text-gray-900">Your Geofences</h2>
          {geofences.length > 0 && (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800">
              {geofences.length}
            </span>
          )}
        </div>
        
        <div className="flex space-x-3">
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
            >
              <ArrowPathIcon className="h-4 w-4 mr-2" />
              Refresh
            </button>
          )}
          
          {onCreateNew && (
            <button
              onClick={onCreateNew}
              className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors"
            >
              <PlusIcon className="h-4 w-4 mr-2" />
              Create Geofence
            </button>
          )}
        </div>
      </div>

      {/* Empty State */}
      {geofences.length === 0 ? (
        <div className="text-center py-12">
          <MapIcon className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-4 text-sm font-medium text-gray-900">No geofences yet</h3>
          <p className="mt-2 text-sm text-gray-500 max-w-sm mx-auto">
            Get started by creating your first geofence. Set up your dorm room location and invite your roommates!
          </p>
          {onCreateNew && (
            <div className="mt-6">
              <button
                onClick={onCreateNew}
                className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                <PlusIcon className="h-4 w-4 mr-2" />
                Create Your First Geofence
              </button>
            </div>
          )}
        </div>
      ) : (
        /* Geofence Grid */
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {geofences.map((geofence) => (
            <GeofenceCard
              key={geofence.id_geofence}
              geofence={geofence}
              onViewDetails={(geofenceId) => {
                router.push(`/dashboard/${geofenceId}`);
              }}
            />
          ))}
        </div>
      )}

      {/* Footer Info */}
      {geofences.length > 0 && (
        <div className="text-center text-sm text-gray-500">
          <p>
            You're a member of {geofences.length} {geofences.length === 1 ? 'geofence' : 'geofences'}.{' '}
            {geofences.filter(g => g.role === 'owner').length > 0 && (
              <>You own {geofences.filter(g => g.role === 'owner').length} of them.</>
            )}
          </p>
        </div>
      )}
    </div>
  );
} 