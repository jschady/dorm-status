'use client';

import React, { useState } from 'react';
import { XMarkIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import { EditGeofenceForm, UpdateGeofenceRequest } from '../geofence/edit-geofence-form';

export interface GeofenceSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  geofence: {
    id_geofence: string;
    name: string;
    center_latitude: number;
    center_longitude: number;
    radius_meters: number;
    hysteresis_meters: number;
  };
  onGeofenceUpdated?: (updatedGeofence: any) => void;
}

export function GeofenceSettingsModal({ 
  isOpen, 
  onClose, 
  geofence, 
  onGeofenceUpdated 
}: GeofenceSettingsModalProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<any | null>(null);

  // Handle form submission
  const handleSubmit = async (formData: UpdateGeofenceRequest) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`/api/geofences/${geofence.id_geofence}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `Failed to update geofence: ${response.status}`);
      }

      // Success - show success message
      setSuccess(data);
      
      // Notify parent component
      if (onGeofenceUpdated) {
        onGeofenceUpdated(data);
      }
      
      // Close modal after a short delay to let user see success message
      setTimeout(() => {
        handleClose();
      }, 2000);

    } catch (error) {
      console.error('Failed to update geofence:', error);
      setError(error instanceof Error ? error.message : 'Failed to update geofence settings');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle modal close with cleanup
  const handleClose = () => {
    setError(null);
    setSuccess(null);
    setIsLoading(false);
    onClose();
  };

  // Don't render if modal is not open
  if (!isOpen) {
    return null;
  }

  const initialData: UpdateGeofenceRequest = {
    name: geofence.name,
    center_latitude: geofence.center_latitude,
    center_longitude: geofence.center_longitude,
    radius_meters: geofence.radius_meters,
    hysteresis_meters: geofence.hysteresis_meters
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-black bg-opacity-25 transition-opacity"
        onClick={handleClose}
      />
      
      {/* Modal Content */}
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="relative w-full max-w-2xl bg-white rounded-lg shadow-xl">
          {/* Modal Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200">
            <h2 className="text-xl font-semibold text-gray-900">
              Edit Geofence
            </h2>
            <button
              onClick={handleClose}
              disabled={isLoading}
              className="text-gray-400 hover:text-gray-500 focus:outline-none focus:text-gray-500 disabled:opacity-50"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>

          {/* Modal Body */}
          <div className="p-6">
            {/* Success Message */}
            {success && (
              <div className="mb-6 rounded-md bg-green-50 p-4">
                <div className="flex">
                  <CheckCircleIcon className="h-5 w-5 text-green-400" />
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-green-800">
                      Geofence Updated Successfully!
                    </h3>
                    <div className="mt-2 text-sm text-green-700">
                      <p>
                        <strong>{success.name}</strong> has been updated with your new settings.
                      </p>
                      <p className="mt-1">
                        All members will see the updated geofence configuration.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Error Message */}
            {error && (
              <div className="mb-6 rounded-md bg-red-50 p-4">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-red-800">
                      Failed to Update Geofence
                    </h3>
                    <p className="mt-1 text-sm text-red-700">
                      {error}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Form */}
            {!success && (
              <EditGeofenceForm
                initialData={initialData}
                onSubmit={handleSubmit}
                isLoading={isLoading}
                onCancel={handleClose}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
} 