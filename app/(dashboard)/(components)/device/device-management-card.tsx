'use client';

import React, { useState, useEffect } from 'react';
import { 
  DevicePhoneMobileIcon, 
  PlusIcon, 
  CheckCircleIcon, 
  XCircleIcon,
  ExclamationTriangleIcon,
  TrashIcon,
  PencilIcon
} from '@heroicons/react/24/outline';
import { DeviceRegistrationModal } from '../modals/device-registration-modal';

interface DeviceMapping {
  id: string;
  device_id: string;
  id_user: string;
  enabled: boolean;
  created_at: string;
  last_location_update?: string;
}

export function DeviceManagementCard() {
  const [device, setDevice] = useState<DeviceMapping | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdating, setIsUpdating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showRegistrationModal, setShowRegistrationModal] = useState(false);

  // Fetch device data on component mount
  useEffect(() => {
    fetchDevice();
  }, []);

  const fetchDevice = async () => {
    try {
      setIsLoading(true);
      setError(null);

      const response = await fetch('/api/device-mapping');
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to fetch device');
      }

      setDevice(data.device);
    } catch (error) {
      console.error('Failed to fetch device:', error);
      setError(error instanceof Error ? error.message : 'Failed to fetch device');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleDeviceEnabled = async () => {
    if (!device) return;

    try {
      setIsUpdating(true);
      setError(null);

      const response = await fetch('/api/device-mapping', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          enabled: !device.enabled
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to update device');
      }

      setDevice(data.device);
    } catch (error) {
      console.error('Failed to update device:', error);
      setError(error instanceof Error ? error.message : 'Failed to update device');
    } finally {
      setIsUpdating(false);
    }
  };

  const removeDevice = async () => {
    if (!device || !confirm('Are you sure you want to remove this device? Location tracking will stop.')) {
      return;
    }

    try {
      setIsUpdating(true);
      setError(null);

      const response = await fetch('/api/device-mapping', {
        method: 'DELETE',
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to remove device');
      }

      setDevice(null);
    } catch (error) {
      console.error('Failed to remove device:', error);
      setError(error instanceof Error ? error.message : 'Failed to remove device');
    } finally {
      setIsUpdating(false);
    }
  };

  const handleDeviceRegistered = () => {
    // Refresh device data after successful registration
    fetchDevice();
  };

  const formatLastSeen = (timestamp?: string) => {
    if (!timestamp) return 'Never';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  const getStatusColor = (device: DeviceMapping | null) => {
    if (!device) return 'text-gray-400';
    if (!device.enabled) return 'text-yellow-600';
    
    const lastUpdate = device.last_location_update;
    if (!lastUpdate) return 'text-gray-400';
    
    const diffMs = new Date().getTime() - new Date(lastUpdate).getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    
    if (diffMins < 30) return 'text-green-600';
    if (diffMins < 60) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getStatusIcon = (device: DeviceMapping | null) => {
    if (!device) return XCircleIcon;
    if (!device.enabled) return ExclamationTriangleIcon;
    
    const lastUpdate = device.last_location_update;
    if (!lastUpdate) return XCircleIcon;
    
    const diffMs = new Date().getTime() - new Date(lastUpdate).getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    
    if (diffMins < 30) return CheckCircleIcon;
    if (diffMins < 60) return ExclamationTriangleIcon;
    return XCircleIcon;
  };

  const getStatusText = (device: DeviceMapping | null) => {
    if (!device) return 'No device registered';
    if (!device.enabled) return 'Device disabled';
    
    const lastUpdate = device.last_location_update;
    if (!lastUpdate) return 'No location data';
    
    const diffMs = new Date().getTime() - new Date(lastUpdate).getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    
    if (diffMins < 5) return 'Active';
    if (diffMins < 30) return 'Recently active';
    if (diffMins < 60) return 'Inactive';
    return 'Offline';
  };

  if (isLoading) {
    return (
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center space-x-3 mb-4">
          <DevicePhoneMobileIcon className="h-6 w-6 text-blue-600" />
          <h3 className="text-lg font-semibold text-gray-900">GPS Device</h3>
        </div>
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/2 mb-2"></div>
          <div className="h-4 bg-gray-200 rounded w-3/4"></div>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <DevicePhoneMobileIcon className="h-6 w-6 text-blue-600" />
            <h3 className="text-lg font-semibold text-gray-900">GPS Device</h3>
          </div>
          
          {device && (
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setShowRegistrationModal(true)}
                className="text-gray-400 hover:text-gray-600 transition-colors"
                title="Update device"
              >
                <PencilIcon className="h-4 w-4" />
              </button>
              <button
                onClick={removeDevice}
                disabled={isUpdating}
                className="text-gray-400 hover:text-red-600 transition-colors"
                title="Remove device"
              >
                <TrashIcon className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <p className="text-sm text-red-800">{error}</p>
          </div>
        )}

        {device ? (
          <div className="space-y-4">
            {/* Device Status */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                {React.createElement(getStatusIcon(device), {
                  className: `h-5 w-5 ${getStatusColor(device)}`
                })}
                <div>
                  <p className="text-sm font-medium text-gray-900">{getStatusText(device)}</p>
                  <p className="text-xs text-gray-500">
                    Last seen: {formatLastSeen(device.last_location_update)}
                  </p>
                </div>
              </div>
            </div>

            {/* Device Info */}
            <div className="bg-gray-50 rounded-md p-3">
              <div className="text-xs text-gray-500 mb-1">Device ID</div>
              <div className="text-sm font-mono text-gray-900">{device.device_id}</div>
            </div>

            {/* Controls */}
            <div className="flex space-x-3">
              <button
                onClick={toggleDeviceEnabled}
                disabled={isUpdating}
                className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  device.enabled
                    ? 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200'
                    : 'bg-green-100 text-green-800 hover:bg-green-200'
                } disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                {isUpdating ? 'Updating...' : device.enabled ? 'Disable' : 'Enable'}
              </button>
            </div>
          </div>
        ) : (
          <div className="text-center py-8">
            <DevicePhoneMobileIcon className="h-12 w-12 text-gray-300 mx-auto mb-4" />
            <p className="text-sm text-gray-600 mb-4">
              No GPS device registered. Register your device to enable automatic location tracking.
            </p>
            <button
              onClick={() => setShowRegistrationModal(true)}
              className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              <PlusIcon className="h-4 w-4" />
              <span>Register Device</span>
            </button>
          </div>
        )}
      </div>

      {/* Device Registration Modal */}
      <DeviceRegistrationModal
        isOpen={showRegistrationModal}
        onClose={() => setShowRegistrationModal(false)}
        onDeviceRegistered={handleDeviceRegistered}
      />
    </>
  );
} 