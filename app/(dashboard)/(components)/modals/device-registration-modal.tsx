'use client';

import React, { useState } from 'react';
import { XMarkIcon, CheckCircleIcon, DevicePhoneMobileIcon } from '@heroicons/react/24/outline';
import { updateDeviceMapping } from '../../(lib)/supabase/devices';

interface DeviceRegistrationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDeviceRegistered?: (deviceId: string) => void;
}

interface DeviceRegistrationData {
  device_id: string;
  enabled: boolean;
}

export function DeviceRegistrationModal({ isOpen, onClose, onDeviceRegistered }: DeviceRegistrationModalProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [deviceId, setDeviceId] = useState('');

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!deviceId.trim()) {
      setError('Device ID is required');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // Call server action
      const result = await updateDeviceMapping(deviceId.trim(), true);

      if (!result.success) {
        throw new Error(result.error);
      }

      // Success - show success message
      setSuccess('Device registered successfully!');
      
      // Notify parent component
      if (onDeviceRegistered) {
        onDeviceRegistered(deviceId.trim());
      }
      
      // Close modal immediately instead of waiting
      handleClose();

    } catch (error) {
      console.error('Failed to register device:', error);
      setError(error instanceof Error ? error.message : 'Failed to register device');
    } finally {
      setIsLoading(false);
    }
  };

  // Reset modal state when closing
  const handleClose = () => {
    setDeviceId('');
    setError(null);
    setSuccess(null);
    setIsLoading(false);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center p-4">
        {/* Backdrop */}
        <div 
          className="fixed inset-0 bg-black bg-opacity-25 backdrop-blur-sm"
          onClick={handleClose}
        />
        
        {/* Modal */}
        <div className="relative w-full max-w-md transform rounded-lg bg-white p-6 shadow-xl transition-all">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <DevicePhoneMobileIcon className="h-6 w-6 text-blue-600" />
              <h3 className="text-lg font-semibold text-gray-900">
                Register GPS Device
              </h3>
            </div>
            
            <button
              onClick={handleClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>

          {/* Success Message */}
          {success && (
            <div className="mb-6 flex items-center space-x-3 rounded-md bg-green-50 p-4">
              <CheckCircleIcon className="h-6 w-6 text-green-600" />
              <div>
                <p className="text-sm font-medium text-green-800">{success}</p>
                <p className="text-xs text-green-600 mt-1">You can now close this dialog.</p>
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="mb-6 rounded-md bg-red-50 p-4">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="device_id" className="block text-sm font-medium text-gray-700 mb-2">
                Device ID
              </label>
              <input
                type="text"
                id="device_id"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                placeholder="Enter device ID from Overland app"
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                disabled={isLoading || !!success}
              />
              <p className="text-xs text-gray-500 mt-1">
                Find this in your Overland GPS app settings
              </p>
            </div>

            {/* Instructions */}
            <div className="bg-blue-50 rounded-md p-4">
              <h4 className="text-sm font-medium text-blue-900 mb-2">How to find your Device ID:</h4>
              <ol className="text-xs text-blue-800 space-y-1 list-decimal list-inside">
                <li>Open the Overland GPS app on your phone</li>
                <li>Go to Settings</li>
                <li>Look for "Device ID" or "Device Identifier"</li>
                <li>Copy and paste it above</li>
              </ol>
            </div>

            {/* Buttons */}
            <div className="flex space-x-3">
              <button
                type="button"
                onClick={handleClose}
                className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 transition-colors"
                disabled={isLoading}
              >
                Cancel
              </button>
              
              <button
                type="submit"
                disabled={isLoading || !!success || !deviceId.trim()}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
              >
                {isLoading ? 'Registering...' : 'Register Device'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
} 