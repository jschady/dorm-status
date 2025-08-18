'use client';

import React, { useState } from 'react';
import { CreateGeofenceFormProps, CreateGeofenceRequest } from '../../(lib)/types';
import { MapPinIcon, HomeIcon, ExclamationTriangleIcon, ChevronDownIcon, ChevronUpIcon } from '@heroicons/react/24/outline';

export function CreateGeofenceForm({ onSubmit, isLoading = false, onCancel }: CreateGeofenceFormProps) {
  const [formData, setFormData] = useState<CreateGeofenceRequest>({
    name: '',
    center_latitude: 0,
    center_longitude: 0,
    radius_meters: 50,
    hysteresis_meters: 5
  });

  const [errors, setErrors] = useState<Partial<Record<keyof CreateGeofenceRequest, string>>>({});
  const [isGettingLocation, setIsGettingLocation] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Form validation
  const validateForm = (): boolean => {
    const newErrors: Partial<Record<keyof CreateGeofenceRequest, string>> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Geofence name is required';
    } else if (formData.name.length < 3) {
      newErrors.name = 'Name must be at least 3 characters';
    } else if (formData.name.length > 50) {
      newErrors.name = 'Name must be less than 50 characters';
    }

    if (formData.center_latitude === 0 && formData.center_longitude === 0) {
      newErrors.center_latitude = 'Please set a location for your geofence';
    } else {
      if (Math.abs(formData.center_latitude) > 90) {
        newErrors.center_latitude = 'Latitude must be between -90 and 90';
      }
      if (Math.abs(formData.center_longitude) > 180) {
        newErrors.center_longitude = 'Longitude must be between -180 and 180';
      }
    }

    if (formData.radius_meters < 10) {
      newErrors.radius_meters = 'Radius must be at least 10 meters';
    } else if (formData.radius_meters > 100) {
      newErrors.radius_meters = 'Radius cannot exceed 100 meters';
    }

    if (formData.hysteresis_meters < 5) {
      newErrors.hysteresis_meters = 'Hysteresis must be at least 5 meters';
    } else if (formData.hysteresis_meters >= formData.radius_meters) {
      newErrors.hysteresis_meters = 'Hysteresis must be less than radius';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Get user's current location
  const getCurrentLocation = () => {
    setIsGettingLocation(true);
    
    if (!navigator.geolocation) {
      setErrors({ center_latitude: 'Geolocation is not supported by this browser' });
      setIsGettingLocation(false);
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        setFormData({
          ...formData,
          center_latitude: Math.round(position.coords.latitude * 10000000) / 10000000,
          center_longitude: Math.round(position.coords.longitude * 10000000) / 10000000
        });
        setErrors({ ...errors, center_latitude: '', center_longitude: '' });
        setIsGettingLocation(false);
      },
      (error) => {
        let message = 'Unable to get your location';
        if (error.code === error.PERMISSION_DENIED) {
          message = 'Location access denied. Please enable location permission.';
        } else if (error.code === error.POSITION_UNAVAILABLE) {
          message = 'Location information is unavailable.';
        }
        setErrors({ ...errors, center_latitude: message });
        setIsGettingLocation(false);
      },
      {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 60000
      }
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    try {
      await onSubmit(formData);
    } catch (error) {
      console.error('Form submission error:', error);
    }
  };

  const handleInputChange = (field: keyof CreateGeofenceRequest, value: string | number) => {
    setFormData({ ...formData, [field]: value });
    // Clear error for this field when user starts typing
    if (errors[field]) {
      setErrors({ ...errors, [field]: '' });
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Geofence Name */}
      <div>
        <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
          <HomeIcon className="w-4 h-4 inline mr-1" />
          Dorm Room Name
        </label>
        <input
          type="text"
          id="name"
          value={formData.name}
          onChange={(e) => handleInputChange('name', e.target.value)}
          placeholder="e.g., Crosby Hall 204"
          className={`mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm ${
            errors.name ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
          }`}
          disabled={isLoading}
        />
        {errors.name && (
          <p className="mt-1 text-sm text-red-600 flex items-center">
            <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
            {errors.name}
          </p>
        )}
      </div>

      {/* Location Section */}
      <div className="border-t pt-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">
          <MapPinIcon className="w-5 h-5 inline mr-2" />
          Geofence Location
        </h3>
        
        {/* Get Current Location Button */}
        <div className="mb-4">
          <button
            type="button"
            onClick={getCurrentLocation}
            disabled={isGettingLocation || isLoading}
            className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <MapPinIcon className="w-4 h-4 mr-2" />
            {isGettingLocation ? 'Getting Location...' : 'Use Current Location'}
          </button>
        </div>

        {/* Manual Coordinates */}
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <div>
            <label htmlFor="latitude" className="block text-sm font-medium text-gray-700">
              Latitude
            </label>
            <input
              type="number"
              id="latitude"
              step="any"
              value={formData.center_latitude || ''}
              onChange={(e) => handleInputChange('center_latitude', parseFloat(e.target.value) || 0)}
              placeholder="40.3430"
              className={`mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm ${
                errors.center_latitude ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
              }`}
              disabled={isLoading}
            />
          </div>
          
          <div>
            <label htmlFor="longitude" className="block text-sm font-medium text-gray-700">
              Longitude
            </label>
            <input
              type="number"
              id="longitude"
              step="any"
              value={formData.center_longitude || ''}
              onChange={(e) => handleInputChange('center_longitude', parseFloat(e.target.value) || 0)}
              placeholder="-74.6514"
              className={`mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm ${
                errors.center_longitude ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
              }`}
              disabled={isLoading}
            />
          </div>
        </div>
        
        {(errors.center_latitude || errors.center_longitude) && (
          <p className="mt-2 text-sm text-red-600 flex items-center">
            <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
            {errors.center_latitude || errors.center_longitude}
          </p>
        )}
      </div>

      {/* Detection Settings */}
      <div className="border-t pt-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Detection Settings</h3>
        
        {/* Radius Control */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <label htmlFor="radius" className="block text-sm font-medium text-gray-700">
              Detection Radius
            </label>
            <div className="flex items-center space-x-2">
              <input
                type="number"
                id="radius-number"
                value={formData.radius_meters}
                onChange={(e) => handleInputChange('radius_meters', parseInt(e.target.value) || 10)}
                min="10"
                max="100"
                step="1"
                className={`w-20 rounded-md border-gray-300 shadow-sm text-sm focus:border-indigo-500 focus:ring-indigo-500 ${
                  errors.radius_meters ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
                }`}
                disabled={isLoading}
              />
              <span className="text-sm text-gray-500">meters</span>
            </div>
          </div>
          
          <div className="relative">
            <input
              type="range"
              id="radius"
              min="10"
              max="100"
              step="1"
              value={formData.radius_meters}
              onChange={(e) => handleInputChange('radius_meters', parseInt(e.target.value))}
              className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer slider-thumb:appearance-none slider-thumb:h-4 slider-thumb:w-4 slider-thumb:rounded-full slider-thumb:bg-indigo-500 slider-thumb:cursor-pointer slider-thumb:shadow-lg slider-thumb:border-2 slider-thumb:border-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
              style={{
                background: `linear-gradient(to right, #6366f1 0%, #6366f1 ${((formData.radius_meters - 10) / (100 - 10)) * 100}%, #e5e7eb ${((formData.radius_meters - 10) / (100 - 10)) * 100}%, #e5e7eb 100%)`
              }}
              disabled={isLoading}
            />
            <div className="flex justify-between text-xs text-gray-400 mt-1">
              <span>10m</span>
              <span className="text-gray-600 font-medium">
                {formData.radius_meters}m
                {formData.radius_meters <= 20 && " (Small dorm)"}
                {formData.radius_meters > 20 && formData.radius_meters <= 40 && " (Regular room)"}
                {formData.radius_meters > 40 && formData.radius_meters <= 70 && " (Large room)"}
                {formData.radius_meters > 70 && " (Suite/floor)"}
              </span>
              <span>100m</span>
            </div>
          </div>
          
          {errors.radius_meters && (
            <p className="mt-2 text-sm text-red-600 flex items-center">
              <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
              {errors.radius_meters}
            </p>
          )}
          <p className="mt-2 text-xs text-gray-500">
            How far from the center point to detect as "in room"
          </p>
        </div>

        {/* Advanced Options Toggle */}
        <div className="mt-6">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center text-sm font-medium text-gray-700 hover:text-gray-900 focus:outline-none"
          >
            {showAdvanced ? (
              <ChevronUpIcon className="w-4 h-4 mr-1" />
            ) : (
              <ChevronDownIcon className="w-4 h-4 mr-1" />
            )}
            Advanced Options
          </button>
          
          {showAdvanced && (
            <div className="mt-4 p-4 bg-gray-50 rounded-lg space-y-4">
              {/* Hysteresis Control */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label htmlFor="hysteresis" className="block text-sm font-medium text-gray-700">
                    Exit Buffer (Hysteresis)
                  </label>
                  <div className="flex items-center space-x-2">
                    <input
                      type="number"
                      id="hysteresis"
                      value={formData.hysteresis_meters}
                      onChange={(e) => handleInputChange('hysteresis_meters', parseInt(e.target.value) || 5)}
                      min="5"
                      max={Math.max(5, formData.radius_meters - 5)}
                      step="1"
                      className={`w-20 rounded-md border-gray-300 shadow-sm text-sm focus:border-indigo-500 focus:ring-indigo-500 ${
                        errors.hysteresis_meters ? 'border-red-300 focus:border-red-500 focus:ring-red-500' : ''
                      }`}
                      disabled={isLoading}
                    />
                    <span className="text-sm text-gray-500">meters</span>
                  </div>
                </div>
                
                {errors.hysteresis_meters && (
                  <p className="mt-1 text-sm text-red-600 flex items-center">
                    <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
                    {errors.hysteresis_meters}
                  </p>
                )}
                <p className="text-xs text-gray-500">
                  Prevents rapid status changes - must move this distance beyond detection radius to exit
                </p>
              </div>
              
              {/* Visual Guide */}
              <div className="bg-white rounded border p-3">
                <h4 className="text-sm font-medium text-gray-900 mb-2">How it Works</h4>
                <div className="space-y-1 text-xs text-gray-600">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-indigo-500 mr-2"></div>
                    <span>Detection zone: {formData.radius_meters}m radius</span>
                  </div>
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-emerald-500 mr-2"></div>
                    <span>Exit buffer: +{formData.hysteresis_meters}m beyond detection zone</span>
                  </div>
                  <div className="mt-2 text-xs text-gray-500">
                    Total exit distance: {formData.radius_meters + formData.hysteresis_meters}m from center
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Form Actions */}
      <div className="flex justify-end space-x-3 pt-6 border-t">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            disabled={isLoading}
            className="px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
        )}
        <button
          type="submit"
          disabled={isLoading}
          className="px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="m4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              Creating...
            </>
          ) : (
            'Create Geofence'
          )}
        </button>
      </div>
    </form>
  );
} 